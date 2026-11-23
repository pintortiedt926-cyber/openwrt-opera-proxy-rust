use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsConnector;

use crate::dialer::{BoxStream, ContextDialer};
use crate::resolver::{build_tls_client_config, format_host_port};
use crate::runtime::CondLogger;

/// Bounded per-direction relay buffer (16 KiB) to keep router RSS low under concurrent traffic.
pub const RELAY_BUF_SIZE: usize = 16 * 1024;
/// Maximum concurrent client connections per proxy instance to bound memory and file descriptors.
pub const MAX_CONCURRENT_CONNS: usize = 256;

const BAD_REQ_MSG: &str = "Bad Request\n";

const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

type ProxyResponseBody = BoxBody<Bytes, io::Error>;

fn full_body(s: &'static str) -> ProxyResponseBody {
    Full::new(Bytes::from_static(s.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn empty_body() -> ProxyResponseBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn del_hop_headers(headers: &mut HeaderMap) {
    // Also strip any header names listed inside `Connection: ...` per RFC 7230 §6.1.
    let extra: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|tok| HeaderName::from_bytes(tok.trim().as_bytes()).ok())
        .collect();
    for name in extra {
        headers.remove(name);
    }
    for &h in HOP_HEADERS {
        headers.remove(h);
    }
}

/// Serve HTTP/1.1 + HTTP/2 forward proxy and CONNECT tunnels on an already-bound `TcpListener`.
pub async fn serve_http_listener(
    listener: TcpListener,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    logger: CondLogger,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    loop {
        let accept_res = tokio::select! {
            res = listener.accept() => res,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };

        let (stream, peer_addr) = match accept_res {
            Ok(pair) => pair,
            Err(e) => {
                logger.error(format_args!("HTTP accept error: {}", e));
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                logger.warning(format_args!(
                    "Rejecting HTTP client {}: concurrency limit ({}) reached",
                    peer_addr, MAX_CONCURRENT_CONNS
                ));
                drop(stream);
                continue;
            }
        };

        let dialer = dialer.clone();
        let roots = roots.clone();
        let logger = logger.clone();
        let shutdown_rx = shutdown.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(stream);
            let mut builder = AutoServerBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .preserve_header_case(true)
                .title_case_headers(true);
            let svc = service_fn(move |req: Request<Incoming>| {
                handle_http_request(
                    req,
                    peer_addr,
                    dialer.clone(),
                    roots.clone(),
                    logger.clone(),
                    shutdown_rx.clone(),
                )
            });
            let _ = builder.serve_connection_with_upgrades(io, svc).await;
        });
    }

    Ok(())
}

pub async fn serve_http_proxy(
    bind_address: &str,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    logger: CondLogger,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind_address).await?;
    serve_http_listener(listener, dialer, roots, logger, shutdown).await
}

async fn handle_http_request(
    mut req: Request<Incoming>,
    peer_addr: SocketAddr,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    logger: CondLogger,
    shutdown: watch::Receiver<bool>,
) -> Result<Response<ProxyResponseBody>, Infallible> {
    logger.info(format_args!(
        "Request: {} {:?} {} {}",
        peer_addr,
        req.version(),
        req.method(),
        req.uri()
    ));

    let is_connect = req.method() == Method::CONNECT;
    let is_h2 = req.version() == Version::HTTP_2;

    let has_host = req.uri().authority().is_some()
        || req
            .headers()
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| !s.is_empty());
    let has_scheme = req.uri().scheme().is_some();

    if (!is_h2 && (!has_host || (!has_scheme && !is_connect))) || (is_h2 && !has_host) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(full_body(BAD_REQ_MSG))
            .unwrap());
    }

    del_hop_headers(req.headers_mut());

    if is_connect {
        Ok(handle_connect(req, dialer, logger, shutdown).await)
    } else {
        Ok(handle_forward_http(req, peer_addr, dialer, roots, logger).await)
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    dialer: Arc<dyn ContextDialer>,
    logger: CondLogger,
    shutdown: watch::Receiver<bool>,
) -> Response<ProxyResponseBody> {
    let target = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let target = if target.contains(':') {
        target
    } else {
        format!("{}:443", target)
    };

    let upstream = match dialer.dial(target.clone()).await {
        Ok(conn) => conn,
        Err(e) => {
            logger.error(format_args!("Can't satisfy CONNECT request: {}", e));
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body("Can't satisfy CONNECT request\n"))
                .unwrap();
        }
    };

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                relay_bidirectional(&mut client_io, upstream, shutdown).await;
            }
            Err(e) => {
                logger.error(format_args!("Can't hijack client connection: {}", e));
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap()
}

async fn handle_forward_http(
    mut req: Request<Incoming>,
    peer_addr: SocketAddr,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    logger: CondLogger,
) -> Response<ProxyResponseBody> {
    let scheme = req
        .uri()
        .scheme_str()
        .unwrap_or("http")
        .to_ascii_lowercase();
    let use_tls = scheme == "https";
    let default_port = if use_tls { 443 } else { 80 };

    let authority_str = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let (host, port) = match crate::dialer::split_host_port(&authority_str) {
        Some((h, p)) => (h, p),
        None => (
            authority_str
                .trim_matches(|c| c == '[' || c == ']')
                .to_string(),
            default_port,
        ),
    };
    let dial_addr = format_host_port(&host, port);
    let log_method = req.method().clone();
    let log_url = req.uri().to_string();

    let conn = match dialer.dial(dial_addr).await {
        Ok(c) => c,
        Err(e) => {
            logger.error(format_args!("HTTP fetch error: {}", e));
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body("Server Error\n"))
                .unwrap();
        }
    };

    // Rewrite absolute-form proxy URI to origin-form (`path?query`).
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    if let Ok(origin_uri) = path_and_query.parse::<Uri>() {
        *req.uri_mut() = origin_uri;
    }
    if !req.headers().contains_key(http::header::HOST) {
        let host_val = if (use_tls && port == 443) || (!use_tls && port == 80) {
            host.clone()
        } else {
            format_host_port(&host, port)
        };
        if let Ok(hv) = http::HeaderValue::from_str(&host_val) {
            req.headers_mut().insert(http::header::HOST, hv);
        }
    }
    *req.version_mut() = Version::HTTP_11;

    let upstream_resp = if use_tls {
        let tls_cfg = match build_tls_client_config(roots, None, true, vec![b"http/1.1".to_vec()]) {
            Ok(c) => c,
            Err(e) => {
                logger.error(format_args!("HTTP fetch TLS config error: {}", e));
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body("Server Error\n"))
                    .unwrap();
            }
        };
        let sni = match ServerName::try_from(host) {
            Ok(s) => s,
            Err(e) => {
                logger.error(format_args!("HTTP fetch invalid SNI: {}", e));
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full_body(BAD_REQ_MSG))
                    .unwrap();
            }
        };
        let tls = match TlsConnector::from(tls_cfg).connect(sni, conn).await {
            Ok(s) => s,
            Err(e) => {
                logger.error(format_args!("HTTP fetch TLS handshake error: {}", e));
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full_body("Server Error\n"))
                    .unwrap();
            }
        };
        forward_http1_stream(TokioIo::new(tls), req).await
    } else {
        forward_http1_stream(TokioIo::new(conn), req).await
    };

    match upstream_resp {
        Ok(mut resp) => {
            logger.info(format_args!(
                "{} {} {} {}",
                peer_addr,
                log_method,
                log_url,
                resp.status()
            ));
            del_hop_headers(resp.headers_mut());
            resp.map(|body| body.map_err(|e| io::Error::other(e.to_string())).boxed())
        }
        Err(e) => {
            logger.error(format_args!("HTTP fetch error: {}", e));
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(full_body("Server Error\n"))
                .unwrap()
        }
    }
}

async fn forward_http1_stream<IO>(
    io: IO,
    req: Request<Incoming>,
) -> Result<Response<Incoming>, String>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("upstream HTTP handshake failed: {}", e))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| format!("upstream HTTP request failed: {}", e))
}

async fn relay_bidirectional<A>(
    client: &mut A,
    mut upstream: BoxStream,
    mut shutdown: watch::Receiver<bool>,
) where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        _ = tokio::io::copy_bidirectional_with_sizes(client, &mut upstream, RELAY_BUF_SIZE, RELAY_BUF_SIZE) => {}
        _ = async {
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        } => {
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
        }
    }
}

// ============================================================================
// SOCKS5 server (`-socks-mode`)
// ============================================================================

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_CMD_CONNECT: u8 = 0x01;

const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_NETWORK_UNREACHABLE: u8 = 0x03;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CONN_REFUSED: u8 = 0x05;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Serve SOCKS5 CONNECT proxy on an already-bound `TcpListener` (no local DNS resolution).
pub async fn serve_socks5_listener(
    listener: TcpListener,
    dialer: Arc<dyn ContextDialer>,
    logger: CondLogger,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    loop {
        let accept_res = tokio::select! {
            res = listener.accept() => res,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };

        let (stream, peer_addr) = match accept_res {
            Ok(pair) => pair,
            Err(e) => {
                logger.error(format_args!("SOCKS5 accept error: {}", e));
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                logger.warning(format_args!(
                    "Rejecting SOCKS5 client {}: concurrency limit ({}) reached",
                    peer_addr, MAX_CONCURRENT_CONNS
                ));
                drop(stream);
                continue;
            }
        };

        let dialer = dialer.clone();
        let logger = logger.clone();
        let shutdown_rx = shutdown.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_socks5_client(stream, dialer, shutdown_rx).await {
                logger.warning(format_args!("SOCKS5 client {} error: {}", peer_addr, e));
            }
        });
    }

    Ok(())
}

pub async fn serve_socks5_proxy(
    bind_address: &str,
    dialer: Arc<dyn ContextDialer>,
    logger: CondLogger,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = TcpListener::bind(bind_address).await?;
    serve_socks5_listener(listener, dialer, logger, shutdown).await
}

async fn handle_socks5_client(
    mut client: TcpStream,
    dialer: Arc<dyn ContextDialer>,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    // 1. Greeting: [VER, NMETHODS, METHODS...]
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version {}", hdr[0]),
        ));
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client.read_exact(&mut methods).await?;

    if !methods.contains(&SOCKS5_NO_AUTH) {
        let _ = client.write_all(&[SOCKS5_VER, SOCKS5_NO_ACCEPTABLE]).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client does not support NO_AUTH method",
        ));
    }
    client.write_all(&[SOCKS5_VER, SOCKS5_NO_AUTH]).await?;

    // 2. Request: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request version",
        ));
    }
    let dest_host = match req_hdr[3] {
        0x01 => {
            let mut b = [0u8; 4];
            client.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 SOCKS5 domain name")
            })?
        }
        0x04 => {
            let mut b = [0u8; 16];
            client.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        atyp => {
            send_socks5_reply(&mut client, SOCKS5_REP_ATYP_NOT_SUPPORTED).await?;
            let _ = client.shutdown().await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 ATYP 0x{:02x}", atyp),
            ));
        }
    };

    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);
    let dest_addr = format_host_port(&dest_host, dest_port);

    if req_hdr[1] != SOCKS5_CMD_CONNECT {
        send_socks5_reply(&mut client, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
        let _ = client.shutdown().await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS5 command 0x{:02x}", req_hdr[1]),
        ));
    }

    // 3. Connect upstream without resolving domain names locally.
    let upstream = match dialer.dial(dest_addr.clone()).await {
        Ok(u) => u,
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            let rep = if msg.contains("refused") {
                SOCKS5_REP_CONN_REFUSED
            } else if msg.contains("network is unreachable") {
                SOCKS5_REP_NETWORK_UNREACHABLE
            } else {
                SOCKS5_REP_HOST_UNREACHABLE
            };
            let _ = send_socks5_reply(&mut client, rep).await;
            return Err(io::Error::other(format!(
                "connect to {} failed: {}",
                dest_addr, e
            )));
        }
    };

    send_socks5_reply(&mut client, SOCKS5_REP_SUCCESS).await?;
    relay_bidirectional(&mut client, upstream, shutdown).await;
    Ok(())
}

async fn send_socks5_reply(stream: &mut TcpStream, rep: u8) -> io::Result<()> {
    let reply = [SOCKS5_VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::{BypassDialer, DialFuture, DirectDialer};
    use crate::resolver::build_root_store;
    use crate::runtime::SILENT;
    use std::sync::Mutex;

    struct RecordingDialer {
        name: &'static str,
        recorded: Mutex<Vec<String>>,
    }

    impl RecordingDialer {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                recorded: Mutex::new(Vec::new()),
            }
        }
    }

    impl ContextDialer for RecordingDialer {
        fn dial(&self, address: String) -> DialFuture {
            self.recorded.lock().unwrap().push(address);
            let name = self.name;
            Box::pin(async move { Err(io::Error::other(name)) })
        }
    }

    #[tokio::test]
    async fn test_http_proxy_bypass_http_and_connect() {
        let direct = Arc::new(RecordingDialer::new("direct"));
        let proxied = Arc::new(RecordingDialer::new("proxied"));
        let bypass = Arc::new(
            BypassDialer::new(
                &["*.example.com".to_string()],
                direct.clone(),
                proxied.clone(),
            )
            .unwrap(),
        );
        let roots = build_root_store("").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let srv = tokio::spawn(serve_http_listener(
            listener,
            bypass,
            roots,
            CondLogger::new("TEST: ", SILENT),
            rx,
        ));

        // 1) Plain HTTP GET to bypassed host -> 500 from mock error, recorded on direct dialer.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET http://check.example.com/path HTTP/1.1\r\nHost: check.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 500 "), "got: {}", resp);

        // 2) CONNECT to bypassed host -> 502 from mock error, recorded on direct dialer.
        let mut s2 = TcpStream::connect(addr).await.unwrap();
        s2.write_all(b"CONNECT secure.example.com:443 HTTP/1.1\r\nHost: secure.example.com:443\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp2 = String::new();
        s2.read_to_string(&mut resp2).await.unwrap();
        assert!(resp2.starts_with("HTTP/1.1 502 "), "got: {}", resp2);

        assert_eq!(
            *direct.recorded.lock().unwrap(),
            vec!["check.example.com:80", "secure.example.com:443"]
        );
        assert!(proxied.recorded.lock().unwrap().is_empty());

        let _ = tx.send(true);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn test_socks5_server_connect_and_relay() {
        // Echo target server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let srv = tokio::spawn(serve_socks5_listener(
            socks_listener,
            Arc::new(DirectDialer::default()),
            CondLogger::new("SOCKS: ", SILENT),
            rx,
        ));

        let mut c = TcpStream::connect(socks_addr).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        c.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        let port = echo_addr.port().to_be_bytes();
        c.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00);

        c.write_all(b"hello socks5").await.unwrap();
        let mut echoed = [0u8; 12];
        c.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello socks5");

        let _ = tx.send(true);
        let _ = srv.await;
    }
}
