#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use md5::{Digest as _, Md5};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use opera_proxy::app::run_with_args;
use opera_proxy::cli::ServerSelection;
use opera_proxy::dialer::{
    basic_auth_header, probe_dialer, select_server, AuthCallback, ContextDialer, DirectDialer,
    HttpProxyDialer, Socks5ClientDialer,
};
use opera_proxy::handler::{serve_http_listener, serve_socks5_listener};
use opera_proxy::resolver::{build_root_store, tls_crypto_provider, FastResolver};
use opera_proxy::runtime::{CondLogger, SILENT};
use opera_proxy::seclient::{
    is_discover_801, load_proxy_entries_from_csv, SeClient, SeEndpoints, SeSettings,
};

struct SyntheticPki {
    roots: Arc<RootCertStore>,
    server_config: Arc<ServerConfig>,
}

fn generate_synthetic_pki(dns_names: &[&str]) -> SyntheticPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Synthetic Opera Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let srv_key = KeyPair::generate().unwrap();
    let mut srv_params = CertificateParams::default();
    srv_params
        .distinguished_name
        .push(DnType::CommonName, dns_names[0]);
    for name in dns_names {
        srv_params
            .subject_alt_names
            .push(SanType::DnsName((*name).try_into().unwrap()));
    }
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .unwrap();

    let cert_chain = vec![
        CertificateDer::from(srv_cert.der().to_vec()),
        CertificateDer::from(ca_cert.der().to_vec()),
    ];
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv_key.serialize_der()));

    let server_config = ServerConfig::builder_with_provider(tls_crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)
        .unwrap();

    SyntheticPki {
        roots: Arc::new(roots),
        server_config: Arc::new(server_config),
    }
}

/// Start a mock TLS upstream proxy (like an Opera sec-tunnel node) that records SNI, checks
/// Proxy-Authorization, accepts CONNECT host:port, and tunnels to `forced_target` (if Some)
/// or the requested host:port.
async fn spawn_mock_tls_proxy(
    server_config: Arc<ServerConfig>,
    expected_auth: String,
    forced_target: Option<SocketAddr>,
    delay: Duration,
) -> (
    SocketAddr,
    Arc<Mutex<Vec<Option<String>>>>,
    Arc<Mutex<Vec<String>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);
    let recorded_sni = Arc::new(Mutex::new(Vec::new()));
    let recorded_targets = Arc::new(Mutex::new(Vec::new()));
    let sni_clone = recorded_sni.clone();
    let targets_clone = recorded_targets.clone();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let expected_auth = expected_auth.clone();
            let sni_log = sni_clone.clone();
            let target_log = targets_clone.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let sni = tls.get_ref().1.server_name().map(|s| s.to_string());
                sni_log.lock().unwrap().push(sni);

                // Read HTTP CONNECT headers
                let mut buf = Vec::new();
                let mut tmp = [0u8; 512];
                let header_end = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos;
                    }
                    let Ok(n) = tls.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                };

                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let first_line = head.lines().next().unwrap_or("");
                let target = first_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                let auth_ok = head.lines().any(|l| {
                    l.to_ascii_lowercase().starts_with("proxy-authorization:")
                        && l.split_once(':')
                            .map(|(_, v)| v.trim() == expected_auth)
                            .unwrap_or(false)
                });

                if !auth_ok {
                    let _ = tls
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .await;
                    return;
                }

                target_log.lock().unwrap().push(target.clone());
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }

                let dial_dest = match forced_target {
                    Some(sa) => sa.to_string(),
                    None => target,
                };
                let Ok(mut backend) = TcpStream::connect(&dial_dest).await else {
                    let _ = tls.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };

                let _ = tls
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await;
                let remainder = &buf[header_end + 4..];
                if !remainder.is_empty() {
                    let _ = backend.write_all(remainder).await;
                }
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut backend).await;
            });
        }
    });

    (addr, recorded_sni, recorded_targets)
}

#[tokio::test]
async fn test_tls_fake_sni_and_strict_certificate_verification() {
    let pki = generate_synthetic_pki(&["eu0.sec-tunnel.com"]);
    let expected_auth = basic_auth_header("devhash", "devpass");

    // Local echo server
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                if let Ok(n) = s.read(&mut b).await {
                    let _ = s.write_all(&b[..n]).await;
                }
            });
        }
    });

    let (proxy_addr, snis, _targets) = spawn_mock_tls_proxy(
        pki.server_config.clone(),
        expected_auth.clone(),
        Some(echo_addr),
        Duration::ZERO,
    )
    .await;

    let auth_cb: AuthCallback = Arc::new(move || Ok(expected_auth.clone()));
    let direct: Arc<dyn ContextDialer> = Arc::new(DirectDialer::default());

    // 1. Valid cert + fake SNI "www.google.com" -> succeeds, server sees SNI "www.google.com"
    let d_fake = HttpProxyDialer::new(
        proxy_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        "www.google.com".to_string(),
        Some(auth_cb.clone()),
        pki.roots.clone(),
        direct.clone(),
    );
    let mut s = d_fake.dial("target.example:443".to_string()).await.unwrap();
    s.write_all(b"ping-fake-sni").await.unwrap();
    let mut out = [0u8; 13];
    s.read_exact(&mut out).await.unwrap();
    assert_eq!(&out, b"ping-fake-sni");

    // 2. Valid cert + empty fake SNI (SNI omitted) -> succeeds, server sees None SNI
    let d_nosni = HttpProxyDialer::new(
        proxy_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        String::new(),
        Some(auth_cb.clone()),
        pki.roots.clone(),
        direct.clone(),
    );
    let mut s2 = d_nosni
        .dial("target.example:443".to_string())
        .await
        .unwrap();
    s2.write_all(b"ping-no-sni").await.unwrap();
    let mut out2 = [0u8; 11];
    s2.read_exact(&mut out2).await.unwrap();
    assert_eq!(&out2, b"ping-no-sni");

    let recorded = snis.lock().unwrap().clone();
    assert_eq!(recorded, vec![Some("www.google.com".to_string()), None]);

    // 3. Hostname mismatch ("us0.sec-tunnel.com" vs cert for "eu0.sec-tunnel.com") -> MUST FAIL!
    let d_wrong_host = HttpProxyDialer::new(
        proxy_addr.to_string(),
        "us0.sec-tunnel.com".to_string(),
        "www.google.com".to_string(),
        Some(auth_cb.clone()),
        pki.roots.clone(),
        direct.clone(),
    );
    assert!(
        d_wrong_host
            .dial("target.example:443".to_string())
            .await
            .is_err(),
        "wrong hostname MUST fail TLS verification even when fake-SNI is set"
    );

    // 4. Untrusted CA (Mozilla bundle instead of synthetic CA) -> MUST FAIL!
    let default_roots = build_root_store("").unwrap();
    let d_untrusted = HttpProxyDialer::new(
        proxy_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        "www.google.com".to_string(),
        Some(auth_cb),
        default_roots,
        direct,
    );
    assert!(
        d_untrusted
            .dial("target.example:443".to_string())
            .await
            .is_err(),
        "untrusted CA MUST fail TLS verification"
    );
}

#[tokio::test]
async fn test_mock_surfeasy_api_digest_auth_cookies_and_801() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let return_801 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let return_801_srv = return_801.clone();
    let password_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let pw_srv = password_counter.clone();

    tokio::spawn(async move {
        let realm = "SurfEasyTest";
        let nonce = "testnonce123";
        while let Ok((tcp, _)) = listener.accept().await {
            let r801 = return_801_srv.clone();
            let pwc = pw_srv.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let r801 = r801.clone();
                    let pwc = pwc.clone();
                    async move {
                        let path = req.uri().path().to_string();
                        let has_auth = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        let cookie = req
                            .headers()
                            .get(header::COOKIE)
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());

                        // Verify MD5 Digest auth
                        let authorized = has_auth.as_deref().is_some_and(|hdr| {
                            hdr.starts_with("Digest ")
                                && hdr.contains("username=\"testuser\"")
                                && hdr.contains(&format!("nonce=\"{}\"", nonce))
                                && {
                                    // Verify actual MD5 response matches RFC 2617
                                    let ha1 = format!(
                                        "{:x}",
                                        Md5::digest(format!("testuser:{}:testsecret", realm))
                                    );
                                    let ha2 =
                                        format!("{:x}", Md5::digest(format!("POST:{}", path)));
                                    let expected = format!(
                                        "{:x}",
                                        Md5::digest(format!("{}:{}:{}", ha1, nonce, ha2))
                                    );
                                    hdr.contains(&format!("response=\"{}\"", expected))
                                }
                        });

                        if !authorized {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .header(
                                        header::WWW_AUTHENTICATE,
                                        format!(
                                            "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5",
                                            realm, nonce
                                        ),
                                    )
                                    .body(Full::new(Bytes::from_static(b"auth required")))
                                    .unwrap(),
                            );
                        }

                        let _body = req.into_body().collect().await.unwrap().to_bytes();
                        match path.as_str() {
                            "/v4/register_subscriber" => Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(header::SET_COOKIE, "se_session=sess1; Path=/")
                                .body(Full::new(Bytes::from_static(
                                    br#"{"data":{},"return_code":{"0":"OK"}}"#,
                                )))
                                .unwrap()),
                            "/v4/register_device" => {
                                assert!(
                                    cookie.as_deref().is_some_and(|c| c.contains("se_session=sess1")),
                                    "missing session cookie on register_device: {:?}",
                                    cookie
                                );
                                Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(
                                        br#"{"data":{"client_type":"se0316","device_id":"DEV-123","device_password":"PASS-1"},"return_code":{"0":"OK"}}"#,
                                    )))
                                    .unwrap())
                            }
                            "/v4/geo_list" => Ok(Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(
                                    br#"{"data":{"geos":[{"country":"Europe","country_code":"EU"},{"country":"Asia","country_code":"AS"}]},"return_code":{"0":"OK"}}"#,
                                )))
                                .unwrap()),
                            "/v4/discover" => {
                                if r801.load(std::sync::atomic::Ordering::SeqCst) {
                                    Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from_static(
                                            br#"{"data":{"ips":[]},"return_code":{"801":"Rate limited"}}"#,
                                        )))
                                        .unwrap())
                                } else {
                                    Ok(Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from_static(
                                            br#"{"data":{"ips":[{"geo":{"country":"Europe","country_code":"EU"},"ip":"77.111.244.26","ports":[443]}]},"return_code":{"0":"OK"}}"#,
                                        )))
                                        .unwrap())
                                }
                            }
                            "/v4/subscriber_login" => Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(header::SET_COOKIE, "se_session=sess2; Path=/")
                                .body(Full::new(Bytes::from_static(
                                    br#"{"data":{},"return_code":{"0":"OK"}}"#,
                                )))
                                .unwrap()),
                            "/v4/device_generate_password" => {
                                let n = pwc.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 2;
                                let json = format!(
                                    r#"{{"data":{{"device_password":"PASS-{}"}},"return_code":{{"0":"OK"}}}}"#,
                                    n
                                );
                                Ok(Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from(json)))
                                    .unwrap())
                            }
                            _ => Ok(Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new()))
                                .unwrap()),
                        }
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let settings = SeSettings {
        endpoints: SeEndpoints::with_base(&format!("http://{}", addr)),
        ..SeSettings::default()
    };
    let client = SeClient::new(
        "testuser".to_string(),
        "testsecret".to_string(),
        settings,
        Arc::new(DirectDialer::default()),
        build_root_store("").unwrap(),
        String::new(),
    )
    .unwrap();

    let t = Duration::from_secs(5);
    client.anon_register(t).await.unwrap();
    client.register_device(t).await.unwrap();
    let (login1, pass1) = client.get_proxy_credentials();
    assert_eq!(login1.len(), 40);
    assert_eq!(pass1, "PASS-1");

    let geos = client.geo_list(t).await.unwrap();
    assert_eq!(geos.len(), 2);
    assert_eq!(geos[0].country_code, "EU");

    let ips = client.discover("\"EU\",,", t).await.unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0].ip, "77.111.244.26");

    // Simulate 801 error
    return_801.store(true, std::sync::atomic::Ordering::SeqCst);
    let err = client.discover("\"EU\",,", t).await.unwrap_err();
    assert!(is_discover_801(&err), "expected code=801, got: {}", err);

    // Refresh login & password
    client.login(t).await.unwrap();
    client.device_generate_password(t).await.unwrap();
    let (_, pass2) = client.get_proxy_credentials();
    assert_eq!(pass2, "PASS-2");
}

#[tokio::test]
async fn test_end_to_end_http_and_socks5_via_tls_upstream_proxy() {
    let pki = generate_synthetic_pki(&["eu0.sec-tunnel.com"]);
    let expected_auth = basic_auth_header("user", "pass");

    // Local HTTP target backend
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = target_listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let has_proxy_conn = req.headers().contains_key("proxy-connection");
                    let body = format!("path={} proxy_conn={}", req.uri().path(), has_proxy_conn);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("x-target", "ok")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let (upstream_addr, _snis, recorded_targets) = spawn_mock_tls_proxy(
        pki.server_config.clone(),
        expected_auth.clone(),
        Some(target_addr),
        Duration::ZERO,
    )
    .await;

    let auth_cb: AuthCallback = Arc::new(move || Ok(expected_auth.clone()));
    let upstream_dialer: Arc<dyn ContextDialer> = Arc::new(HttpProxyDialer::new(
        upstream_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        String::new(),
        Some(auth_cb),
        pki.roots.clone(),
        Arc::new(DirectDialer::default()),
    ));

    // Start local HTTP proxy + local SOCKS5 proxy
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);

    let h_srv = tokio::spawn(serve_http_listener(
        http_listener,
        upstream_dialer.clone(),
        pki.roots.clone(),
        CondLogger::new("PROXY: ", SILENT),
        rx.clone(),
    ));
    let s_srv = tokio::spawn(serve_socks5_listener(
        socks_listener,
        upstream_dialer,
        CondLogger::new("SOCKS: ", SILENT),
        rx,
    ));

    // 1. Plain HTTP forward request through HTTP proxy (checks hop-by-hop removal)
    let mut c1 = TcpStream::connect(http_addr).await.unwrap();
    c1.write_all(
        b"GET http://synthetic.local/hello HTTP/1.1\r\nHost: synthetic.local\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp1 = String::new();
    c1.read_to_string(&mut resp1).await.unwrap();
    assert!(resp1.contains("200 OK"), "resp1={}", resp1);
    assert!(
        resp1.contains("path=/hello proxy_conn=false"),
        "resp1={}",
        resp1
    );

    // 2. HTTP CONNECT tunnel through HTTP proxy -> upstream TLS proxy -> target HTTP server
    let mut c2 = TcpStream::connect(http_addr).await.unwrap();
    c2.write_all(
        b"CONNECT synthetic-connect.local:80 HTTP/1.1\r\nHost: synthetic-connect.local:80\r\n\r\n",
    )
    .await
    .unwrap();
    let mut hdr_buf = vec![0u8; 64];
    let n = c2.read(&mut hdr_buf).await.unwrap();
    let connect_head = String::from_utf8_lossy(&hdr_buf[..n]);
    assert!(
        connect_head.starts_with("HTTP/1.1 200"),
        "head={}",
        connect_head
    );
    c2.write_all(
        b"GET /tunneled HTTP/1.1\r\nHost: synthetic-connect.local\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp2 = String::new();
    c2.read_to_string(&mut resp2).await.unwrap();
    assert!(resp2.contains("path=/tunneled"), "resp2={}", resp2);

    // 3. SOCKS5h client -> local SOCKS5 proxy (verifies remote DNS domain pass-through!)
    let socks_client = Socks5ClientDialer::new(
        socks_addr.to_string(),
        None,
        true,
        Arc::new(DirectDialer::default()),
    );
    let mut c3 = socks_client
        .dial("remote-only-domain.invalid:80".to_string())
        .await
        .unwrap();
    c3.write_all(b"GET /via-socks5 HTTP/1.1\r\nHost: remote-only-domain.invalid\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp3 = String::new();
    c3.read_to_string(&mut resp3).await.unwrap();
    assert!(resp3.contains("path=/via-socks5"), "resp3={}", resp3);

    // Confirm upstream received the unresolved domain name from SOCKS5!
    let targets = recorded_targets.lock().unwrap().clone();
    assert!(
        targets.contains(&"remote-only-domain.invalid:80".to_string()),
        "targets={:?}",
        targets
    );

    let _ = tx.send(true);
    let _ = h_srv.await;
    let _ = s_srv.await;
}

#[tokio::test]
async fn test_bootstrap_dns_udp_and_fast_resolver() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = udp.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        for _ in 0..4 {
            if let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                let mut resp = buf[..n].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                // Check qtype at end of question (last 4 bytes: qtype, qclass)
                let qtype = u16::from_be_bytes([buf[n - 4], buf[n - 3]]);
                if qtype == 1 {
                    resp[6] = 0;
                    resp[7] = 1; // ANCOUNT=1
                    resp.extend_from_slice(&[0xC0, 0x0C]);
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&60u32.to_be_bytes());
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&[127, 0, 0, 77]);
                }
                let _ = udp.send_to(&resp, peer).await;
            }
        }
    });

    let roots = build_root_store("").unwrap();
    let resolver = FastResolver::from_urls(
        roots,
        &[
            "dns://127.0.0.1:1".to_string(), // closed/failing
            format!("dns://{}", dns_addr),
        ],
    )
    .unwrap();
    let ips = resolver.lookup_ip("api2.sec-tunnel.com").await.unwrap();
    assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 77))]);
}

#[tokio::test]
async fn test_server_selection_fastest_and_probe_dl_limit() {
    let pki = generate_synthetic_pki(&["eu0.sec-tunnel.com"]);
    let auth = basic_auth_header("u", "p");

    // Local HTTP payload server
    let payload_srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let payload_addr = payload_srv.local_addr().unwrap();
    tokio::spawn(async move {
        let body_bytes = Bytes::from(vec![b'A'; 64 * 1024]);
        while let Ok((tcp, _)) = payload_srv.accept().await {
            let body_c = body_bytes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let b = body_c.clone();
                    async move { Ok::<_, Infallible>(Response::new(Full::new(b))) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let (slow_addr, _, _) = spawn_mock_tls_proxy(
        pki.server_config.clone(),
        auth.clone(),
        Some(payload_addr),
        Duration::from_millis(350),
    )
    .await;
    let (fast_addr, _, _) = spawn_mock_tls_proxy(
        pki.server_config.clone(),
        auth.clone(),
        Some(payload_addr),
        Duration::ZERO,
    )
    .await;

    let auth_cb: AuthCallback = Arc::new(move || Ok(auth.clone()));
    let direct: Arc<dyn ContextDialer> = Arc::new(DirectDialer::default());
    let d_slow: Arc<dyn ContextDialer> = Arc::new(HttpProxyDialer::new(
        slow_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        String::new(),
        Some(auth_cb.clone()),
        pki.roots.clone(),
        direct.clone(),
    ));
    let d_fast: Arc<dyn ContextDialer> = Arc::new(HttpProxyDialer::new(
        fast_addr.to_string(),
        "eu0.sec-tunnel.com".to_string(),
        String::new(),
        Some(auth_cb),
        pki.roots.clone(),
        direct,
    ));

    let test_url = format!("http://{}/bench", payload_addr);
    probe_dialer(
        d_fast.clone(),
        &test_url,
        1024,
        pki.roots.clone(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let winner = select_server(
        ServerSelection::Fastest,
        vec![d_slow, d_fast],
        &test_url,
        4096,
        pki.roots.clone(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(winner.endpoint_address(), Some(fast_addr.to_string()));
}

#[tokio::test]
async fn test_cli_exit_codes_and_csv_blacklist() {
    assert_eq!(run_with_args(["-version"]).await, 0);
    assert_eq!(run_with_args(["-unknown-flag"]).await, 2);
    assert_eq!(run_with_args(["-country", ""]).await, 2);
    assert_eq!(
        run_with_args(["-verbosity", "60", "-cafile", "/nonexistent/ca.pem"]).await,
        15
    );
    assert_eq!(
        run_with_args([
            "-verbosity",
            "60",
            "-proxy-blacklist",
            "/nonexistent/blacklist.txt"
        ])
        .await,
        18
    );

    // CSV discover + blacklist filtering
    let dir = std::env::temp_dir().join("opera_proxy_csv_test");
    let _ = std::fs::create_dir_all(&dir);
    let csv_path = dir.join("proxies.csv");
    std::fs::write(
        &csv_path,
        "country_code,country_name,host,ip_address,port\n\
         EU,Europe,eu0.sec-tunnel.com,77.111.244.26,443\n\
         EU,Europe,eu1.sec-tunnel.com,77.111.244.67,443\n\
         AS,Asia,as0.sec-tunnel.com,77.111.245.10,443\n",
    )
    .unwrap();
    let mut bl = HashSet::new();
    bl.insert("77.111.244.26:443".to_string());
    let entries = load_proxy_entries_from_csv(&csv_path, "EU", false, true, &bl).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ip, "77.111.244.67");
    let _ = std::fs::remove_file(&csv_path);
}

#[test]
fn test_io_error_type_sanity() {
    let _ = io::ErrorKind::WouldBlock;
}
