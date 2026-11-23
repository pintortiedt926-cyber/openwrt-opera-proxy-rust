#![forbid(unsafe_code)]

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use opera_proxy::cli::{parse_csv_arg, parse_go_duration};
use opera_proxy::dialer::{ContextDialer, DirectDialer};
use opera_proxy::handler::{serve_http_listener, serve_socks5_listener};
use opera_proxy::resolver::build_root_store;
use opera_proxy::runtime::{CondLogger, SILENT};

#[tokio::test]
async fn test_http_bad_request_missing_scheme_or_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(serve_http_listener(
        listener,
        Arc::new(DirectDialer::default()),
        build_root_store("").unwrap(),
        CondLogger::new("TEST: ", SILENT),
        rx,
    ));

    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(
        b"GET /relative-path-no-scheme HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 400 "), "got: {}", resp);

    let _ = tx.send(true);
    let _ = srv.await;
}

#[tokio::test]
async fn test_http2_connect_tunnel_bidirectional() {
    // Echo server
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = echo.accept().await {
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
                let _ = s.shutdown().await;
            }
        }
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(serve_http_listener(
        proxy_listener,
        Arc::new(DirectDialer::default()),
        build_root_store("").unwrap(),
        CondLogger::new("H2: ", SILENT),
        rx,
    ));

    // HTTP/2 prior-knowledge client
    let stream = TcpStream::connect(proxy_addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(echo_addr.to_string())
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let mut tunnel = TokioIo::new(upgraded);
    tunnel.write_all(b"hello-over-h2-connect").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut out = Vec::new();
    tunnel.read_to_end(&mut out).await.unwrap();
    assert_eq!(&out[..], b"hello-over-h2-connect");

    let _ = tx.send(true);
    let _ = srv.await;
}

#[tokio::test]
async fn test_socks5_error_reply_codes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(serve_socks5_listener(
        listener,
        Arc::new(DirectDialer::default()),
        CondLogger::new("SOCKS: ", SILENT),
        rx,
    ));

    // 1. Unsupported auth method (only 0x02 offered) -> 0xFF
    let mut c1 = TcpStream::connect(addr).await.unwrap();
    c1.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut r1 = [0u8; 2];
    c1.read_exact(&mut r1).await.unwrap();
    assert_eq!(r1, [0x05, 0xFF]);

    // 2. Unsupported CMD (0x02 BIND) -> REP 0x07
    let mut c2 = TcpStream::connect(addr).await.unwrap();
    c2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut g2 = [0u8; 2];
    c2.read_exact(&mut g2).await.unwrap();
    assert_eq!(g2, [0x05, 0x00]);
    c2.write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut r2 = [0u8; 10];
    c2.read_exact(&mut r2).await.unwrap();
    assert_eq!(r2[1], 0x07);

    // 3. Connection refused -> REP 0x05 (bind & immediately close an ephemeral port)
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead_listener.local_addr().unwrap().port();
    drop(dead_listener);

    let mut c3 = TcpStream::connect(addr).await.unwrap();
    c3.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut g3 = [0u8; 2];
    c3.read_exact(&mut g3).await.unwrap();
    let p = dead_port.to_be_bytes();
    c3.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
        .await
        .unwrap();
    let mut r3 = [0u8; 10];
    c3.read_exact(&mut r3).await.unwrap();
    assert!(
        r3[1] == 0x05 || r3[1] == 0x04,
        "expected refused (0x05) or host unreachable (0x04), got 0x{:02x}",
        r3[1]
    );

    let _ = tx.send(true);
    let _ = srv.await;
}

#[tokio::test]
async fn test_concurrent_connect_tunnels_and_clean_shutdown() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let srv = tokio::spawn(serve_http_listener(
        proxy,
        Arc::new(DirectDialer::default()) as Arc<dyn ContextDialer>,
        build_root_store("").unwrap(),
        CondLogger::new("CONC: ", SILENT),
        rx,
    ));

    let mut handles = Vec::new();
    for i in 0..30usize {
        handles.push(tokio::spawn(async move {
            let mut c = TcpStream::connect(proxy_addr).await.unwrap();
            let req = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo_addr, echo_addr
            );
            c.write_all(req.as_bytes()).await.unwrap();
            let mut hbuf = [0u8; 64];
            let n = c.read(&mut hbuf).await.unwrap();
            assert!(String::from_utf8_lossy(&hbuf[..n]).starts_with("HTTP/1.1 200"));
            let payload = format!("msg-{}", i);
            c.write_all(payload.as_bytes()).await.unwrap();
            let mut resp = vec![0u8; payload.len()];
            c.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, payload.as_bytes());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let _ = tx.send(true);
    let _ = srv.await;
}

#[test]
fn test_go_duration_and_csv_edge_cases() {
    assert_eq!(
        parse_go_duration("1h2m3s4ms5us6ns").unwrap(),
        std::time::Duration::new(3723, 4_005_006)
    );
    assert_eq!(
        parse_go_duration("0.5s").unwrap(),
        std::time::Duration::from_millis(500)
    );
    assert_eq!(
        parse_go_duration("1.25h").unwrap(),
        std::time::Duration::from_secs(4500)
    );
    assert!(parse_go_duration("").is_err());
    assert!(parse_go_duration("10d").is_err());

    assert_eq!(
        parse_csv_arg(r#"https://1.1.1.1/dns-query, "tls://9.9.9.9:853""#).unwrap(),
        vec!["https://1.1.1.1/dns-query", "tls://9.9.9.9:853"]
    );
}
