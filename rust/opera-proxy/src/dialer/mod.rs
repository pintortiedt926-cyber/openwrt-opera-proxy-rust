use std::collections::HashSet;
use std::fs::File;
use std::future::Future;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::cli::{parse_csv_arg, ServerSelection};
use crate::resolver::{build_tls_client_config, format_host_port, FastResolver};

const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_RESP_MAX_HEADER_BYTES: usize = 16 * 1024;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxStream = Pin<Box<dyn AsyncStream>>;
pub type DialFuture = Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>>;
pub type AuthCallback = Arc<dyn Fn() -> Result<String, String> + Send + Sync>;

pub trait ContextDialer: Send + Sync {
    fn dial(&self, address: String) -> DialFuture;

    fn endpoint_address(&self) -> Option<String> {
        None
    }
}

/// Stream wrapper that replays pre-buffered bytes before reading from the inner stream.
pub struct PrefixStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Direct TCP dialer with bounded connect timeout.
#[derive(Debug, Clone)]
pub struct DirectDialer {
    connect_timeout: Duration,
}

impl Default for DirectDialer {
    fn default() -> Self {
        Self {
            connect_timeout: DIRECT_CONNECT_TIMEOUT,
        }
    }
}

impl DirectDialer {
    pub fn with_timeout(connect_timeout: Duration) -> Self {
        Self { connect_timeout }
    }
}

impl ContextDialer for DirectDialer {
    fn dial(&self, address: String) -> DialFuture {
        let timeout = self.connect_timeout;
        Box::pin(async move {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(&address))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("TCP connect timeout to {}", address),
                    )
                })??;
            let _ = stream.set_nodelay(true);
            Ok(Box::pin(stream) as BoxStream)
        })
    }
}

/// FixedDialer replaces the destination host with a fixed IP/host while preserving the port.
pub struct FixedDialer {
    fixed_address: String,
    next: Arc<dyn ContextDialer>,
}

impl FixedDialer {
    pub fn new(fixed_address: String, next: Arc<dyn ContextDialer>) -> Self {
        Self {
            fixed_address,
            next,
        }
    }
}

impl ContextDialer for FixedDialer {
    fn dial(&self, address: String) -> DialFuture {
        let fixed = self.fixed_address.clone();
        let next = self.next.clone();
        Box::pin(async move {
            let (_host, port) = split_host_port(&address).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid host:port {:?}", address),
                )
            })?;
            let target = format_host_port(&fixed, port);
            next.dial(target).await
        })
    }
}

/// ResolvingDialer resolves destination hostnames using `FastResolver` before dialing `next`.
pub struct ResolvingDialer {
    resolver: Arc<FastResolver>,
    next: Arc<dyn ContextDialer>,
}

impl ResolvingDialer {
    pub fn new(resolver: Arc<FastResolver>, next: Arc<dyn ContextDialer>) -> Self {
        Self { resolver, next }
    }
}

impl ContextDialer for ResolvingDialer {
    fn dial(&self, address: String) -> DialFuture {
        let resolver = self.resolver.clone();
        let next = self.next.clone();
        Box::pin(async move {
            let (host, port) = split_host_port(&address).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("failed to extract host and port from {}", address),
                )
            })?;
            let ips = resolver
                .lookup_ip(&host)
                .await
                .map_err(|e| io::Error::other(format!("dial failed on address lookup: {}", e)))?;
            let mut last_err = None;
            for ip in ips {
                let target = format_host_port(&ip.to_string(), port);
                match next.dial(target).await {
                    Ok(conn) => return Ok(conn),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                io::Error::other(format!("failed to dial {}: no addresses", address))
            }))
        })
    }
}

/// Upstream HTTP/HTTPS CONNECT proxy dialer (used for both Opera TLS proxies and `-proxy http(s)://`).
/// When `tls_server_name` is non-empty, wraps the connection in TLS with strict WebPKI verification
/// against `tls_server_name`, while sending `fake_sni` (or omitting SNI if empty) in ClientHello.
pub struct HttpProxyDialer {
    address: String,
    tls_server_name: String,
    fake_sni: String,
    auth: Option<AuthCallback>,
    roots: Arc<RootCertStore>,
    next: Arc<dyn ContextDialer>,
}

impl HttpProxyDialer {
    pub fn new(
        address: String,
        tls_server_name: String,
        fake_sni: String,
        auth: Option<AuthCallback>,
        roots: Arc<RootCertStore>,
        next: Arc<dyn ContextDialer>,
    ) -> Self {
        Self {
            address,
            tls_server_name,
            fake_sni,
            auth,
            roots,
            next,
        }
    }
}

impl ContextDialer for HttpProxyDialer {
    fn dial(&self, target_address: String) -> DialFuture {
        let proxy_addr = self.address.clone();
        let tls_server_name = self.tls_server_name.clone();
        let fake_sni = self.fake_sni.clone();
        let auth = self.auth.clone();
        let roots = self.roots.clone();
        let next = self.next.clone();

        Box::pin(async move {
            let mut conn: BoxStream = next.dial(proxy_addr.clone()).await?;

            if !tls_server_name.is_empty() {
                let send_sni = !fake_sni.is_empty();
                let tls_cfg = build_tls_client_config(
                    roots,
                    Some(&tls_server_name),
                    send_sni,
                    vec![b"http/1.1".to_vec()],
                )
                .map_err(io::Error::other)?;
                let hello_name = if send_sni {
                    fake_sni.clone()
                } else {
                    tls_server_name.clone()
                };
                let server_name = ServerName::try_from(hello_name).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid TLS server name: {}", e),
                    )
                })?;
                let tls = TlsConnector::from(tls_cfg)
                    .connect(server_name, conn)
                    .await?;
                conn = Box::pin(tls);
            }

            let mut req_buf = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
                target_address, target_address
            );
            if let Some(auth_cb) = auth {
                let header_val = auth_cb().map_err(io::Error::other)?;
                req_buf.push_str("Proxy-Authorization: ");
                req_buf.push_str(&header_val);
                req_buf.push_str("\r\n");
            }
            req_buf.push_str("\r\n");

            conn.write_all(req_buf.as_bytes()).await?;
            conn.flush().await?;

            let (status_line, status_code, remainder) =
                read_http_connect_response(&mut conn).await?;
            if status_code != 200 {
                return Err(io::Error::other(format!(
                    "bad response from upstream proxy server: {}",
                    status_line
                )));
            }

            if !remainder.is_empty() {
                conn = Box::pin(PrefixStream::new(remainder, conn));
            }
            Ok(conn)
        })
    }

    fn endpoint_address(&self) -> Option<String> {
        Some(self.address.clone())
    }
}

async fn read_http_connect_response<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<(String, u16, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() >= CONNECT_RESP_MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream proxy CONNECT response headers too large",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF while reading upstream proxy CONNECT response",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = &buf[..header_end];
    let remainder = buf[header_end + 4..].to_vec();
    let header_text = String::from_utf8_lossy(header_bytes);
    let first_line = header_text.lines().next().unwrap_or("").trim().to_string();
    let mut parts = first_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    let code_str = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTP CONNECT status line: {:?}", first_line),
        ));
    }
    let code = code_str.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTP CONNECT status code: {:?}", first_line),
        )
    })?;
    Ok((first_line, code, remainder))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Upstream SOCKS5 client dialer supporting `socks5://` (local DNS) and `socks5h://` (remote DNS).
pub struct Socks5ClientDialer {
    proxy_address: String,
    auth: Option<(String, String)>,
    resolve_remotely: bool,
    next: Arc<dyn ContextDialer>,
}

impl Socks5ClientDialer {
    pub fn new(
        proxy_address: String,
        auth: Option<(String, String)>,
        resolve_remotely: bool,
        next: Arc<dyn ContextDialer>,
    ) -> Self {
        Self {
            proxy_address,
            auth,
            resolve_remotely,
            next,
        }
    }
}

impl ContextDialer for Socks5ClientDialer {
    fn dial(&self, target_address: String) -> DialFuture {
        let proxy_addr = self.proxy_address.clone();
        let auth = self.auth.clone();
        let resolve_remotely = self.resolve_remotely;
        let next = self.next.clone();

        Box::pin(async move {
            let (host, port) = split_host_port(&target_address).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid target address {:?}", target_address),
                )
            })?;

            let mut conn = next.dial(proxy_addr).await?;

            // Greeting
            if auth.is_some() {
                conn.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
            } else {
                conn.write_all(&[0x05, 0x01, 0x00]).await?;
            }
            let mut method_resp = [0u8; 2];
            conn.read_exact(&mut method_resp).await?;
            if method_resp[0] != 0x05 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 version in greeting reply",
                ));
            }
            match method_resp[1] {
                0x00 => {}
                0x02 => {
                    let (user, pass) = auth.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "SOCKS5 server requested auth but none configured",
                        )
                    })?;
                    let ub = user.as_bytes();
                    let pb = pass.as_bytes();
                    if ub.len() > 255 || pb.len() > 255 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "SOCKS5 username/password exceeds 255 bytes",
                        ));
                    }
                    let mut auth_req = Vec::with_capacity(3 + ub.len() + pb.len());
                    auth_req.push(0x01);
                    auth_req.push(ub.len() as u8);
                    auth_req.extend_from_slice(ub);
                    auth_req.push(pb.len() as u8);
                    auth_req.extend_from_slice(pb);
                    conn.write_all(&auth_req).await?;
                    let mut auth_resp = [0u8; 2];
                    conn.read_exact(&mut auth_resp).await?;
                    if auth_resp[1] != 0x00 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "SOCKS5 authentication failed",
                        ));
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 server rejected authentication methods",
                    ));
                }
            }

            // CONNECT request
            let mut req = Vec::with_capacity(64);
            req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER=5, CMD=CONNECT, RSV=0

            if let Ok(ip) = host.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
            } else if resolve_remotely {
                let hb = host.as_bytes();
                if hb.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS5 hostname exceeds 255 bytes",
                    ));
                }
                req.push(0x03);
                req.push(hb.len() as u8);
                req.extend_from_slice(hb);
            } else {
                let resolved = tokio::net::lookup_host((host.as_str(), port))
                    .await?
                    .next()
                    .ok_or_else(|| {
                        io::Error::other(format!("DNS lookup returned no addresses for {}", host))
                    })?;
                match resolved.ip() {
                    IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
            }
            req.extend_from_slice(&port.to_be_bytes());
            conn.write_all(&req).await?;
            conn.flush().await?;

            // Read reply header
            let mut hdr = [0u8; 4];
            conn.read_exact(&mut hdr).await?;
            if hdr[0] != 0x05 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 version in CONNECT reply",
                ));
            }
            if hdr[1] != 0x00 {
                return Err(io::Error::other(format!(
                    "SOCKS5 CONNECT failed with reply code 0x{:02x}",
                    hdr[1]
                )));
            }
            // Drain BND.ADDR + BND.PORT
            match hdr[3] {
                0x01 => {
                    let mut skip = [0u8; 6];
                    conn.read_exact(&mut skip).await?;
                }
                0x03 => {
                    let mut len = [0u8; 1];
                    conn.read_exact(&mut len).await?;
                    let mut skip = vec![0u8; len[0] as usize + 2];
                    conn.read_exact(&mut skip).await?;
                }
                0x04 => {
                    let mut skip = [0u8; 18];
                    conn.read_exact(&mut skip).await?;
                }
                atyp => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown SOCKS5 ATYP 0x{:02x}", atyp),
                    ));
                }
            }
            Ok(conn)
        })
    }
}

/// Build an upstream proxy dialer from URL (`http://`, `https://`, `socks5://`, `socks5h://`).
pub fn proxy_dialer_from_url(
    raw_url: &str,
    roots: Arc<RootCertStore>,
    next: Arc<dyn ContextDialer>,
) -> Result<Arc<dyn ContextDialer>, String> {
    let u = Url::parse(raw_url)
        .map_err(|e| format!("unable to parse proxy URL {:?}: {}", raw_url, e))?;
    let host = u
        .host_str()
        .ok_or_else(|| format!("proxy URL {:?} missing host", raw_url))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();

    let scheme = u.scheme().to_ascii_lowercase();
    let creds = if !u.username().is_empty() || u.password().is_some() {
        Some((
            percent_decode_str(u.username()),
            percent_decode_str(u.password().unwrap_or("")),
        ))
    } else {
        None
    };

    match scheme.as_str() {
        "http" | "https" => {
            let port = u.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
            let address = format_host_port(&host, port);
            let tls_name = if scheme == "https" {
                host.clone()
            } else {
                String::new()
            };
            let auth: Option<AuthCallback> = creds.map(|(user, pass)| {
                let header = basic_auth_header(&user, &pass);
                Arc::new(move || Ok(header.clone())) as AuthCallback
            });
            Ok(Arc::new(HttpProxyDialer::new(
                address,
                tls_name.clone(),
                tls_name,
                auth,
                roots,
                next,
            )))
        }
        "socks5" | "socks5h" => {
            let port = u.port().unwrap_or(1080);
            let address = format_host_port(&host, port);
            Ok(Arc::new(Socks5ClientDialer::new(
                address,
                creds,
                scheme == "socks5h",
                next,
            )))
        }
        other => Err(format!("unsupported proxy type {:?}", other)),
    }
}

fn percent_decode_str(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// BypassDialer routes matching destination hosts directly instead of through the Opera proxy.
pub struct BypassDialer {
    direct: Arc<dyn ContextDialer>,
    proxied: Arc<dyn ContextDialer>,
    patterns: Vec<String>,
}

impl BypassDialer {
    pub fn new(
        raw_patterns: &[String],
        direct: Arc<dyn ContextDialer>,
        proxied: Arc<dyn ContextDialer>,
    ) -> Result<Self, String> {
        let mut patterns = Vec::with_capacity(raw_patterns.len());
        for raw in raw_patterns {
            let norm = normalize_bypass_pattern(raw)
                .map_err(|e| format!("invalid proxy bypass pattern {:?}: {}", raw, e))?;
            // Validate glob syntax upfront (matching Go path.Match validation)
            validate_glob_pattern(&norm)
                .map_err(|e| format!("invalid proxy bypass pattern {:?}: {}", raw, e))?;
            patterns.push(norm);
        }
        Ok(Self {
            direct,
            proxied,
            patterns,
        })
    }

    pub fn should_bypass(&self, address: &str) -> bool {
        let host = normalize_dial_target(address);
        if host.is_empty() {
            return false;
        }
        self.patterns.iter().any(|p| glob_match(p, &host))
    }
}

impl ContextDialer for BypassDialer {
    fn dial(&self, address: String) -> DialFuture {
        if self.should_bypass(&address) {
            self.direct.dial(address)
        } else {
            self.proxied.dial(address)
        }
    }
}

pub fn normalize_bypass_pattern(raw: &str) -> Result<String, String> {
    let mut pattern = raw.trim().to_string();
    if pattern.is_empty() {
        return Err("empty pattern".to_string());
    }

    if pattern.contains("://") {
        let parsed = Url::parse(&pattern).map_err(|e| format!("unable to parse URL: {}", e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL does not contain a host".to_string())?;
        pattern = host.to_string();
    } else if pattern.starts_with("//") {
        let parsed = Url::parse(&format!("https:{}", pattern))
            .map_err(|e| format!("unable to parse URL: {}", e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "URL does not contain a host".to_string())?;
        pattern = host.to_string();
    } else if pattern.contains('/') || pattern.contains('?') {
        let stripped = pattern.trim_start_matches('/');
        let parsed = Url::parse(&format!("https://{}", stripped))
            .map_err(|e| format!("unable to parse URL-like pattern: {}", e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "pattern does not contain a host".to_string())?;
        pattern = host.to_string();
    } else if let Some((h, _port)) = split_host_port(&pattern) {
        pattern = h;
    }

    if pattern.starts_with('[') && pattern.ends_with(']') {
        pattern = pattern[1..pattern.len() - 1].to_string();
    }
    pattern = pattern.to_ascii_lowercase();
    if pattern.is_empty() {
        return Err("empty host pattern".to_string());
    }
    Ok(pattern)
}

pub fn normalize_dial_target(address: &str) -> String {
    let mut host = address.trim().to_string();
    if host.is_empty() {
        return String::new();
    }
    if host.contains("://") {
        if let Ok(parsed) = Url::parse(&host) {
            if let Some(h) = parsed.host_str() {
                host = h.to_string();
            }
        }
    } else if let Some((h, _)) = split_host_port(&host) {
        host = h;
    }
    host.trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase()
}

fn validate_glob_pattern(pattern: &str) -> Result<(), String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if i + 1 >= chars.len() {
                    return Err("syntax error in pattern: trailing backslash".to_string());
                }
                i += 2;
            }
            '[' => {
                i += 1;
                if i < chars.len() && chars[i] == '^' {
                    i += 1;
                }
                let mut closed = false;
                let mut count = 0;
                while i < chars.len() {
                    if chars[i] == ']' && count > 0 {
                        closed = true;
                        i += 1;
                        break;
                    }
                    if chars[i] == '\\' {
                        i += 1;
                        if i >= chars.len() {
                            return Err("syntax error in pattern: unclosed bracket".to_string());
                        }
                    }
                    count += 1;
                    i += 1;
                }
                if !closed {
                    return Err("syntax error in pattern: unclosed bracket".to_string());
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Go `path.Match` compatible glob matcher (`*`, `?`, `[abc]`, `[a-z]`, `[^...]`, `\x`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_slice(&p, &t)
}

fn glob_match_slice(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            // '*' matches any sequence of non-'/' characters (Go path.Match)
            if glob_match_slice(&p[1..], t) {
                return true;
            }
            if !t.is_empty() && t[0] != '/' {
                return glob_match_slice(p, &t[1..]);
            }
            false
        }
        '?' => !t.is_empty() && t[0] != '/' && glob_match_slice(&p[1..], &t[1..]),
        '\\' => p.len() >= 2 && !t.is_empty() && p[1] == t[0] && glob_match_slice(&p[2..], &t[1..]),
        '[' => {
            if t.is_empty() || t[0] == '/' {
                return false;
            }
            let ch = t[0];
            let mut i = 1;
            let negate = if i < p.len() && p[i] == '^' {
                i += 1;
                true
            } else {
                false
            };
            let mut matched = false;
            let mut first = true;
            while i < p.len() {
                if p[i] == ']' && !first {
                    return (matched != negate) && glob_match_slice(&p[i + 1..], &t[1..]);
                }
                first = false;
                let lo = if p[i] == '\\' && i + 1 < p.len() {
                    i += 1;
                    p[i]
                } else {
                    p[i]
                };
                i += 1;
                if i + 1 < p.len() && p[i] == '-' && p[i + 1] != ']' {
                    i += 1;
                    let hi = if p[i] == '\\' && i + 1 < p.len() {
                        i += 1;
                        p[i]
                    } else {
                        p[i]
                    };
                    i += 1;
                    if ch >= lo && ch <= hi {
                        matched = true;
                    }
                } else if ch == lo {
                    matched = true;
                }
            }
            false
        }
        c => !t.is_empty() && c == t[0] && glob_match_slice(&p[1..], &t[1..]),
    }
}

pub fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => line[..idx].trim(),
        None => line.trim(),
    }
}

pub fn load_proxy_bypass_list(path: &Path) -> io::Result<Vec<String>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut seen = HashSet::new();
    let mut patterns = Vec::new();

    for line_res in reader.lines() {
        let raw_line = line_res?;
        let line = strip_comment(&raw_line);
        if line.is_empty() {
            continue;
        }
        let parsed = parse_csv_arg(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unable to parse proxy bypass entry {:?} from {}: {}",
                    line,
                    path.display(),
                    e
                ),
            )
        })?;
        for val in parsed {
            let p = val.trim().to_string();
            if p.is_empty() || !seen.insert(p.clone()) {
                continue;
            }
            patterns.push(p);
        }
    }
    Ok(patterns)
}

pub fn sanitize_fixed_proxy_address(addr: &str) -> String {
    let trimmed = addr.trim();
    if split_host_port(trimmed).is_some() {
        return trimmed.to_string();
    }
    let clean_host = trimmed.trim_matches(|c| c == '[' || c == ']');
    format_host_port(clean_host, 443)
}

pub fn load_proxy_blacklist(path_str: &str) -> io::Result<HashSet<String>> {
    let mut blacklist = HashSet::new();
    if path_str.is_empty() {
        return Ok(blacklist);
    }
    let f = File::open(path_str)?;
    let reader = BufReader::new(f);
    for line_res in reader.lines() {
        let raw_line = line_res?;
        let line = strip_comment(&raw_line);
        if line.is_empty() {
            continue;
        }
        blacklist.insert(sanitize_fixed_proxy_address(line));
    }
    Ok(blacklist)
}

pub fn basic_auth_header(login: &str, password: &str) -> String {
    let raw = format!("{}:{}", login, password);
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

/// Split `host:port` or `[ipv6]:port` into `(host_without_brackets, port)`.
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some((sa.ip().to_string(), sa.port()));
    }
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port_part) = rest.split_once("]:")?;
        let port = port_part.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    let idx = addr.rfind(':')?;
    let host = &addr[..idx];
    // Unbracketed IPv6 has multiple colons and cannot have a port without brackets.
    if host.contains(':') || host.is_empty() {
        return None;
    }
    let port = addr[idx + 1..].parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

/// Probe a dialer by issuing an HTTP(S) GET request to `target_url` and reading up to `dl_limit`
/// bytes (`0` = full body), strictly verifying TLS certificates using `roots`.
pub async fn probe_dialer(
    dialer: Arc<dyn ContextDialer>,
    target_url: &str,
    dl_limit: i64,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<(), String> {
    tokio::time::timeout(
        timeout,
        probe_dialer_inner(dialer, target_url, dl_limit, roots),
    )
    .await
    .map_err(|_| format!("probe timeout after {:?} for {:?}", timeout, target_url))?
}

async fn probe_dialer_inner(
    dialer: Arc<dyn ContextDialer>,
    target_url: &str,
    dl_limit: i64,
    roots: Arc<RootCertStore>,
) -> Result<(), String> {
    let parsed = Url::parse(target_url).map_err(|e| format!("invalid probe URL: {}", e))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let use_tls = match scheme.as_str() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported probe URL scheme {:?}", other)),
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("probe URL {:?} missing host", target_url))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = parsed.port().unwrap_or(if use_tls { 443 } else { 80 });
    let dial_addr = format_host_port(&host, port);

    let conn = dialer
        .dial(dial_addr)
        .await
        .map_err(|e| format!("probe dial failed: {}", e))?;

    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{}", parsed.path(), q),
        None => parsed.path().to_string(),
    };
    let host_hdr = if (use_tls && port == 443) || (!use_tls && port == 80) {
        host.clone()
    } else {
        format_host_port(&host, port)
    };

    let req = Request::builder()
        .method(Method::GET)
        .uri(&path_and_query)
        .header("host", &host_hdr)
        .header("connection", "close")
        .body(Empty::<Bytes>::new())
        .map_err(|e| format!("probe request build failed: {}", e))?;

    let resp = if use_tls {
        let tls_cfg = build_tls_client_config(roots, None, true, vec![b"http/1.1".to_vec()])?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid probe TLS server name: {}", e))?;
        let tls = TlsConnector::from(tls_cfg)
            .connect(server_name, conn)
            .await
            .map_err(|e| format!("probe TLS handshake failed: {}", e))?;
        let io = TokioIo::new(tls);
        let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("probe HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = hconn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("probe HTTP request failed: {}", e))?
    } else {
        let io = TokioIo::new(conn);
        let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("probe HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = hconn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("probe HTTP request failed: {}", e))?
    };

    if resp.status() != StatusCode::OK {
        return Err(format!(
            "bad status code {} for URL {:?}",
            resp.status().as_u16(),
            target_url
        ));
    }

    let mut body = resp.into_body();
    let mut downloaded: u64 = 0;
    let limit = if dl_limit > 0 {
        Some(dl_limit as u64)
    } else {
        None
    };

    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("probe body read failed: {}", e))?;
        if let Some(data) = frame.data_ref() {
            downloaded = downloaded.saturating_add(data.len() as u64);
            if let Some(max_bytes) = limit {
                if downloaded >= max_bytes {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Select one dialer from `dialers` according to `policy` (`first`, `random`, `fastest`).
pub async fn select_server(
    policy: ServerSelection,
    dialers: Vec<Arc<dyn ContextDialer>>,
    test_url: &str,
    dl_limit: i64,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<Arc<dyn ContextDialer>, String> {
    if dialers.is_empty() {
        return Err("empty dialers list".to_string());
    }
    match policy {
        ServerSelection::First => Ok(dialers[0].clone()),
        ServerSelection::Random => {
            let mut buf = [0u8; 8];
            let _ = getrandom::getrandom(&mut buf);
            let idx = (u64::from_le_bytes(buf) as usize) % dialers.len();
            Ok(dialers[idx].clone())
        }
        ServerSelection::Fastest => {
            let mut set = tokio::task::JoinSet::new();
            for d in dialers {
                let url = test_url.to_string();
                let r = roots.clone();
                set.spawn(async move {
                    match probe_dialer(d.clone(), &url, dl_limit, r, timeout).await {
                        Ok(()) => Ok(d),
                        Err(e) => Err(e),
                    }
                });
            }

            let mut errs = Vec::new();
            let select_res = tokio::time::timeout(timeout, async {
                while let Some(joined) = set.join_next().await {
                    match joined {
                        Ok(Ok(winner)) => {
                            set.abort_all();
                            return Ok(winner);
                        }
                        Ok(Err(e)) => errs.push(e),
                        Err(e) => errs.push(format!("selection task failed: {}", e)),
                    }
                }
                Err(format!("all endpoints failed probe: {}", errs.join("; ")))
            })
            .await;

            set.abort_all();
            match select_res {
                Ok(res) => res,
                Err(_) => Err(format!("server selection timed out after {:?}", timeout)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    async fn test_bypass_dialer_routes_by_host_pattern() {
        let direct = Arc::new(RecordingDialer::new("direct"));
        let proxied = Arc::new(RecordingDialer::new("proxied"));
        let d = BypassDialer::new(
            &[
                "api2.sec-tunnel.com".to_string(),
                "*.example.com".to_string(),
                "https://already.url.test/some/path".to_string(),
            ],
            direct.clone(),
            proxied.clone(),
        )
        .unwrap();

        let cases = [
            ("api2.sec-tunnel.com:443", "direct"),
            ("cdn.example.com:8443", "direct"),
            ("ALREADY.URL.TEST:443", "direct"),
            ("other.test:443", "proxied"),
        ];
        for (addr, want) in cases {
            let err = d.dial(addr.to_string()).await.err().unwrap();
            assert_eq!(err.to_string(), want, "for {}", addr);
        }
    }

    #[test]
    fn test_bypass_rejects_invalid_pattern() {
        let direct = Arc::new(RecordingDialer::new("d"));
        let proxied = Arc::new(RecordingDialer::new("p"));
        assert!(BypassDialer::new(&[" ".to_string()], direct.clone(), proxied.clone()).is_err());
        assert!(BypassDialer::new(&["[unclosed".to_string()], direct, proxied).is_err());
    }

    #[test]
    fn test_sanitize_fixed_proxy_address() {
        assert_eq!(sanitize_fixed_proxy_address("1.2.3.4"), "1.2.3.4:443");
        assert_eq!(sanitize_fixed_proxy_address("1.2.3.4:8443"), "1.2.3.4:8443");
        assert_eq!(
            sanitize_fixed_proxy_address("2001:db8::1"),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            sanitize_fixed_proxy_address("[2001:db8::1]:443"),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn test_load_proxy_bypass_list_parity() {
        let dir = std::env::temp_dir().join("opera_proxy_test_bypass");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("proxy-bypass.txt");
        let content = "# comment only\napi2.sec-tunnel.com\n*.example.com, https://download.test.local/list.txt\napi2.sec-tunnel.com # duplicate\n\n";
        std::fs::write(&file, content).unwrap();
        let got = load_proxy_bypass_list(&file).unwrap();
        assert_eq!(
            got,
            vec![
                "api2.sec-tunnel.com",
                "*.example.com",
                "https://download.test.local/list.txt",
            ]
        );
        let _ = std::fs::remove_file(&file);
    }
}
