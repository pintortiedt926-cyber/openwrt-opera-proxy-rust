use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use url::Url;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Build x509 RootCertStore from custom `-cafile` PEM bundle or bundled Mozilla roots (`webpki-roots`).
pub fn build_root_store(ca_file: &str) -> Result<Arc<RootCertStore>, String> {
    let mut store = RootCertStore::empty();
    if !ca_file.is_empty() {
        let f = File::open(ca_file).map_err(|e| format!("Can't load CA file: {}", e))?;
        let mut reader = BufReader::new(f);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Can't parse certificates from CA file: {}", e))?;
        let (added, _ignored) = store.add_parsable_certificates(certs);
        if added == 0 {
            return Err("Can't load certificates from CA file".to_string());
        }
        return Ok(Arc::new(store));
    }

    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(Arc::new(store))
}

/// Return the active rustls CryptoProvider (`ring` on ARM64/x86_64, pure RustCrypto on mipsel).
pub fn tls_crypto_provider() -> Arc<CryptoProvider> {
    #[cfg(feature = "ring-crypto")]
    {
        Arc::new(rustls::crypto::ring::default_provider())
    }
    #[cfg(all(not(feature = "ring-crypto"), feature = "pure-rust-crypto"))]
    {
        Arc::new(rustls_rustcrypto::provider())
    }
    #[cfg(all(not(feature = "ring-crypto"), not(feature = "pure-rust-crypto")))]
    {
        compile_error!("Enable either `ring-crypto` or `pure-rust-crypto` feature");
    }
}

/// Custom WebPKI certificate verifier that always validates the peer certificate
/// against `expected_server_name` even when ClientHello SNI is omitted or faked.
#[derive(Debug)]
pub struct OverrideServerNameVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected_server_name: ServerName<'static>,
}

impl OverrideServerNameVerifier {
    pub fn new(roots: Arc<RootCertStore>, expected_hostname: &str) -> Result<Self, String> {
        let provider = tls_crypto_provider();
        let inner = WebPkiServerVerifier::builder_with_provider(roots, provider)
            .build()
            .map_err(|e| format!("failed to build WebPKI verifier: {}", e))?;
        let expected_server_name =
            ServerName::try_from(expected_hostname.to_string()).map_err(|e| {
                format!(
                    "invalid expected TLS server name {:?}: {}",
                    expected_hostname, e
                )
            })?;
        Ok(Self {
            inner,
            expected_server_name,
        })
    }
}

impl ServerCertVerifier for OverrideServerNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &self.expected_server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls ClientConfig with strict WebPKI verification.
/// - If `override_verify_name` is `Some(host)`, peer certs are always verified against `host`,
///   regardless of what SNI (or empty SNI) is sent in ClientHello.
/// - `enable_sni` controls whether the SNI extension is sent in ClientHello.
pub fn build_tls_client_config(
    roots: Arc<RootCertStore>,
    override_verify_name: Option<&str>,
    enable_sni: bool,
    alpn: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = tls_crypto_provider();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol config error: {}", e))?;

    let mut cfg = if let Some(expected_host) = override_verify_name {
        let verifier = Arc::new(OverrideServerNameVerifier::new(roots, expected_host)?);
        builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    cfg.enable_sni = enable_sni;
    cfg.alpn_protocols = alpn;
    Ok(Arc::new(cfg))
}

#[derive(Debug, Clone)]
pub enum UpstreamResolver {
    Udp {
        addr: String,
    },
    Tcp {
        addr: String,
    },
    Dot {
        host: String,
        port: u16,
        roots: Arc<RootCertStore>,
    },
    Doh {
        url: Url,
        host: String,
        port: u16,
        use_tls: bool,
        roots: Arc<RootCertStore>,
    },
}

impl UpstreamResolver {
    pub fn from_url(raw: &str, roots: Arc<RootCertStore>) -> Result<Self, String> {
        let normalized = if !raw.contains("://") {
            if raw.starts_with("//") {
                format!("dns:{}", raw)
            } else {
                format!("dns://{}", raw)
            }
        } else {
            raw.to_string()
        };

        let mut parsed = Url::parse(&normalized)
            .map_err(|e| format!("invalid resolver URL {:?}: {}", raw, e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("resolver URL {:?} missing host", raw))?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();

        match parsed.scheme().to_ascii_lowercase().as_str() {
            "udp" | "dns" => {
                let port = parsed.port().unwrap_or(53);
                Ok(Self::Udp {
                    addr: format_host_port(&host, port),
                })
            }
            "tcp" => {
                let port = parsed.port().unwrap_or(53);
                Ok(Self::Tcp {
                    addr: format_host_port(&host, port),
                })
            }
            "tls" | "dot" => {
                let port = parsed.port().unwrap_or(853);
                Ok(Self::Dot { host, port, roots })
            }
            "http" | "https" | "doh" => {
                let scheme = parsed.scheme().to_ascii_lowercase();
                let use_tls = scheme != "http";
                let port = parsed.port().unwrap_or(if use_tls { 443 } else { 80 });
                if scheme == "doh" {
                    let _ = parsed.set_scheme("https");
                }
                Ok(Self::Doh {
                    url: parsed,
                    host,
                    port,
                    use_tls,
                    roots,
                })
            }
            other => Err(format!("resolver scheme {:?} not implemented", other)),
        }
    }

    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        // Query A and AAAA concurrently and combine (IPv4 first for router compatibility).
        let (res_a, res_aaaa) = tokio::join!(
            self.query_record(host, DNS_TYPE_A),
            self.query_record(host, DNS_TYPE_AAAA),
        );

        let mut out = Vec::new();
        let mut errs = Vec::new();
        match res_a {
            Ok(ips) => out.extend(ips),
            Err(e) => errs.push(e),
        }
        match res_aaaa {
            Ok(ips) => out.extend(ips),
            Err(e) => errs.push(e),
        }

        if !out.is_empty() {
            Ok(out)
        } else if errs.is_empty() {
            Err(format!("no DNS records found for {}", host))
        } else {
            Err(errs.join("; "))
        }
    }

    async fn query_record(&self, host: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
        let mut id_bytes = [0u8; 2];
        let _ = getrandom::getrandom(&mut id_bytes);
        let txid = u16::from_be_bytes(id_bytes);
        let query = encode_dns_query(txid, host, qtype)?;

        let resp_bytes = tokio::time::timeout(DNS_QUERY_TIMEOUT, self.exchange(&query))
            .await
            .map_err(|_| format!("DNS query timeout for {}", host))??;

        decode_dns_response(&resp_bytes, txid)
    }

    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Udp { addr } => exchange_udp(addr, query).await,
            Self::Tcp { addr } => exchange_tcp(addr, query).await,
            Self::Dot { host, port, roots } => {
                exchange_dot(host, *port, roots.clone(), query).await
            }
            Self::Doh {
                url,
                host,
                port,
                use_tls,
                roots,
            } => exchange_doh(url, host, *port, *use_tls, roots.clone(), query).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FastResolver {
    upstreams: Vec<UpstreamResolver>,
}

impl FastResolver {
    pub fn from_urls(roots: Arc<RootCertStore>, urls: &[String]) -> Result<Self, String> {
        let mut upstreams = Vec::with_capacity(urls.len());
        for (i, u) in urls.iter().enumerate() {
            let r = UpstreamResolver::from_url(u, roots.clone())
                .map_err(|e| format!("unable to construct resolver #{} ({:?}): {}", i, u, e))?;
            upstreams.push(r);
        }
        if upstreams.is_empty() {
            return Err("no bootstrap DNS resolvers configured".to_string());
        }
        Ok(Self { upstreams })
    }

    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if self.upstreams.len() == 1 {
            return self.upstreams[0].lookup_ip(host).await;
        }

        let mut set = tokio::task::JoinSet::new();
        for upstream in &self.upstreams {
            let u = upstream.clone();
            let h = host.to_string();
            set.spawn(async move { u.lookup_ip(&h).await });
        }

        let mut errors = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(ips)) if !ips.is_empty() => {
                    set.abort_all();
                    return Ok(ips);
                }
                Ok(Ok(_)) => errors.push("empty DNS response".to_string()),
                Ok(Err(e)) => errors.push(e),
                Err(e) => errors.push(format!("resolver task error: {}", e)),
            }
        }
        Err(format!(
            "all bootstrap DNS resolvers failed: {}",
            errors.join("; ")
        ))
    }
}

async fn resolve_bootstrap_addr(addr: &str) -> Result<SocketAddr, String> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("failed to resolve bootstrap DNS host {}: {}", addr, e))?
        .next()
        .ok_or_else(|| format!("no address for bootstrap DNS host {}", addr))
}

async fn exchange_udp(addr: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let target = resolve_bootstrap_addr(addr).await?;
    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("UDP bind failed: {}", e))?;
    sock.connect(target)
        .await
        .map_err(|e| format!("UDP connect failed: {}", e))?;
    sock.send(query)
        .await
        .map_err(|e| format!("UDP send failed: {}", e))?;
    let mut buf = vec![0u8; 4096];
    let n = sock
        .recv(&mut buf)
        .await
        .map_err(|e| format!("UDP recv failed: {}", e))?;
    buf.truncate(n);
    Ok(buf)
}

async fn exchange_tcp(addr: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let target = resolve_bootstrap_addr(addr).await?;
    let mut stream = TcpStream::connect(target)
        .await
        .map_err(|e| format!("TCP DNS connect failed: {}", e))?;
    write_dns_tcp_frame(&mut stream, query).await?;
    read_dns_tcp_frame(&mut stream).await
}

async fn exchange_dot(
    host: &str,
    port: u16,
    roots: Arc<RootCertStore>,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    let addr = format_host_port(host, port);
    let target = resolve_bootstrap_addr(&addr).await?;
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|e| format!("DoT connect failed: {}", e))?;
    let tls_cfg = build_tls_client_config(roots, None, true, vec![b"dot".to_vec()])?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid DoT server name {:?}: {}", host, e))?;
    let mut tls = TlsConnector::from(tls_cfg)
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("DoT TLS handshake failed: {}", e))?;
    write_dns_tcp_frame(&mut tls, query).await?;
    read_dns_tcp_frame(&mut tls).await
}

async fn exchange_doh(
    url: &Url,
    host: &str,
    port: u16,
    use_tls: bool,
    roots: Arc<RootCertStore>,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    let addr = format_host_port(host, port);
    let target = resolve_bootstrap_addr(&addr).await?;
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|e| format!("DoH connect failed: {}", e))?;

    let path_and_query = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };
    let host_header = if (use_tls && port == 443) || (!use_tls && port == 80) {
        host.to_string()
    } else {
        format_host_port(host, port)
    };

    let req = Request::builder()
        .method(Method::POST)
        .uri(&path_and_query)
        .header("host", &host_header)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(query)))
        .map_err(|e| format!("DoH request build failed: {}", e))?;

    let resp = if use_tls {
        let tls_cfg = build_tls_client_config(roots, None, true, vec![b"http/1.1".to_vec()])?;
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid DoH server name {:?}: {}", host, e))?;
        let tls = TlsConnector::from(tls_cfg)
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("DoH TLS handshake failed: {}", e))?;
        let io = TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("DoH HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("DoH request failed: {}", e))?
    } else {
        let io = TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("DoH HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("DoH request failed: {}", e))?
    };

    if resp.status() != StatusCode::OK {
        return Err(format!("DoH HTTP error status: {}", resp.status()));
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("DoH body read failed: {}", e))?
        .to_bytes();
    Ok(body.to_vec())
}

async fn write_dns_tcp_frame<W: AsyncWriteExt + Unpin>(
    stream: &mut W,
    query: &[u8],
) -> Result<(), String> {
    let len = u16::try_from(query.len()).map_err(|_| "DNS query too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("DNS TCP write length failed: {}", e))?;
    stream
        .write_all(query)
        .await
        .map_err(|e| format!("DNS TCP write payload failed: {}", e))?;
    stream
        .flush()
        .await
        .map_err(|e| format!("DNS TCP flush failed: {}", e))?;
    Ok(())
}

async fn read_dns_tcp_frame<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("DNS TCP read length failed: {}", e))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("DNS TCP read payload failed: {}", e))?;
    Ok(buf)
}

pub fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Encode a standard recursive DNS query (RFC 1035) for `host` and `qtype` (A=1, AAAA=28).
pub fn encode_dns_query(txid: u16, host: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err("empty DNS hostname".to_string());
    }
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT=0
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT=0

    for label in trimmed.split('.') {
        let lb = label.as_bytes();
        if lb.is_empty() || lb.len() > 63 {
            return Err(format!("invalid DNS label {:?} in {:?}", label, host));
        }
        buf.push(lb.len() as u8);
        buf.extend_from_slice(lb);
    }
    buf.push(0); // root terminator
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(buf)
}

/// Decode A and AAAA answer records from an RFC 1035 DNS wire response.
pub fn decode_dns_response(msg: &[u8], expected_txid: u16) -> Result<Vec<IpAddr>, String> {
    if msg.len() < 12 {
        return Err("DNS response shorter than 12 bytes".to_string());
    }
    let txid = u16::from_be_bytes([msg[0], msg[1]]);
    if txid != expected_txid {
        return Err(format!(
            "DNS txid mismatch: got {}, expected {}",
            txid, expected_txid
        ));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if (flags & 0x8000) == 0 {
        return Err("DNS packet is not a response".to_string());
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS server returned RCODE {}", rcode));
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        offset = skip_dns_name(msg, offset)?;
        if offset + 4 > msg.len() {
            return Err("truncated DNS question".to_string());
        }
        offset += 4;
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(msg, offset)?;
        if offset + 10 > msg.len() {
            return Err("truncated DNS answer header".to_string());
        }
        let rtype = u16::from_be_bytes([msg[offset], msg[offset + 1]]);
        let rclass = u16::from_be_bytes([msg[offset + 2], msg[offset + 3]]);
        let rdlen = u16::from_be_bytes([msg[offset + 8], msg[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > msg.len() {
            return Err("truncated DNS answer rdata".to_string());
        }
        if rclass == DNS_CLASS_IN {
            if rtype == DNS_TYPE_A && rdlen == 4 {
                let ip = Ipv4Addr::new(
                    msg[offset],
                    msg[offset + 1],
                    msg[offset + 2],
                    msg[offset + 3],
                );
                addrs.push(IpAddr::V4(ip));
            } else if rtype == DNS_TYPE_AAAA && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&msg[offset..offset + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        offset += rdlen;
    }
    Ok(addrs)
}

fn skip_dns_name(msg: &[u8], mut offset: usize) -> Result<usize, String> {
    let mut jumps = 0usize;
    loop {
        if offset >= msg.len() {
            return Err("truncated DNS name".to_string());
        }
        let len = msg[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= msg.len() {
                return Err("truncated DNS compression pointer".to_string());
            }
            jumps += 1;
            if jumps > 16 {
                return Err("DNS compression pointer loop".to_string());
            }
            // Pointer terminates the inline name in the current section.
            return Ok(offset + 2);
        }
        if (len & 0xC0) != 0 {
            return Err("invalid DNS label type".to_string());
        }
        offset += 1 + (len as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_decode_dns_a_and_aaaa() {
        let query = encode_dns_query(0x1234, "api2.sec-tunnel.com", DNS_TYPE_A).unwrap();
        // Build a synthetic response echoing the question + 1 A record + 1 AAAA record using compression pointer 0xC00C.
        let mut resp = query.clone();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, RCODE=0
        resp[6] = 0x00;
        resp[7] = 0x02; // ANCOUNT=2

        // Answer 1: A -> 77.111.247.143
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[77, 111, 247, 143]);

        // Answer 2: AAAA -> 2001:db8::1
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&60u32.to_be_bytes());
        resp.extend_from_slice(&16u16.to_be_bytes());
        resp.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets());

        let ips = decode_dns_response(&resp, 0x1234).unwrap();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(77, 111, 247, 143)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn test_decode_dns_rejects_txid_mismatch_and_rcode() {
        let mut resp = encode_dns_query(0x1111, "example.com", DNS_TYPE_A).unwrap();
        resp[2] = 0x81;
        resp[3] = 0x83; // NXDOMAIN
        assert!(decode_dns_response(&resp, 0x1111).is_err());
        assert!(decode_dns_response(&resp, 0x2222).is_err());
    }

    #[test]
    fn test_resolver_url_schemes() {
        let roots = build_root_store("").unwrap();
        assert!(matches!(
            UpstreamResolver::from_url("1.1.1.1", roots.clone()).unwrap(),
            UpstreamResolver::Udp { .. }
        ));
        assert!(matches!(
            UpstreamResolver::from_url("dns://8.8.8.8:53", roots.clone()).unwrap(),
            UpstreamResolver::Udp { .. }
        ));
        assert!(matches!(
            UpstreamResolver::from_url("tcp://9.9.9.9", roots.clone()).unwrap(),
            UpstreamResolver::Tcp { .. }
        ));
        assert!(matches!(
            UpstreamResolver::from_url("tls://9.9.9.9:853", roots.clone()).unwrap(),
            UpstreamResolver::Dot { .. }
        ));
        assert!(matches!(
            UpstreamResolver::from_url("https://1.1.1.1/dns-query", roots.clone()).unwrap(),
            UpstreamResolver::Doh { use_tls: true, .. }
        ));
        assert!(UpstreamResolver::from_url("ftp://1.1.1.1", roots).is_err());
    }

    #[test]
    fn test_build_root_store_bundled_and_missing_file() {
        let store = build_root_store("").unwrap();
        assert!(!store.is_empty());
        assert!(build_root_store("/nonexistent/ca.pem").is_err());
    }
}
