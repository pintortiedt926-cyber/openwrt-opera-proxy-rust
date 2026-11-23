use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use md5::{Digest as Md5Digest, Md5};
use rustls::RootCertStore;
use rustls_pki_types::ServerName;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use sha1::Sha1;
use sha2::Sha256;
use tokio_rustls::TlsConnector;
use url::Url;

use crate::cli::{
    DEFAULT_API_CLIENT_TYPE, DEFAULT_API_CLIENT_VERSION, DEFAULT_API_USER_AGENT, PROXY_SUFFIX,
};
use crate::dialer::{basic_auth_header, sanitize_fixed_proxy_address, ContextDialer};
use crate::resolver::{build_tls_client_config, format_host_port};

const ANON_EMAIL_LOCALPART_BYTES: usize = 32;
const DEVICE_ID_BYTES: usize = 20;
const SE_READ_LIMIT: usize = 128 * 1024;
const SE_STATUS_OK: i64 = 0;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: i64,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "API responded with error message: code={}, msg={:?}",
            self.code, self.message
        )
    }
}

impl std::error::Error for ApiError {}

pub fn is_discover_801(err: &str) -> bool {
    err.contains("code=801")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeStatusPair {
    pub code: i64,
    pub message: String,
}

impl<'de> Deserialize<'de> for SeStatusPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusVisitor;
        impl<'de> Visitor<'de> for StatusVisitor {
            type Value = SeStatusPair;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a single-entry JSON object mapping status code string to message")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut entry: Option<(String, String)> = None;
                let mut count = 0usize;
                while let Some((k, v)) = access.next_entry::<String, String>()? {
                    count += 1;
                    entry = Some((k, v));
                }
                if count != 1 {
                    return Err(de::Error::custom("ambiguous status"));
                }
                let (k, v) = entry.ok_or_else(|| de::Error::custom("missing status"))?;
                let code = k
                    .parse::<i64>()
                    .map_err(|_| de::Error::custom(format!("invalid status code {:?}", k)))?;
                Ok(SeStatusPair { code, message: v })
            }
        }
        deserializer.deserialize_map(StatusVisitor)
    }
}

#[derive(Debug, Deserialize)]
struct SeRegisterSubscriberResponse {
    #[serde(rename = "return_code")]
    status: SeStatusPair,
}

#[derive(Debug, Deserialize)]
struct SeRegisterDeviceData {
    device_id: String,
    device_password: String,
}

#[derive(Debug, Deserialize)]
struct SeRegisterDeviceResponse {
    data: Option<SeRegisterDeviceData>,
    #[serde(rename = "return_code")]
    status: SeStatusPair,
}

#[derive(Debug, Deserialize)]
struct SeDeviceGeneratePasswordData {
    device_password: String,
}

#[derive(Debug, Deserialize)]
struct SeDeviceGeneratePasswordResponse {
    data: Option<SeDeviceGeneratePasswordData>,
    #[serde(rename = "return_code")]
    status: SeStatusPair,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct SeGeoEntry {
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
}

#[derive(Debug, Deserialize)]
struct SeGeoListData {
    #[serde(default)]
    geos: Vec<SeGeoEntry>,
}

#[derive(Debug, Deserialize)]
struct SeGeoListResponse {
    data: Option<SeGeoListData>,
    #[serde(rename = "return_code")]
    status: SeStatusPair,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct SeIpEntry {
    #[serde(default)]
    pub geo: SeGeoEntry,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl SeIpEntry {
    pub fn net_addr(&self) -> String {
        let port = self.ports.first().copied().unwrap_or(443);
        format_host_port(&self.ip, port)
    }
}

impl fmt::Display for SeIpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.net_addr())
    }
}

#[derive(Debug, Deserialize)]
struct SeDiscoverData {
    #[serde(default)]
    ips: Vec<SeIpEntry>,
}

#[derive(Debug, Deserialize)]
struct SeDiscoverResponse {
    data: Option<SeDiscoverData>,
    #[serde(rename = "return_code")]
    status: SeStatusPair,
}

#[derive(Debug, Clone)]
pub struct SeEndpoints {
    pub register_subscriber: String,
    pub subscriber_login: String,
    pub register_device: String,
    pub device_generate_password: String,
    pub geo_list: String,
    pub discover: String,
}

impl Default for SeEndpoints {
    fn default() -> Self {
        Self::with_base("https://api2.sec-tunnel.com")
    }
}

impl SeEndpoints {
    pub fn with_base(base: &str) -> Self {
        let b = base.trim_end_matches('/');
        Self {
            register_subscriber: format!("{}/v4/register_subscriber", b),
            subscriber_login: format!("{}/v4/subscriber_login", b),
            register_device: format!("{}/v4/register_device", b),
            device_generate_password: format!("{}/v4/device_generate_password", b),
            geo_list: format!("{}/v4/geo_list", b),
            discover: format!("{}/v4/discover", b),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeSettings {
    pub client_version: String,
    pub client_type: String,
    pub device_name: String,
    pub operating_system: String,
    pub user_agent: String,
    pub endpoints: SeEndpoints,
}

impl Default for SeSettings {
    fn default() -> Self {
        Self {
            client_version: DEFAULT_API_CLIENT_VERSION.to_string(),
            client_type: DEFAULT_API_CLIENT_TYPE.to_string(),
            device_name: "Opera-Browser-Client".to_string(),
            operating_system: "Windows".to_string(),
            user_agent: DEFAULT_API_USER_AGENT.to_string(),
            endpoints: SeEndpoints::default(),
        }
    }
}

#[derive(Debug, Clone)]
struct DigestChallenge {
    realm: String,
    nonce: String,
    qop: Option<String>,
    opaque: Option<String>,
    algorithm: String,
    nc: u32,
}

#[derive(Debug, Default)]
struct SeClientState {
    subscriber_email: String,
    subscriber_password: String,
    device_id: String,
    assigned_device_id: String,
    assigned_device_id_hash: String,
    device_password: String,
    cookies: BTreeMap<String, String>,
    digest: Option<DigestChallenge>,
}

pub struct SeClient {
    api_username: String,
    api_secret: String,
    pub settings: SeSettings,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    fake_sni: String,
    state: Mutex<SeClientState>,
}

impl SeClient {
    pub fn new(
        api_username: String,
        api_secret: String,
        settings: SeSettings,
        dialer: Arc<dyn ContextDialer>,
        roots: Arc<RootCertStore>,
        fake_sni: String,
    ) -> Result<Self, String> {
        let device_id = random_capital_hex(DEVICE_ID_BYTES)?;
        let state = SeClientState {
            device_id,
            ..Default::default()
        };
        Ok(Self {
            api_username,
            api_secret,
            settings,
            dialer,
            roots,
            fake_sni,
            state: Mutex::new(state),
        })
    }

    pub fn get_proxy_credentials(&self) -> (String, String) {
        let st = self.state.lock().unwrap();
        (
            st.assigned_device_id_hash.clone(),
            st.device_password.clone(),
        )
    }

    pub fn reset_cookies(&self) {
        let mut st = self.state.lock().unwrap();
        st.cookies.clear();
    }

    pub async fn anon_register(&self, timeout: Duration) -> Result<(), String> {
        let local_part = random_email_local_part()?;
        let email = format!("{}@{}.best.vpn", local_part, self.settings.client_type);
        let password = capital_hex_sha1(&email);
        {
            let mut st = self.state.lock().unwrap();
            st.subscriber_email = email;
            st.subscriber_password = password;
            st.cookies.clear();
        }
        let (email, password) = {
            let st = self.state.lock().unwrap();
            (st.subscriber_email.clone(), st.subscriber_password.clone())
        };
        let resp: SeRegisterSubscriberResponse = self
            .rpc_call(
                &self.settings.endpoints.register_subscriber,
                &[("email", &email), ("password", &password)],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        Ok(())
    }

    pub async fn register_device(&self, timeout: Duration) -> Result<(), String> {
        let device_id = { self.state.lock().unwrap().device_id.clone() };
        let resp: SeRegisterDeviceResponse = self
            .rpc_call(
                &self.settings.endpoints.register_device,
                &[
                    ("client_type", &self.settings.client_type),
                    ("device_hash", &device_id),
                    ("device_name", &self.settings.device_name),
                ],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        let data = resp
            .data
            .ok_or_else(|| "register_device response missing data".to_string())?;
        let hash = capital_hex_sha1(&data.device_id);
        let mut st = self.state.lock().unwrap();
        st.assigned_device_id = data.device_id;
        st.device_password = data.device_password;
        st.assigned_device_id_hash = hash;
        Ok(())
    }

    pub async fn geo_list(&self, timeout: Duration) -> Result<Vec<SeGeoEntry>, String> {
        let device_hash = { self.state.lock().unwrap().assigned_device_id_hash.clone() };
        let resp: SeGeoListResponse = self
            .rpc_call(
                &self.settings.endpoints.geo_list,
                &[("device_id", &device_hash)],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        Ok(resp.data.map(|d| d.geos).unwrap_or_default())
    }

    pub async fn discover(
        &self,
        requested_geo: &str,
        timeout: Duration,
    ) -> Result<Vec<SeIpEntry>, String> {
        let device_hash = { self.state.lock().unwrap().assigned_device_id_hash.clone() };
        let resp: SeDiscoverResponse = self
            .rpc_call(
                &self.settings.endpoints.discover,
                &[
                    ("serial_no", &device_hash),
                    ("requested_geo", requested_geo),
                ],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        Ok(resp.data.map(|d| d.ips).unwrap_or_default())
    }

    pub async fn login(&self, timeout: Duration) -> Result<(), String> {
        let (email, password) = {
            let mut st = self.state.lock().unwrap();
            st.cookies.clear();
            (st.subscriber_email.clone(), st.subscriber_password.clone())
        };
        let resp: SeRegisterSubscriberResponse = self
            .rpc_call(
                &self.settings.endpoints.subscriber_login,
                &[
                    ("login", &email),
                    ("password", &password),
                    ("client_type", &self.settings.client_type),
                ],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        Ok(())
    }

    pub async fn device_generate_password(&self, timeout: Duration) -> Result<(), String> {
        let assigned_id = { self.state.lock().unwrap().assigned_device_id.clone() };
        let resp: SeDeviceGeneratePasswordResponse = self
            .rpc_call(
                &self.settings.endpoints.device_generate_password,
                &[("device_id", &assigned_id)],
                timeout,
            )
            .await?;
        if resp.status.code != SE_STATUS_OK {
            return Err(ApiError {
                code: resp.status.code,
                message: resp.status.message,
            }
            .to_string());
        }
        let data = resp
            .data
            .ok_or_else(|| "device_generate_password response missing data".to_string())?;
        self.state.lock().unwrap().device_password = data.device_password;
        Ok(())
    }

    async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<T, String> {
        tokio::time::timeout(timeout, self.rpc_call_inner(endpoint, params))
            .await
            .map_err(|_| format!("API call timeout after {:?} for {}", timeout, endpoint))?
    }

    async fn rpc_call_inner<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
    ) -> Result<T, String> {
        let parsed = Url::parse(endpoint).map_err(|e| format!("invalid endpoint URL: {}", e))?;
        let body_str = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in params {
                form.append_pair(k, v);
            }
            form.finish()
        };

        let path_and_query = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        };

        // First attempt: reuse cached digest challenge if available.
        let initial_auth = {
            let mut st = self.state.lock().unwrap();
            st.digest.as_mut().map(|ch| {
                ch.nc = ch.nc.saturating_add(1);
                build_digest_authorization(
                    ch,
                    &self.api_username,
                    &self.api_secret,
                    "POST",
                    &path_and_query,
                )
            })
        };

        let (status, www_auth, resp_body) = self
            .send_http_post(&parsed, &path_and_query, &body_str, initial_auth.as_deref())
            .await?;

        let final_body = if status == StatusCode::UNAUTHORIZED {
            let hdr = www_auth
                .ok_or_else(|| "HTTP 401 without WWW-Authenticate Digest header".to_string())?;
            let mut challenge = parse_digest_challenge(&hdr)?;
            challenge.nc = 1;
            let auth_header = build_digest_authorization(
                &challenge,
                &self.api_username,
                &self.api_secret,
                "POST",
                &path_and_query,
            );
            {
                self.state.lock().unwrap().digest = Some(challenge);
            }
            let (status2, _www2, body2) = self
                .send_http_post(&parsed, &path_and_query, &body_str, Some(&auth_header))
                .await?;
            if status2 != StatusCode::OK {
                return Err(format!("bad http status: {}", status2));
            }
            body2
        } else if status != StatusCode::OK {
            return Err(format!("bad http status: {}", status));
        } else {
            resp_body
        };

        serde_json::from_slice(&final_body)
            .map_err(|e| format!("failed to decode API JSON response: {}", e))
    }

    async fn send_http_post(
        &self,
        url: &Url,
        path_and_query: &str,
        body_str: &str,
        authorization: Option<&str>,
    ) -> Result<(StatusCode, Option<String>, Vec<u8>), String> {
        let use_tls = url.scheme().eq_ignore_ascii_case("https");
        let host = url
            .host_str()
            .ok_or_else(|| "API URL missing host".to_string())?
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port = url.port().unwrap_or(if use_tls { 443 } else { 80 });
        let dial_addr = format_host_port(&host, port);

        let conn = self
            .dialer
            .dial(dial_addr)
            .await
            .map_err(|e| format!("API dial failed: {}", e))?;

        let host_header = if (use_tls && port == 443) || (!use_tls && port == 80) {
            host.clone()
        } else {
            format_host_port(&host, port)
        };

        let cookie_header = {
            let st = self.state.lock().unwrap();
            if st.cookies.is_empty() {
                None
            } else {
                let joined = st
                    .cookies
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(joined)
            }
        };

        let mut req_builder = Request::builder()
            .method(Method::POST)
            .uri(path_and_query)
            .header(header::HOST, &host_header)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .header("SE-Client-Version", &self.settings.client_version)
            .header("SE-Operating-System", &self.settings.operating_system)
            .header(header::USER_AGENT, &self.settings.user_agent)
            .header(header::CONNECTION, "close");

        if let Some(auth) = authorization {
            req_builder = req_builder.header(header::AUTHORIZATION, auth);
        }
        if let Some(cookie) = cookie_header {
            req_builder = req_builder.header(header::COOKIE, cookie);
        }

        let req = req_builder
            .body(Full::new(Bytes::copy_from_slice(body_str.as_bytes())))
            .map_err(|e| format!("API request build failed: {}", e))?;

        let resp = if use_tls {
            let sni_host = if self.fake_sni.is_empty() {
                host.clone()
            } else {
                self.fake_sni.clone()
            };
            // Always verify the server certificate against the real API hostname using `roots`.
            let tls_cfg = build_tls_client_config(
                self.roots.clone(),
                Some(&host),
                true,
                vec![b"http/1.1".to_vec()],
            )?;
            let server_name = ServerName::try_from(sni_host)
                .map_err(|e| format!("invalid API TLS server name: {}", e))?;
            let tls = TlsConnector::from(tls_cfg)
                .connect(server_name, conn)
                .await
                .map_err(|e| format!("API TLS handshake failed: {}", e))?;
            let io = TokioIo::new(tls);
            let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| format!("API HTTP handshake failed: {}", e))?;
            tokio::spawn(async move {
                let _ = hconn.await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| format!("API HTTP request failed: {}", e))?
        } else {
            let io = TokioIo::new(conn);
            let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| format!("API HTTP handshake failed: {}", e))?;
            tokio::spawn(async move {
                let _ = hconn.await;
            });
            sender
                .send_request(req)
                .await
                .map_err(|e| format!("API HTTP request failed: {}", e))?
        };

        let status = resp.status();
        let www_auth = resp
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|s| s.to_ascii_lowercase().starts_with("digest "))
            .map(|s| s.to_string());

        // Capture Set-Cookie pairs into the in-memory jar.
        {
            let mut st = self.state.lock().unwrap();
            for val in resp.headers().get_all(header::SET_COOKIE) {
                if let Ok(s) = val.to_str() {
                    if let Some(pair) = s.split(';').next() {
                        if let Some((k, v)) = pair.split_once('=') {
                            let name = k.trim();
                            if !name.is_empty() {
                                st.cookies.insert(name.to_string(), v.trim().to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut body_out = Vec::new();
        let mut body = resp.into_body();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| format!("API body read error: {}", e))?;
            if let Some(data) = frame.data_ref() {
                let remaining = SE_READ_LIMIT.saturating_sub(body_out.len());
                if remaining == 0 {
                    break;
                }
                let take = data.len().min(remaining);
                body_out.extend_from_slice(&data[..take]);
            }
        }

        Ok((status, www_auth, body_out))
    }
}

fn parse_digest_challenge(header_val: &str) -> Result<DigestChallenge, String> {
    let rest = header_val
        .trim()
        .strip_prefix("Digest ")
        .or_else(|| header_val.trim().strip_prefix("digest "))
        .ok_or_else(|| format!("not a Digest WWW-Authenticate header: {:?}", header_val))?;

    let mut params = HashMap::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        let key = rest[key_start..i].trim().to_ascii_lowercase();
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1; // skip '='
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let val = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let mut s = String::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    s.push(bytes[i + 1] as char);
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    break;
                } else {
                    s.push(bytes[i] as char);
                    i += 1;
                }
            }
            s
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            rest[val_start..i].trim().to_string()
        };
        params.insert(key, val);
    }

    let realm = params
        .get("realm")
        .cloned()
        .ok_or_else(|| "Digest challenge missing realm".to_string())?;
    let nonce = params
        .get("nonce")
        .cloned()
        .ok_or_else(|| "Digest challenge missing nonce".to_string())?;
    let qop = params.get("qop").and_then(|q| {
        q.split(',')
            .map(|s| s.trim())
            .find(|&opt| opt.eq_ignore_ascii_case("auth"))
            .map(|_| "auth".to_string())
    });
    let opaque = params.get("opaque").cloned();
    let algorithm = params
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "MD5".to_string());

    Ok(DigestChallenge {
        realm,
        nonce,
        qop,
        opaque,
        algorithm,
        nc: 0,
    })
}

fn digest_hash_hex(algorithm: &str, data: &str) -> String {
    if algorithm.to_ascii_uppercase().starts_with("SHA-256") {
        let out = Sha256::digest(data.as_bytes());
        hex_lower(&out)
    } else {
        let out = Md5::digest(data.as_bytes());
        hex_lower(&out)
    }
}

fn build_digest_authorization(
    ch: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> String {
    let mut cnonce_bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut cnonce_bytes);
    let cnonce = hex_lower(&cnonce_bytes);
    let nc_hex = format!("{:08x}", ch.nc);

    let mut ha1 = digest_hash_hex(
        &ch.algorithm,
        &format!("{}:{}:{}", username, ch.realm, password),
    );
    if ch.algorithm.to_ascii_uppercase().ends_with("-SESS") {
        ha1 = digest_hash_hex(&ch.algorithm, &format!("{}:{}:{}", ha1, ch.nonce, cnonce));
    }
    let ha2 = digest_hash_hex(&ch.algorithm, &format!("{}:{}", method, uri));

    let response = if let Some(ref qop) = ch.qop {
        digest_hash_hex(
            &ch.algorithm,
            &format!("{}:{}:{}:{}:{}:{}", ha1, ch.nonce, nc_hex, cnonce, qop, ha2),
        )
    } else {
        digest_hash_hex(&ch.algorithm, &format!("{}:{}:{}", ha1, ch.nonce, ha2))
    };

    let mut parts = vec![
        format!("username=\"{}\"", username),
        format!("realm=\"{}\"", ch.realm),
        format!("nonce=\"{}\"", ch.nonce),
        format!("uri=\"{}\"", uri),
        format!("algorithm={}", ch.algorithm),
        format!("response=\"{}\"", response),
    ];
    if let Some(ref qop) = ch.qop {
        parts.push(format!("qop={}", qop));
        parts.push(format!("nc={}", nc_hex));
        parts.push(format!("cnonce=\"{}\"", cnonce));
    }
    if let Some(ref opaque) = ch.opaque {
        parts.push(format!("opaque=\"{}\"", opaque));
    }
    format!("Digest {}", parts.join(", "))
}

pub fn capital_hex_sha1(input: &str) -> String {
    let out = Sha1::digest(input.as_bytes());
    hex_upper(&out)
}

fn random_email_local_part() -> Result<String, String> {
    let mut b = [0u8; ANON_EMAIL_LOCALPART_BYTES];
    getrandom::getrandom(&mut b).map_err(|e| format!("CSPRNG failed: {}", e))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(b))
}

fn random_capital_hex(len: usize) -> Result<String, String> {
    let mut b = vec![0u8; len];
    getrandom::getrandom(&mut b).map_err(|e| format!("CSPRNG failed: {}", e))?;
    Ok(hex_upper(&b))
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_upper(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

// ============================================================================
// API proxy list normalization & loading
// ============================================================================

pub fn normalize_api_proxy(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains("://") {
        return Ok(trimmed.to_string());
    }
    if trimmed.contains('@') {
        return Ok(format!("http://{}", trimmed));
    }
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 4 {
        let host = parts[0].trim();
        let port = parts[1].trim();
        let user = parts[2].trim();
        let pass = parts[3].trim();
        if host.is_empty() || port.is_empty() || user.is_empty() {
            return Err(format!("invalid proxy entry {:?}", raw));
        }
        let mut u = Url::parse(&format!("http://{}:{}", host, port))
            .map_err(|e| format!("invalid proxy entry {:?}: {}", raw, e))?;
        let _ = u.set_username(user);
        let _ = u.set_password(Some(pass));
        return Ok(u.to_string().trim_end_matches('/').to_string());
    }
    if parts.len() == 2 {
        let host = parts[0].trim();
        let port = parts[1].trim();
        if host.is_empty() || port.is_empty() {
            return Err(format!("invalid proxy entry {:?}", raw));
        }
        return Ok(format!("http://{}:{}", host, port));
    }
    Err(format!("unsupported proxy entry format {:?}", raw))
}

pub fn load_api_proxy_list_from_reader<R: io::Read>(
    reader: R,
    source: &str,
) -> Result<Vec<String>, String> {
    let br = BufReader::new(reader);
    let mut proxies = Vec::new();
    let mut seen = HashSet::new();
    for line_res in br.lines() {
        let line = line_res
            .map_err(|e| format!("unable to read API proxy list from {}: {}", source, e))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let proxy = normalize_api_proxy(trimmed).map_err(|e| {
            format!(
                "invalid API proxy entry {:?} from {}: {}",
                trimmed, source, e
            )
        })?;
        if seen.insert(proxy.clone()) {
            proxies.push(proxy);
        }
    }
    if proxies.is_empty() {
        return Err(format!("no API proxies found in {}", source));
    }
    Ok(proxies)
}

pub fn load_api_proxy_list(filename: &str) -> Result<Vec<String>, String> {
    let f = File::open(filename)
        .map_err(|e| format!("unable to open API proxy list {:?}: {}", filename, e))?;
    load_api_proxy_list_from_reader(f, &format!("file {:?}", filename))
}

pub async fn http_get_text(
    url_str: &str,
    user_agent: &str,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<String, String> {
    tokio::time::timeout(
        timeout,
        http_get_text_inner(url_str, user_agent, dialer, roots),
    )
    .await
    .map_err(|_| format!("HTTP GET timeout after {:?} for {:?}", timeout, url_str))?
}

async fn http_get_text_inner(
    url_str: &str,
    user_agent: &str,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
) -> Result<String, String> {
    let parsed = Url::parse(url_str).map_err(|e| format!("invalid URL {:?}: {}", url_str, e))?;
    let use_tls = parsed.scheme().eq_ignore_ascii_case("https");
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("URL {:?} missing host", url_str))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = parsed.port().unwrap_or(if use_tls { 443 } else { 80 });
    let dial_addr = format_host_port(&host, port);

    let conn = dialer
        .dial(dial_addr)
        .await
        .map_err(|e| format!("dial failed for {:?}: {}", url_str, e))?;

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
        .header(header::HOST, &host_hdr)
        .header(header::USER_AGENT, user_agent)
        .header(header::CONNECTION, "close")
        .body(http_body_util::Empty::<Bytes>::new())
        .map_err(|e| format!("request build failed: {}", e))?;

    let resp = if use_tls {
        let tls_cfg = build_tls_client_config(roots, None, true, vec![b"http/1.1".to_vec()])?;
        let server_name =
            ServerName::try_from(host).map_err(|e| format!("invalid TLS server name: {}", e))?;
        let tls = TlsConnector::from(tls_cfg)
            .connect(server_name, conn)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
        let io = TokioIo::new(tls);
        let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = hconn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("HTTP GET failed: {}", e))?
    } else {
        let io = TokioIo::new(conn);
        let (mut sender, hconn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("HTTP handshake failed: {}", e))?;
        tokio::spawn(async move {
            let _ = hconn.await;
        });
        sender
            .send_request(req)
            .await
            .map_err(|e| format!("HTTP GET failed: {}", e))?
    };

    if resp.status() != StatusCode::OK {
        return Err(format!("unexpected HTTP status {}", resp.status()));
    }
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("HTTP body read failed: {}", e))?
        .to_bytes();
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub async fn load_api_proxy_list_from_url(
    list_url: &str,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    let body = http_get_text(
        list_url,
        "opera-proxy api-proxy-list fetcher/1.0",
        dialer,
        roots,
        timeout,
    )
    .await
    .map_err(|e| {
        format!(
            "unable to download API proxy list from {:?}: {}",
            list_url, e
        )
    })?;
    load_api_proxy_list_from_reader(body.as_bytes(), &format!("URL {:?}", list_url))
}

// ============================================================================
// Proxy list filtering, CSV discover/export, dp-export, freeproxy fetch
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyEndpointKey {
    pub country_code: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct ProxySpeedResult {
    pub duration: Duration,
    pub err: Option<String>,
}

impl ProxySpeedResult {
    pub fn status(&self) -> &str {
        match &self.err {
            None => "ok",
            Some(e) => e.as_str(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyListRow {
    pub country_code: String,
    pub country_name: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub speed: Option<ProxySpeedResult>,
}

pub fn parse_country_filters(raw: &str) -> (Vec<String>, bool) {
    let mut res = Vec::new();
    let mut seen = HashSet::new();
    for part in raw.split(',') {
        let country = part.trim().to_ascii_uppercase();
        if country.is_empty() {
            continue;
        }
        if country == "ALL" || country == "*" {
            return (Vec::new(), true);
        }
        if seen.insert(country.clone()) {
            res.push(country);
        }
    }
    (res, false)
}

pub fn filter_blacklisted_proxy_entries(
    entries: Vec<SeIpEntry>,
    blacklist: &HashSet<String>,
) -> (Vec<SeIpEntry>, Vec<String>) {
    if blacklist.is_empty() {
        return (entries, Vec::new());
    }
    let mut filtered = Vec::with_capacity(entries.len());
    let mut blocked = Vec::new();
    let mut blocked_seen = HashSet::new();

    for entry in entries {
        if entry.ports.is_empty() {
            let addr = format_host_port(&entry.ip, 443);
            if blacklist.contains(&addr) {
                if blocked_seen.insert(addr.clone()) {
                    blocked.push(addr);
                }
                continue;
            }
            filtered.push(entry);
            continue;
        }
        let mut ports = Vec::with_capacity(entry.ports.len());
        for port in entry.ports {
            let addr = format_host_port(&entry.ip, port);
            if blacklist.contains(&addr) {
                if blocked_seen.insert(addr.clone()) {
                    blocked.push(addr);
                }
                continue;
            }
            ports.push(port);
        }
        if !ports.is_empty() {
            filtered.push(SeIpEntry {
                geo: entry.geo,
                host: entry.host,
                ip: entry.ip,
                ports,
            });
        }
    }
    (filtered, blocked)
}

pub fn append_unique_proxies(
    dst: &mut Vec<SeIpEntry>,
    src: Vec<SeIpEntry>,
    seen: &mut HashSet<ProxyEndpointKey>,
) {
    for entry in src {
        if entry.ports.is_empty() {
            let key = ProxyEndpointKey {
                country_code: entry.geo.country_code.clone(),
                ip: entry.ip.clone(),
                port: 443,
            };
            if seen.insert(key) {
                dst.push(SeIpEntry {
                    geo: entry.geo,
                    host: entry.host,
                    ip: entry.ip,
                    ports: vec![443],
                });
            }
            continue;
        }
        let mut ports = Vec::with_capacity(entry.ports.len());
        for port in entry.ports {
            let key = ProxyEndpointKey {
                country_code: entry.geo.country_code.clone(),
                ip: entry.ip.clone(),
                port,
            };
            if seen.insert(key) {
                ports.push(port);
            }
        }
        if !ports.is_empty() {
            dst.push(SeIpEntry {
                geo: entry.geo,
                host: entry.host,
                ip: entry.ip,
                ports,
            });
        }
    }
}

pub fn sort_proxy_entries(entries: &mut [SeIpEntry]) {
    for e in entries.iter_mut() {
        e.ports.sort_unstable();
    }
    entries.sort_by(|a, b| {
        a.geo
            .country_code
            .cmp(&b.geo.country_code)
            .then_with(|| a.ip.cmp(&b.ip))
            .then_with(|| {
                let lp = a.ports.first().copied().unwrap_or(443);
                let rp = b.ports.first().copied().unwrap_or(443);
                lp.cmp(&rp)
            })
    });
}

pub fn count_proxy_ports(entries: &[SeIpEntry]) -> usize {
    entries.iter().map(|e| e.ports.len().max(1)).sum()
}

pub fn load_proxy_entries_from_csv(
    path: &Path,
    country_filter: &str,
    allow_all: bool,
    country_explicit: bool,
    blacklist: &HashSet<String>,
) -> Result<Vec<SeIpEntry>, String> {
    let f = File::open(path).map_err(|e| format!("unable to open CSV {:?}: {}", path, e))?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(f);

    let headers = rdr
        .headers()
        .map_err(|e| format!("failed to read CSV header {:?}: {}", path, e))?;
    let mut col_idx = HashMap::new();
    for (i, name) in headers.iter().enumerate() {
        col_idx.insert(name.trim().to_ascii_lowercase(), i);
    }
    for req in ["country_code", "ip_address", "port"] {
        if !col_idx.contains_key(req) {
            return Err(format!(
                "proxy CSV {:?} is missing required column {:?}",
                path, req
            ));
        }
    }

    let (filters, mut all_countries) = parse_country_filters(country_filter);
    if allow_all && !country_explicit {
        all_countries = true;
    }
    let allowed: HashSet<String> = filters.into_iter().collect();

    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut line_no = 1usize;

    for rec_res in rdr.records() {
        line_no += 1;
        let rec = rec_res.map_err(|e| {
            format!(
                "failed to read proxy CSV {:?} at line {}: {}",
                path, line_no, e
            )
        })?;
        let cc = rec
            .get(col_idx["country_code"])
            .map(|s| s.trim().to_ascii_uppercase())
            .unwrap_or_default();
        if cc.is_empty() {
            return Err(format!(
                "proxy CSV {:?} line {} has empty country_code",
                path, line_no
            ));
        }
        if !all_countries && !allowed.contains(&cc) {
            continue;
        }
        let ip = rec
            .get(col_idx["ip_address"])
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if ip.is_empty() || ip.parse::<IpAddr>().is_err() {
            return Err(format!(
                "proxy CSV {:?} line {} has invalid ip_address {:?}",
                path, line_no, ip
            ));
        }
        let port_str = rec
            .get(col_idx["port"])
            .map(|s| s.trim())
            .unwrap_or_default();
        let port = port_str.parse::<u16>().map_err(|e| {
            format!(
                "proxy CSV {:?} line {} has invalid port {:?}: {}",
                path, line_no, port_str, e
            )
        })?;
        let country_name = col_idx
            .get("country_name")
            .and_then(|&idx| rec.get(idx))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let host = col_idx
            .get("host")
            .and_then(|&idx| rec.get(idx))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let entry = SeIpEntry {
            geo: SeGeoEntry {
                country_code: cc,
                country: country_name,
            },
            host,
            ip,
            ports: vec![port],
        };
        append_unique_proxies(&mut entries, vec![entry], &mut seen);
    }

    let (mut entries, blocked) = filter_blacklisted_proxy_entries(entries, blacklist);
    if !blocked.is_empty() {
        eprintln!(
            "loadProxyEntriesFromCSV: skipped {} blacklisted endpoints: {:?}",
            blocked.len(),
            blocked
        );
    }
    if entries.is_empty() {
        return Err(format!(
            "no proxy endpoints from CSV {:?} matched country {:?}",
            path, country_filter
        ));
    }
    sort_proxy_entries(&mut entries);
    Ok(entries)
}

pub fn emit_country_csv<W: Write>(w: W, list: &[SeGeoEntry]) -> Result<(), String> {
    let mut wtr = csv::Writer::from_writer(w);
    wtr.write_record(["country code", "country name"])
        .map_err(|e| e.to_string())?;
    for c in list {
        wtr.write_record([&c.country_code, &c.country])
            .map_err(|e| e.to_string())?;
    }
    wtr.flush().map_err(|e| e.to_string())
}

pub fn build_proxy_rows(
    ips: &[SeIpEntry],
    speed_results: Option<&HashMap<ProxyEndpointKey, ProxySpeedResult>>,
    sort_by: &str,
) -> Vec<ProxyListRow> {
    let mut rows = Vec::with_capacity(count_proxy_ports(ips));
    for (i, ip) in ips.iter().enumerate() {
        let ports: &[u16] = if ip.ports.is_empty() {
            &[443]
        } else {
            &ip.ports
        };
        for &port in ports {
            let host = if ip.host.is_empty() {
                format!(
                    "{}{}.{}",
                    ip.geo.country_code.to_ascii_lowercase(),
                    i,
                    PROXY_SUFFIX
                )
            } else {
                ip.host.clone()
            };
            let speed = speed_results.and_then(|map| {
                map.get(&ProxyEndpointKey {
                    country_code: ip.geo.country_code.clone(),
                    ip: ip.ip.clone(),
                    port,
                })
                .cloned()
            });
            rows.push(ProxyListRow {
                country_code: ip.geo.country_code.clone(),
                country_name: ip.geo.country.clone(),
                host,
                ip: ip.ip.clone(),
                port,
                speed,
            });
        }
    }

    rows.sort_by(|left, right| match sort_by {
        "country" => left
            .country_code
            .cmp(&right.country_code)
            .then_with(|| left.country_name.cmp(&right.country_name))
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.port.cmp(&right.port)),
        "ip" => left
            .ip
            .cmp(&right.ip)
            .then_with(|| left.port.cmp(&right.port))
            .then_with(|| left.country_code.cmp(&right.country_code)),
        _ => {
            let left_ok = left
                .speed
                .as_ref()
                .map(|s| s.err.is_none())
                .unwrap_or(false);
            let right_ok = right
                .speed
                .as_ref()
                .map(|s| s.err.is_none())
                .unwrap_or(false);
            right_ok
                .cmp(&left_ok)
                .then_with(|| {
                    if left_ok && right_ok {
                        left.speed
                            .as_ref()
                            .unwrap()
                            .duration
                            .cmp(&right.speed.as_ref().unwrap().duration)
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .then_with(|| left.country_code.cmp(&right.country_code))
                .then_with(|| left.ip.cmp(&right.ip))
                .then_with(|| left.port.cmp(&right.port))
        }
    });

    rows
}

pub fn emit_proxy_csv<W: Write>(
    w: W,
    ips: &[SeIpEntry],
    speed_results: Option<&HashMap<ProxyEndpointKey, ProxySpeedResult>>,
    sort_by: &str,
) -> Result<(), String> {
    let mut wtr = csv::Writer::from_writer(w);
    let include_speed = speed_results.is_some();
    if include_speed {
        wtr.write_record([
            "country_code",
            "country_name",
            "host",
            "ip_address",
            "port",
            "speed_ms",
            "speed_status",
        ])
        .map_err(|e| e.to_string())?;
    } else {
        wtr.write_record(["country_code", "country_name", "host", "ip_address", "port"])
            .map_err(|e| e.to_string())?;
    }

    let rows = build_proxy_rows(ips, speed_results, sort_by);
    for row in rows {
        let port_s = row.port.to_string();
        if include_speed {
            let (speed_ms, status) = match &row.speed {
                Some(s) if s.err.is_none() => {
                    (s.duration.as_millis().to_string(), "ok".to_string())
                }
                Some(s) => (String::new(), s.status().to_string()),
                None => (String::new(), "not_tested".to_string()),
            };
            wtr.write_record([
                &row.country_code,
                &row.country_name,
                &row.host,
                &row.ip,
                &port_s,
                &speed_ms,
                &status,
            ])
            .map_err(|e| e.to_string())?;
        } else {
            wtr.write_record([
                &row.country_code,
                &row.country_name,
                &row.host,
                &row.ip,
                &port_s,
            ])
            .map_err(|e| e.to_string())?;
        }
    }
    wtr.flush().map_err(|e| e.to_string())
}

pub fn emit_proxy_list_stdout<W: Write>(
    mut w: W,
    ips: &[SeIpEntry],
    login: &str,
    password: &str,
    speed_results: Option<&HashMap<ProxyEndpointKey, ProxySpeedResult>>,
    sort_by: &str,
) -> Result<(), String> {
    writeln!(w, "Proxy login: {}", login).map_err(|e| e.to_string())?;
    writeln!(w, "Proxy password: {}", password).map_err(|e| e.to_string())?;
    writeln!(
        w,
        "Proxy-Authorization: {}",
        basic_auth_header(login, password)
    )
    .map_err(|e| e.to_string())?;
    writeln!(w).map_err(|e| e.to_string())?;
    emit_proxy_csv(w, ips, speed_results, sort_by)
}

pub fn emit_dp_export<W: Write>(
    mut w: W,
    ips: &[SeIpEntry],
    login: &str,
    password: &str,
    sni: &str,
) -> Result<(), String> {
    let mut got_one = false;
    for (i, ip) in ips.iter().enumerate() {
        let Some(&port) = ip.ports.first() else {
            continue;
        };
        let host_port = format_host_port(&ip.ip, port);
        let peername = format!(
            "{}{}.{}",
            ip.geo.country_code.to_ascii_lowercase(),
            i,
            PROXY_SUFFIX
        );
        let mut qs = url::form_urlencoded::Serializer::new(String::new());
        qs.append_pair("peername", &peername);
        qs.append_pair("sni", sni);
        let query = qs.finish();

        // Match Go's url.URL encoding preserving explicit :port and userinfo encoding.
        let mut user_url = Url::parse("https://placeholder.invalid").unwrap();
        let _ = user_url.set_username(login);
        let _ = user_url.set_password(Some(password));
        let userinfo = &user_url.as_str()["https://".len()..user_url.as_str().find('@').unwrap()];

        let full_url = format!("https://{}@{}?{}", userinfo, host_port, query);
        let key = if got_one { "#proxy" } else { "proxy" };
        writeln!(w, "{} {}", key, full_url).map_err(|e| e.to_string())?;
        got_one = true;
    }
    Ok(())
}

/// Extract `ip:port` lines from advanced.name/freeproxy HTML without regex crate.
pub fn extract_freeproxy_pairs(html: &str) -> Result<Vec<String>, String> {
    let ips = extract_attr_values(html, "data-ip=\"");
    let ports = extract_attr_values(html, "data-port=\"");
    let count = ips.len().min(ports.len());
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let ip_bytes = base64::engine::general_purpose::STANDARD
            .decode(ips[i].as_bytes())
            .map_err(|e| format!("decode ip on row {}: {}", i + 1, e))?;
        let port_bytes = base64::engine::general_purpose::STANDARD
            .decode(ports[i].as_bytes())
            .map_err(|e| format!("decode port on row {}: {}", i + 1, e))?;
        let ip = String::from_utf8_lossy(&ip_bytes);
        let port = String::from_utf8_lossy(&port_bytes);
        out.push(format!("{}:{}", ip, port));
    }
    Ok(out)
}

fn extract_attr_values<'a>(html: &'a str, marker: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(pos) = rest.find(marker) {
        let after = &rest[pos + marker.len()..];
        let Some(end) = after.find('"') else {
            break;
        };
        if end > 0 {
            out.push(&after[..end]);
        }
        rest = &after[end + 1..];
    }
    out
}

pub fn freeproxy_page_url(raw_url: &str, page: usize) -> Result<String, String> {
    let mut parsed = Url::parse(raw_url).map_err(|e| format!("parse url: {}", e))?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "page")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut q = parsed.query_pairs_mut();
        q.clear();
        for (k, v) in pairs {
            q.append_pair(&k, &v);
        }
        if page > 1 {
            q.append_pair("page", &page.to_string());
        }
    }
    if parsed.query() == Some("") {
        parsed.set_query(None);
    }
    Ok(parsed.to_string())
}

pub async fn fetch_freeproxy_to_file(
    source_url: &str,
    out_path: &str,
    dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<usize, String> {
    let mut seen = HashSet::new();
    let mut proxies = Vec::new();
    for page in 1usize..=50 {
        let page_url = freeproxy_page_url(source_url, page)?;
        let html = http_get_text(
            &page_url,
            "opera-proxy freeproxy fetcher/1.0",
            dialer.clone(),
            roots.clone(),
            timeout,
        )
        .await
        .map_err(|e| format!("page {}: {}", page, e))?;
        let page_proxies =
            extract_freeproxy_pairs(&html).map_err(|e| format!("page {}: {}", page, e))?;
        if page_proxies.is_empty() {
            break;
        }
        for p in page_proxies {
            if seen.insert(p.clone()) {
                proxies.push(p);
            }
        }
    }
    if proxies.is_empty() {
        return Err(format!("no proxies found at {}", source_url));
    }
    let mut content = proxies.join("\n");
    content.push('\n');
    std::fs::write(out_path, content).map_err(|e| e.to_string())?;
    Ok(proxies.len())
}

pub fn proxy_tls_server_name(entry: &SeIpEntry) -> String {
    if !entry.host.trim().is_empty() {
        entry.host.clone()
    } else {
        format!(
            "{}0.{}",
            entry.geo.country_code.to_ascii_lowercase(),
            PROXY_SUFFIX
        )
    }
}

pub fn proxy_endpoint_addrs(entries: &[SeIpEntry]) -> Vec<String> {
    let mut out = Vec::with_capacity(count_proxy_ports(entries));
    for e in entries {
        if e.ports.is_empty() {
            out.push(format_host_port(&e.ip, 443));
        } else {
            for &p in &e.ports {
                out.push(format_host_port(&e.ip, p));
            }
        }
    }
    out
}

pub fn sanitize_api_proxy_override(raw: &str) -> Result<String, String> {
    let norm = normalize_api_proxy(raw)?;
    if norm.is_empty() {
        return Ok(String::new());
    }
    let _ = sanitize_fixed_proxy_address; // keep helper used
    Ok(norm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_se_status_pair_deserialize() {
        let ok: SeStatusPair = serde_json::from_str(r#"{"0":"OK"}"#).unwrap();
        assert_eq!(ok.code, 0);
        assert_eq!(ok.message, "OK");

        let err801: SeStatusPair = serde_json::from_str(r#"{"801":"Rate limited"}"#).unwrap();
        assert_eq!(err801.code, 801);
        assert!(is_discover_801(
            &ApiError {
                code: err801.code,
                message: err801.message,
            }
            .to_string()
        ));

        assert!(serde_json::from_str::<SeStatusPair>(r#"{"0":"a","1":"b"}"#).is_err());
    }

    #[test]
    fn test_digest_challenge_parsing_and_auth() {
        let hdr =
            r#"Digest realm="SurfEasy", nonce="abc123", qop="auth", algorithm=MD5, opaque="op1""#;
        let mut ch = parse_digest_challenge(hdr).unwrap();
        assert_eq!(ch.realm, "SurfEasy");
        assert_eq!(ch.nonce, "abc123");
        assert_eq!(ch.qop.as_deref(), Some("auth"));
        assert_eq!(ch.opaque.as_deref(), Some("op1"));
        ch.nc = 1;
        let auth =
            build_digest_authorization(&ch, "se0316", "secret", "POST", "/v4/register_subscriber");
        assert!(auth.starts_with("Digest username=\"se0316\""));
        assert!(auth.contains("qop=auth"));
        assert!(auth.contains("nc=00000001"));
        assert!(auth.contains("opaque=\"op1\""));
    }

    #[test]
    fn test_normalize_api_proxy() {
        assert_eq!(
            normalize_api_proxy("1.2.3.4:8080").unwrap(),
            "http://1.2.3.4:8080"
        );
        assert_eq!(
            normalize_api_proxy("1.2.3.4:8080:alice:pass").unwrap(),
            "http://alice:pass@1.2.3.4:8080"
        );
        assert_eq!(
            normalize_api_proxy("socks5://127.0.0.1:1080").unwrap(),
            "socks5://127.0.0.1:1080"
        );
        assert!(normalize_api_proxy("badformat").is_err());
    }

    #[test]
    fn test_extract_freeproxy_pairs() {
        let ip_b64 = base64::engine::general_purpose::STANDARD.encode("1.2.3.4");
        let port_b64 = base64::engine::general_purpose::STANDARD.encode("8080");
        let html = format!(
            r#"<tr><td data-ip="{}" data-port="{}">x</td></tr>"#,
            ip_b64, port_b64
        );
        assert_eq!(
            extract_freeproxy_pairs(&html).unwrap(),
            vec!["1.2.3.4:8080"]
        );
    }

    #[test]
    fn test_dp_export_output() {
        let ips = vec![
            SeIpEntry {
                geo: SeGeoEntry {
                    country: "Europe".to_string(),
                    country_code: "EU".to_string(),
                },
                host: String::new(),
                ip: "77.111.244.26".to_string(),
                ports: vec![443],
            },
            SeIpEntry {
                geo: SeGeoEntry {
                    country: "Europe".to_string(),
                    country_code: "EU".to_string(),
                },
                host: String::new(),
                ip: "77.111.244.67".to_string(),
                ports: vec![443],
            },
        ];
        let mut out = Vec::new();
        emit_dp_export(&mut out, &ips, "user1", "pass1", "www.google.com").unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("proxy https://user1:pass1@77.111.244.26:443?"));
        assert!(lines[0].contains("peername=eu0.sec-tunnel.com"));
        assert!(lines[0].contains("sni=www.google.com"));
        assert!(lines[1].starts_with("#proxy https://user1:pass1@77.111.244.67:443?"));
    }
}
