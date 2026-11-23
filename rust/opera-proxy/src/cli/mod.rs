use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

pub const API_DOMAIN: &str = "api2.sec-tunnel.com";
pub const PROXY_SUFFIX: &str = "sec-tunnel.com";
pub const DEFAULT_DISCOVER_CSV_FALLBACK: &str = "proxies.csv";
pub const DEFAULT_PROXY_BYPASS_FALLBACK: &str = "proxy-bypass.txt";

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_SERVER_SELECTION_TIMEOUT: Duration = Duration::from_secs(60);

pub const DEFAULT_API_CLIENT_VERSION: &str = "Stable 114.0.5282.21";
pub const DEFAULT_API_CLIENT_TYPE: &str = "se0316";
pub const DEFAULT_API_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0";
pub const DEFAULT_API_LOGIN: &str = "se0316";
// Public application-level Digest Auth secret embedded in upstream Opera/opera-proxy client
// (Alexey71/opera-proxy main.go). Required for SurfEasy API compatibility.
pub const DEFAULT_API_PASSWORD: &str = "SILrMEPBmJuhomxWkfm3JalqHX2Eheg1YhlEZiMh8II";

pub const DEFAULT_SPEED_TEST_URL: &str =
    "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js";
pub const DEFAULT_FREEPROXY_URL: &str = "https://advanced.name/freeproxy";

pub const DEFAULT_BOOTSTRAP_DNS: &[&str] = &[
    "https://1.1.1.3/dns-query",
    "https://8.8.8.8/dns-query",
    "https://dns.google/dns-query",
    "https://security.cloudflare-dns.com/dns-query",
    "https://fidelity.vm-0.com/q",
    "https://wikimedia-dns.org/dns-query",
    "https://dns.adguard-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.cleanbrowsing.org/doh/adult-filter/",
];

pub fn version() -> &'static str {
    option_env!("OPERA_PROXY_VERSION").unwrap_or(concat!("v", env!("CARGO_PKG_VERSION"), "-rust"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerSelection {
    First,
    Random,
    Fastest,
}

impl ServerSelection {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "first" => Ok(Self::First),
            "random" => Ok(Self::Random),
            "fastest" => Ok(Self::Fastest),
            _ => Err("unknown server selection strategy".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Random => "random",
            Self::Fastest => "fastest",
        }
    }
}

impl fmt::Display for ServerSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    HelpRequested,
    Invalid(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => f.write_str("help requested"),
            Self::Invalid(msg) => f.write_str(msg),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub country: String,
    pub country_explicit: bool,
    pub discover_csv: String,
    pub list_countries: bool,
    pub list_proxies: bool,
    pub list_proxies_all: bool,
    pub list_proxies_all_out: String,
    pub fetch_freeproxy_out: String,
    pub fetch_freeproxy_url: String,
    pub estimate_proxy_speed: bool,
    pub sort_proxies_by: String,
    pub dp_export: bool,
    pub discover_repeat: i32,
    pub bind_address: String,
    pub socks_mode: bool,
    pub verbosity: i32,
    pub timeout: Duration,
    pub show_version: bool,
    pub proxy: String,
    pub api_login: String,
    pub api_password: String,
    pub api_address: String,
    pub api_client_type: String,
    pub api_client_version: String,
    pub api_user_agent: String,
    pub api_proxy: String,
    pub api_proxy_file: String,
    pub api_proxy_list_url: String,
    pub api_proxy_parallel: i32,
    pub bootstrap_dns: Vec<String>,
    pub refresh: Duration,
    pub refresh_retry: Duration,
    pub init_retries: i32,
    pub init_retry_interval: Duration,
    pub ca_file: String,
    pub fake_sni: String,
    pub proxy_bypass: Vec<String>,
    pub proxy_blacklist_file: String,
    pub override_proxy_address: String,
    pub proxy_speed_test_url: String,
    pub proxy_speed_timeout: Duration,
    pub proxy_speed_dl_limit: i64,
    pub server_selection: ServerSelection,
    pub server_selection_timeout: Duration,
    pub server_selection_test_url: String,
    pub server_selection_dl_limit: i64,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            country: "EU".to_string(),
            country_explicit: false,
            discover_csv: String::new(),
            list_countries: false,
            list_proxies: false,
            list_proxies_all: false,
            list_proxies_all_out: String::new(),
            fetch_freeproxy_out: String::new(),
            fetch_freeproxy_url: DEFAULT_FREEPROXY_URL.to_string(),
            estimate_proxy_speed: false,
            sort_proxies_by: "speed".to_string(),
            dp_export: false,
            discover_repeat: 1,
            bind_address: "127.0.0.1:18080".to_string(),
            socks_mode: false,
            verbosity: 20,
            timeout: DEFAULT_TIMEOUT,
            show_version: false,
            proxy: String::new(),
            api_login: DEFAULT_API_LOGIN.to_string(),
            api_password: DEFAULT_API_PASSWORD.to_string(),
            api_address: String::new(),
            api_client_type: DEFAULT_API_CLIENT_TYPE.to_string(),
            api_client_version: DEFAULT_API_CLIENT_VERSION.to_string(),
            api_user_agent: DEFAULT_API_USER_AGENT.to_string(),
            api_proxy: String::new(),
            api_proxy_file: String::new(),
            api_proxy_list_url: String::new(),
            api_proxy_parallel: 15,
            bootstrap_dns: DEFAULT_BOOTSTRAP_DNS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            refresh: Duration::from_secs(4 * 3600),
            refresh_retry: Duration::from_secs(5),
            init_retries: 0,
            init_retry_interval: Duration::from_secs(5),
            ca_file: String::new(),
            fake_sni: String::new(),
            proxy_bypass: Vec::new(),
            proxy_blacklist_file: String::new(),
            override_proxy_address: String::new(),
            proxy_speed_test_url: DEFAULT_SPEED_TEST_URL.to_string(),
            proxy_speed_timeout: Duration::from_secs(15),
            proxy_speed_dl_limit: 262_144,
            server_selection: ServerSelection::Fastest,
            server_selection_timeout: DEFAULT_SERVER_SELECTION_TIMEOUT,
            server_selection_test_url: DEFAULT_SPEED_TEST_URL.to_string(),
            server_selection_dl_limit: 0,
        }
    }
}

impl CliArgs {
    /// Parse CLI arguments using Go `flag` compatible syntax:
    /// `-flag`, `--flag`, `-flag=value`, `-flag value`, bool `-flag` / `-flag=true|false`.
    pub fn parse_from<I, S>(iter: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut args = Self::default();
        let tokens: Vec<String> = iter.into_iter().map(|s| s.as_ref().to_string()).collect();
        let mut idx = 0;

        while idx < tokens.len() {
            let tok = &tokens[idx];
            if tok == "--" || !tok.starts_with('-') || tok == "-" {
                break;
            }
            let stripped = tok.strip_prefix("--").unwrap_or_else(|| &tok[1..]);
            if stripped.starts_with('-') || stripped.starts_with('=') || stripped.is_empty() {
                return Err(ParseError::Invalid(format!("bad flag syntax: {}", tok)));
            }

            let (name, inline_val) = match stripped.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (stripped, None),
            };

            if name == "h" || name == "help" {
                return Err(ParseError::HelpRequested);
            }

            if is_bool_flag(name) {
                let val_str = inline_val.unwrap_or("true");
                args.set_flag(name, val_str)?;
                idx += 1;
            } else if is_known_flag(name) {
                let val_str = if let Some(v) = inline_val {
                    idx += 1;
                    v.to_string()
                } else {
                    if idx + 1 >= tokens.len() {
                        return Err(ParseError::Invalid(format!(
                            "flag needs an argument: -{}",
                            name
                        )));
                    }
                    let v = tokens[idx + 1].clone();
                    idx += 2;
                    v
                };
                args.set_flag(name, &val_str)?;
            } else {
                return Err(ParseError::Invalid(format!(
                    "flag provided but not defined: -{}",
                    name
                )));
            }
        }

        args.validate()?;
        Ok(args)
    }

    fn set_flag(&mut self, name: &str, value: &str) -> Result<(), ParseError> {
        let inv = |msg: String| ParseError::Invalid(msg);
        match name {
            "country" => {
                self.country = value.to_string();
                self.country_explicit = true;
            }
            "discover-csv" => self.discover_csv = value.to_string(),
            "list-countries" => self.list_countries = parse_go_bool(name, value).map_err(inv)?,
            "list-proxies" => self.list_proxies = parse_go_bool(name, value).map_err(inv)?,
            "list-proxies-all" => {
                self.list_proxies_all = parse_go_bool(name, value).map_err(inv)?
            }
            "list-proxies-all-out" => self.list_proxies_all_out = value.to_string(),
            "fetch-freeproxy-out" => self.fetch_freeproxy_out = value.to_string(),
            "fetch-freeproxy-url" => self.fetch_freeproxy_url = value.to_string(),
            "estimate-proxy-speed" => {
                self.estimate_proxy_speed = parse_go_bool(name, value).map_err(inv)?
            }
            "sort-proxies-by" => self.sort_proxies_by = value.to_string(),
            "dp-export" => self.dp_export = parse_go_bool(name, value).map_err(inv)?,
            "discover-repeat" => {
                self.discover_repeat = parse_go_i32(name, value).map_err(inv)?;
            }
            "bind-address" => self.bind_address = value.to_string(),
            "socks-mode" => self.socks_mode = parse_go_bool(name, value).map_err(inv)?,
            "verbosity" => self.verbosity = parse_go_i32(name, value).map_err(inv)?,
            "timeout" => self.timeout = parse_go_duration(value).map_err(inv)?,
            "version" => self.show_version = parse_go_bool(name, value).map_err(inv)?,
            "proxy" => self.proxy = value.to_string(),
            "proxy-bypass" => self.proxy_bypass = parse_csv_arg(value).map_err(inv)?,
            "api-client-version" => self.api_client_version = value.to_string(),
            "api-client-type" => self.api_client_type = value.to_string(),
            "api-user-agent" => self.api_user_agent = value.to_string(),
            "api-login" => self.api_login = value.to_string(),
            "api-password" => self.api_password = value.to_string(),
            "api-address" => self.api_address = value.to_string(),
            "api-proxy" => self.api_proxy = value.to_string(),
            "api-proxy-file" => self.api_proxy_file = value.to_string(),
            "api-proxy-list-url" => self.api_proxy_list_url = value.to_string(),
            "api-proxy-parallel" => {
                self.api_proxy_parallel = parse_go_i32(name, value).map_err(inv)?;
            }
            "bootstrap-dns" => self.bootstrap_dns = parse_csv_arg(value).map_err(inv)?,
            "refresh" => self.refresh = parse_go_duration(value).map_err(inv)?,
            "refresh-retry" => self.refresh_retry = parse_go_duration(value).map_err(inv)?,
            "init-retries" => self.init_retries = parse_go_i32(name, value).map_err(inv)?,
            "init-retry-interval" => {
                self.init_retry_interval = parse_go_duration(value).map_err(inv)?
            }
            "cafile" => self.ca_file = value.to_string(),
            "fake-SNI" => self.fake_sni = value.to_string(),
            "proxy-blacklist" => self.proxy_blacklist_file = value.to_string(),
            "override-proxy-address" => self.override_proxy_address = value.to_string(),
            "proxy-speed-test-url" => self.proxy_speed_test_url = value.to_string(),
            "proxy-speed-timeout" => {
                self.proxy_speed_timeout = parse_go_duration(value).map_err(inv)?
            }
            "proxy-speed-dl-limit" => {
                self.proxy_speed_dl_limit = parse_go_i64(name, value).map_err(inv)?;
            }
            "server-selection" => {
                self.server_selection = ServerSelection::parse(value).map_err(inv)?;
            }
            "server-selection-timeout" => {
                self.server_selection_timeout = parse_go_duration(value).map_err(inv)?;
            }
            "server-selection-test-url" => self.server_selection_test_url = value.to_string(),
            "server-selection-dl-limit" => {
                self.server_selection_dl_limit = parse_go_i64(name, value).map_err(inv)?;
            }
            "config" => self.read_config_file(Path::new(value))?,
            _ => {
                return Err(ParseError::Invalid(format!(
                    "flag provided but not defined: -{}",
                    name
                )));
            }
        }
        Ok(())
    }

    fn read_config_file(&mut self, path: &Path) -> Result<(), ParseError> {
        let mut f = File::open(path).map_err(|e| {
            ParseError::Invalid(format!(
                "unable to open config file {:?}: {}",
                path.display(),
                e
            ))
        })?;
        let mut content = String::new();
        f.read_to_string(&mut content).map_err(|e| {
            ParseError::Invalid(format!(
                "unable to read config file {:?}: {}",
                path.display(),
                e
            ))
        })?;
        self.apply_config_reader(content.as_bytes(), &path.display().to_string())
    }

    pub fn apply_config_reader<R: io::Read>(
        &mut self,
        reader: R,
        source_name: &str,
    ) -> Result<(), ParseError> {
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(b' ')
            .comment(Some(b'#'))
            .flexible(true)
            .trim(csv::Trim::Headers)
            .from_reader(reader);

        let mut raw = csv::StringRecord::new();
        let mut line_no = 0usize;
        loop {
            line_no += 1;
            match rdr.read_record(&mut raw) {
                Ok(false) => break,
                Ok(true) => {
                    // Go's csv.Reader with TrimLeadingSpace trims leading space on fields;
                    // filter out empty tokens created by multiple spaces when unquoted.
                    let fields: Vec<&str> = raw
                        .iter()
                        .map(|s| s.trim_start())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if fields.is_empty() {
                        continue;
                    }
                    let key = fields[0];
                    let val = if fields.len() == 1 {
                        "true".to_string()
                    } else {
                        fields[1..].join(" ")
                    };
                    self.set_flag(key, &val).map_err(|e| {
                        ParseError::Invalid(format!(
                            "error parsing config file {:?} at record {}: {}",
                            source_name, line_no, e
                        ))
                    })?;
                }
                Err(e) => {
                    return Err(ParseError::Invalid(format!(
                        "configuration file parsing failed: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate(&mut self) -> Result<(), ParseError> {
        if self.country.is_empty() {
            return Err(ParseError::Invalid(
                "Country can't be empty string.".to_string(),
            ));
        }
        if self.discover_repeat < 1 {
            return Err(ParseError::Invalid(
                "discover-repeat must be >= 1.".to_string(),
            ));
        }
        if self.api_proxy_parallel < 1 {
            return Err(ParseError::Invalid(
                "api-proxy-parallel must be >= 1.".to_string(),
            ));
        }
        match self.sort_proxies_by.as_str() {
            "speed" | "country" | "ip" => {}
            _ => {
                return Err(ParseError::Invalid(
                    "sort-proxies-by must be one of: speed, country, ip.".to_string(),
                ));
            }
        }
        if !self.list_proxies_all_out.is_empty() {
            self.list_proxies_all = true;
        }
        if self.list_proxies_all {
            self.estimate_proxy_speed = true;
        }

        let output_modes = [
            self.list_countries,
            self.list_proxies,
            self.list_proxies_all,
            self.dp_export,
            !self.fetch_freeproxy_out.is_empty(),
        ]
        .into_iter()
        .filter(|&b| b)
        .count();

        if output_modes > 1 {
            return Err(ParseError::Invalid(
                "mutually exclusive output arguments were provided".to_string(),
            ));
        }
        Ok(())
    }
}

fn is_bool_flag(name: &str) -> bool {
    matches!(
        name,
        "list-countries"
            | "list-proxies"
            | "list-proxies-all"
            | "estimate-proxy-speed"
            | "dp-export"
            | "socks-mode"
            | "version"
    )
}

fn is_known_flag(name: &str) -> bool {
    is_bool_flag(name)
        || matches!(
            name,
            "country"
                | "discover-csv"
                | "list-proxies-all-out"
                | "fetch-freeproxy-out"
                | "fetch-freeproxy-url"
                | "sort-proxies-by"
                | "discover-repeat"
                | "bind-address"
                | "verbosity"
                | "timeout"
                | "proxy"
                | "proxy-bypass"
                | "api-client-version"
                | "api-client-type"
                | "api-user-agent"
                | "api-login"
                | "api-password"
                | "api-address"
                | "api-proxy"
                | "api-proxy-file"
                | "api-proxy-list-url"
                | "api-proxy-parallel"
                | "bootstrap-dns"
                | "refresh"
                | "refresh-retry"
                | "init-retries"
                | "init-retry-interval"
                | "cafile"
                | "fake-SNI"
                | "proxy-blacklist"
                | "override-proxy-address"
                | "proxy-speed-test-url"
                | "proxy-speed-timeout"
                | "proxy-speed-dl-limit"
                | "server-selection"
                | "server-selection-timeout"
                | "server-selection-test-url"
                | "server-selection-dl-limit"
                | "config"
        )
}

fn parse_go_bool(name: &str, value: &str) -> Result<bool, String> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!(
            "invalid boolean value {:?} for -{}: parse error",
            value, name
        )),
    }
}

fn parse_go_i32(name: &str, value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("invalid value {:?} for flag -{}: parse error", value, name))
}

fn parse_go_i64(name: &str, value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("invalid value {:?} for flag -{}: parse error", value, name))
}

/// Parse a single CSV line into comma-separated values matching Go `CSVArg.Set`
/// (with `TrimLeadingSpace = true`, so spaces after commas before quotes are skipped).
pub fn parse_csv_arg(line: &str) -> Result<Vec<String>, String> {
    if line.is_empty() {
        return Ok(Vec::new());
    }
    let mut normalized = String::with_capacity(line.len());
    let mut in_quotes = false;
    let mut at_field_start = true;
    for ch in line.chars() {
        if at_field_start && !in_quotes && (ch == ' ' || ch == '\t') {
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            at_field_start = false;
        } else {
            at_field_start = ch == ',' && !in_quotes;
        }
        normalized.push(ch);
    }

    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(normalized.as_bytes());
    let mut rec = csv::StringRecord::new();
    match rdr.read_record(&mut rec) {
        Ok(false) => Ok(Vec::new()),
        Ok(true) => Ok(rec.iter().map(|s| s.to_string()).collect()),
        Err(e) => Err(format!("unable to parse comma-separated argument: {}", e)),
    }
}

/// Parse a Go `time.ParseDuration` string (e.g. `4h0m0s`, `30s`, `500ms`, `1.5m`, `0`).
/// Negative durations are rejected (clamped/error) because Rust `Duration` is non-negative.
pub fn parse_go_duration(raw: &str) -> Result<Duration, String> {
    let orig = raw;
    let s = raw.trim();
    if s.is_empty() {
        return Err(format!("time: invalid duration {:?}", orig));
    }
    if s == "0" || s == "+0" {
        return Ok(Duration::ZERO);
    }
    let s = if let Some(rest) = s.strip_prefix('+') {
        rest
    } else if s.starts_with('-') {
        return Err(format!("time: negative duration not supported: {:?}", orig));
    } else {
        s
    };

    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut total_nanos: u128 = 0;

    while i < bytes.len() {
        let num_start = i;
        let mut has_int = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            has_int = true;
            i += 1;
        }
        let mut frac_val: u128 = 0;
        let mut frac_scale: u128 = 1;
        let mut has_frac = false;
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                has_frac = true;
                if frac_scale <= 1_000_000_000 {
                    frac_val = frac_val * 10 + (bytes[i] - b'0') as u128;
                    frac_scale *= 10;
                }
                i += 1;
            }
        }
        if !has_int && !has_frac {
            return Err(format!("time: invalid duration {:?}", orig));
        }

        let int_str = &s[num_start..s[num_start..i].find('.').map_or(i, |p| num_start + p)];
        let int_val: u128 = if int_str.is_empty() {
            0
        } else {
            int_str
                .parse::<u128>()
                .map_err(|_| format!("time: invalid duration {:?}", orig))?
        };

        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &s[unit_start..i];
        let unit_ns: u128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3600 * 1_000_000_000,
            _ => {
                return Err(format!(
                    "time: unknown unit {:?} in duration {:?}",
                    unit, orig
                ))
            }
        };

        let part_ns = int_val
            .checked_mul(unit_ns)
            .and_then(|v| v.checked_add((frac_val * unit_ns) / frac_scale))
            .ok_or_else(|| format!("time: duration overflow {:?}", orig))?;
        total_nanos = total_nanos
            .checked_add(part_ns)
            .ok_or_else(|| format!("time: duration overflow {:?}", orig))?;
    }

    let secs = (total_nanos / 1_000_000_000) as u64;
    let subsec_nanos = (total_nanos % 1_000_000_000) as u32;
    Ok(Duration::new(secs, subsec_nanos))
}

pub fn usage_text() -> &'static str {
    "\
Usage: opera-proxy [options]
  -api-address string
        override IP address of api2.sec-tunnel.com
  -api-client-type string
        client type reported to SurfEasy API (default \"se0316\")
  -api-client-version string
        client version reported to SurfEasy API (default \"Stable 114.0.5282.21\")
  -api-login string
        SurfEasy API login (default \"se0316\")
  -api-password string
        SurfEasy API password
  -api-proxy string
        additional proxy server used to access SurfEasy API
  -api-proxy-file string
        path to text file with candidate proxy servers for SurfEasy API access
  -api-proxy-list-url string
        URL of a text file with candidate proxy servers for SurfEasy API access
  -api-proxy-parallel int
        number of API proxy candidates tested in parallel (default 15)
  -api-user-agent string
        user agent reported to SurfEasy API
  -bind-address string
        proxy listen address (default \"127.0.0.1:18080\")
  -bootstrap-dns value
        comma-separated list of DNS/DoH/DoT/TCP resolvers for initial discovery
  -cafile string
        use custom CA certificate bundle file
  -config file
        read configuration from file with space-separated keys and values
  -country string
        desired proxy location (default \"EU\")
  -discover-csv string
        read proxy endpoints from CSV instead of SurfEasy discover API
  -discover-repeat int
        number of repeated discover requests to aggregate and deduplicate (default 1)
  -dp-export
        export configuration for dumbproxy
  -estimate-proxy-speed
        measure proxy response time for proxy list output
  -fake-SNI string
        domain name to use as SNI in outbound TLS
  -fetch-freeproxy-out string
        download proxy list from advanced.name/freeproxy and save to file
  -fetch-freeproxy-url string
        source URL for -fetch-freeproxy-out (default \"https://advanced.name/freeproxy\")
  -init-retries int
        number of attempts for initialization steps, zero for unlimited retry
  -init-retry-interval duration
        delay between initialization retries (default 5s)
  -list-countries
        list available countries and exit
  -list-proxies
        output proxy list and exit
  -list-proxies-all
        output proxy list for all countries and exit
  -list-proxies-all-out string
        write proxy list CSV to file
  -override-proxy-address string
        use fixed proxy address instead of server address returned by SurfEasy API
  -proxy string
        sets base proxy to use for all dial-outs (<http|https|socks5|socks5h>://...)
  -proxy-blacklist string
        path to file with blacklisted proxy addresses, one host[:port] per line
  -proxy-bypass value
        comma-separated list of destination host or URL patterns to bypass proxying
  -proxy-speed-dl-limit int
        limit of downloaded bytes for proxy speed measurement (default 262144)
  -proxy-speed-test-url string
        URL used to measure proxy response time
  -proxy-speed-timeout duration
        timeout for a single proxy speed measurement (default 15s)
  -refresh duration
        login refresh interval (default 4h0m0s)
  -refresh-retry duration
        login refresh retry interval (default 5s)
  -server-selection value
        server selection policy (first/random/fastest) (default fastest)
  -server-selection-dl-limit int
        restrict amount of downloaded data per connection by fastest server selection
  -server-selection-test-url string
        URL used for download benchmark by fastest server selection policy
  -server-selection-timeout duration
        timeout given for server selection function to produce result (default 1m0s)
  -socks-mode
        listen for SOCKS requests instead of HTTP
  -sort-proxies-by string
        proxy list sort order: speed, country, ip (default \"speed\")
  -timeout duration
        timeout for network operations (default 30s)
  -verbosity int
        logging verbosity (10 debug, 20 info, 30 warning, 40 error, 50 critical, 60 silent) (default 20)
  -version
        show program version and exit
"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_defaults() {
        let args = CliArgs::parse_from::<[&str; 0], &str>([]).unwrap();
        assert_eq!(args.country, "EU");
        assert!(!args.country_explicit);
        assert_eq!(args.bind_address, "127.0.0.1:18080");
        assert_eq!(args.timeout, Duration::from_secs(30));
        assert_eq!(args.server_selection, ServerSelection::Fastest);
        assert_eq!(args.server_selection_timeout, Duration::from_secs(60));
        assert_eq!(args.refresh, Duration::from_secs(4 * 3600));
        assert_eq!(args.verbosity, 20);
        assert_eq!(args.bootstrap_dns.len(), 9);
    }

    #[test]
    fn test_parse_openwrt_uci_args() {
        let a1 = CliArgs::parse_from(["-bind-address", "127.0.0.1:18081"]).unwrap();
        assert_eq!(a1.bind_address, "127.0.0.1:18081");
        assert!(!a1.socks_mode);

        let a2 = CliArgs::parse_from([
            "-bind-address",
            "127.0.0.1:18082",
            "-country",
            "AM",
            "-socks-mode",
        ])
        .unwrap();
        assert_eq!(a2.bind_address, "127.0.0.1:18082");
        assert_eq!(a2.country, "AM");
        assert!(a2.country_explicit);
        assert!(a2.socks_mode);

        let a3 = CliArgs::parse_from([
            "--bind-address=127.0.0.1:18083",
            "-country=AS",
            "-socks-mode=true",
            "-fake-SNI",
            "www.google.com",
        ])
        .unwrap();
        assert_eq!(a3.bind_address, "127.0.0.1:18083");
        assert_eq!(a3.country, "AS");
        assert!(a3.socks_mode);
        assert_eq!(a3.fake_sni, "www.google.com");
    }

    #[test]
    fn test_parse_go_durations() {
        assert_eq!(parse_go_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_go_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(
            parse_go_duration("4h0m0s").unwrap(),
            Duration::from_secs(14400)
        );
        assert_eq!(
            parse_go_duration("1m30.5s").unwrap(),
            Duration::from_millis(90_500)
        );
        assert_eq!(
            parse_go_duration("250ms").unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            parse_go_duration("100µs").unwrap(),
            Duration::from_micros(100)
        );
        assert!(parse_go_duration("bad").is_err());
        assert!(parse_go_duration("-5s").is_err());
    }

    #[test]
    fn test_mutually_exclusive_outputs() {
        assert!(CliArgs::parse_from(["-list-countries", "-list-proxies"]).is_err());
        assert!(CliArgs::parse_from(["-list-proxies", "-dp-export"]).is_err());
        assert!(CliArgs::parse_from(["-list-proxies-all-out", "out.csv", "-dp-export"]).is_err());
    }

    #[test]
    fn test_list_proxies_all_implies_speed() {
        let a = CliArgs::parse_from(["-list-proxies-all-out", "out.csv"]).unwrap();
        assert!(a.list_proxies_all);
        assert!(a.estimate_proxy_speed);
    }

    #[test]
    fn test_config_file_parsing() {
        let cfg = "# comment\ncountry AS\nsocks-mode\nbind-address 127.0.0.1:19090\napi-user-agent Custom Agent/1.0\n";
        let mut args = CliArgs::default();
        args.apply_config_reader(cfg.as_bytes(), "test.cfg")
            .unwrap();
        assert_eq!(args.country, "AS");
        assert!(args.socks_mode);
        assert_eq!(args.bind_address, "127.0.0.1:19090");
        assert_eq!(args.api_user_agent, "Custom Agent/1.0");
    }

    #[test]
    fn test_validation_errors() {
        assert!(CliArgs::parse_from(["-country", ""]).is_err());
        assert!(CliArgs::parse_from(["-discover-repeat", "0"]).is_err());
        assert!(CliArgs::parse_from(["-api-proxy-parallel", "0"]).is_err());
        assert!(CliArgs::parse_from(["-sort-proxies-by", "bogus"]).is_err());
        assert!(CliArgs::parse_from(["-server-selection", "bogus"]).is_err());
    }
}
