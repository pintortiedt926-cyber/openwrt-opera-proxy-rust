use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use rustls::RootCertStore;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

use crate::cli::{
    usage_text, version, CliArgs, ParseError, DEFAULT_DISCOVER_CSV_FALLBACK,
    DEFAULT_PROXY_BYPASS_FALLBACK,
};
use crate::dialer::{
    basic_auth_header, load_proxy_blacklist, load_proxy_bypass_list, probe_dialer,
    proxy_dialer_from_url, sanitize_fixed_proxy_address, select_server, AuthCallback, BypassDialer,
    ContextDialer, DirectDialer, FixedDialer, HttpProxyDialer, ResolvingDialer,
};
use crate::handler::{serve_http_listener, serve_socks5_listener};
use crate::resolver::{build_root_store, format_host_port, FastResolver};
use crate::runtime::{retry_action, spawn_refresh_ticker, wait_for_shutdown_signal, CondLogger};
use crate::seclient::{
    append_unique_proxies, count_proxy_ports, emit_country_csv, emit_dp_export, emit_proxy_csv,
    emit_proxy_list_stdout, fetch_freeproxy_to_file, filter_blacklisted_proxy_entries,
    is_discover_801, load_api_proxy_list, load_api_proxy_list_from_url,
    load_proxy_entries_from_csv, normalize_api_proxy, parse_country_filters, proxy_endpoint_addrs,
    proxy_tls_server_name, sort_proxy_entries, ProxyEndpointKey, ProxySpeedResult, SeClient,
    SeGeoEntry, SeIpEntry, SeSettings,
};

const BENCH_WORKERS: usize = 8;

/// Run the full opera-proxy CLI application with custom raw args (excluding argv[0]).
pub async fn run_with_args<I, S>(raw_args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = match CliArgs::parse_from(raw_args) {
        Ok(a) => a,
        Err(ParseError::HelpRequested) => {
            eprint!("{}", usage_text());
            return 0;
        }
        Err(ParseError::Invalid(msg)) => {
            eprintln!("\n{}", msg);
            eprintln!("\n{}", usage_text());
            return 2;
        }
    };

    if args.show_version {
        println!("{}", version());
        return 0;
    }

    if !args.fetch_freeproxy_out.is_empty() {
        let roots = match build_root_store(&args.ca_file) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("failed to fetch free proxy list: {}", e);
                return 19;
            }
        };
        let direct: Arc<dyn ContextDialer> = Arc::new(DirectDialer::default());
        match fetch_freeproxy_to_file(
            &args.fetch_freeproxy_url,
            &args.fetch_freeproxy_out,
            direct,
            roots,
            args.timeout,
        )
        .await
        {
            Ok(count) => {
                println!("Saved {} proxies to {}", count, args.fetch_freeproxy_out);
                return 0;
            }
            Err(e) => {
                eprintln!("failed to fetch free proxy list: {}", e);
                return 19;
            }
        }
    }

    let main_logger = CondLogger::new("MAIN    : ", args.verbosity);
    let proxy_logger = CondLogger::new("PROXY   : ", args.verbosity);
    let socks_logger = CondLogger::new("SOCKS   : ", args.verbosity);

    main_logger.info(format_args!(
        "opera-proxy client version {} is starting...",
        version()
    ));

    let blacklist = match load_proxy_blacklist(&args.proxy_blacklist_file) {
        Ok(b) => b,
        Err(e) => {
            main_logger.error(format_args!(
                "Can't load proxy blacklist file {:?}: {}",
                args.proxy_blacklist_file, e
            ));
            return 18;
        }
    };
    if !blacklist.is_empty() {
        main_logger.info(format_args!(
            "Loaded {} blacklisted proxy endpoints from {}.",
            blacklist.len(),
            args.proxy_blacklist_file
        ));
    }

    let roots = match build_root_store(&args.ca_file) {
        Ok(r) => r,
        Err(e) => {
            main_logger.error(format_args!("{}", e));
            return 15;
        }
    };

    let direct_dialer: Arc<dyn ContextDialer> = Arc::new(DirectDialer::default());
    let mut base_dialer = direct_dialer.clone();
    if !args.proxy.is_empty() {
        if url::Url::parse(&args.proxy).is_err() {
            main_logger.critical(format_args!(
                "Unable to parse base proxy URL: {:?}",
                args.proxy
            ));
            return 6;
        }
        match proxy_dialer_from_url(&args.proxy, roots.clone(), base_dialer) {
            Ok(d) => base_dialer = d,
            Err(e) => {
                main_logger.critical(format_args!(
                    "Unable to instantiate base proxy dialer: {}",
                    e
                ));
                return 7;
            }
        }
    }

    if args.proxy_bypass.is_empty() {
        match load_proxy_bypass_list(Path::new(DEFAULT_PROXY_BYPASS_FALLBACK)) {
            Ok(patterns) => args.proxy_bypass = patterns,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                main_logger.critical(format_args!("Unable to load proxy bypass list: {}", e));
                return 7;
            }
        }
    }
    main_logger.info(format_args!(
        "Proxy bypass loaded: {} rule(s).",
        args.proxy_bypass.len()
    ));

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _sig = wait_for_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });

    if !args.api_address.is_empty() {
        main_logger.info(format_args!(
            "Using fixed API host address = {}",
            args.api_address
        ));
    }

    let mut preloaded_ips: Option<Vec<SeIpEntry>> = None;
    let seclient: Arc<SeClient>;

    if !args.api_proxy_list_url.is_empty() || !args.api_proxy_file.is_empty() {
        let mut candidates = Vec::new();
        if !args.api_proxy_list_url.is_empty() {
            match load_api_proxy_list_from_url(
                &args.api_proxy_list_url,
                base_dialer.clone(),
                roots.clone(),
                args.timeout,
            )
            .await
            {
                Ok(list) => candidates = list,
                Err(e) => {
                    if args.api_proxy_file.is_empty() {
                        main_logger.critical(format_args!(
                            "Unable to load API proxy list from URL: {}",
                            e
                        ));
                        return 8;
                    }
                    main_logger.warning(format_args!(
                        "Unable to load API proxy list from URL {:?}, falling back to file {:?}: {}",
                        args.api_proxy_list_url, args.api_proxy_file, e
                    ));
                }
            }
        }
        if candidates.is_empty() {
            match load_api_proxy_list(&args.api_proxy_file) {
                Ok(list) => candidates = list,
                Err(e) => {
                    main_logger.critical(format_args!("Unable to load API proxy list: {}", e));
                    return 8;
                }
            }
        }
        if !args.api_proxy.is_empty() {
            let explicit = match normalize_api_proxy(&args.api_proxy) {
                Ok(v) => v,
                Err(e) => {
                    main_logger.critical(format_args!("Unable to parse explicit API proxy: {}", e));
                    return 6;
                }
            };
            let mut filtered = Vec::with_capacity(candidates.len() + 1);
            filtered.push(explicit.clone());
            for c in candidates {
                if c != explicit {
                    filtered.push(c);
                }
            }
            candidates = filtered;
        }

        let parallelism = (args.api_proxy_parallel as usize)
            .min(candidates.len())
            .max(1);
        main_logger.info(format_args!(
            "Loaded {} API proxy candidates. Testing up to {} in parallel.",
            candidates.len(),
            parallelism
        ));

        let need_discover = args.list_proxies
            || args.list_proxies_all
            || args.dp_export
            || args.override_proxy_address.is_empty();

        match select_api_proxy_candidate(
            &args,
            base_dialer.clone(),
            roots.clone(),
            &blacklist,
            &main_logger,
            &candidates,
            need_discover,
            args.list_countries,
            shutdown_rx.clone(),
        )
        .await
        {
            Ok(winner) => {
                args.api_proxy = winner.candidate;
                if args.list_countries {
                    let stdout = io::stdout();
                    if let Err(e) = emit_country_csv(stdout.lock(), &winner.countries) {
                        eprintln!("failed to write country list: {}", e);
                        return 1;
                    }
                    return 0;
                }
                if !winner.ips.is_empty() {
                    preloaded_ips = Some(winner.ips);
                }
                seclient = winner.client;
            }
            Err(e) => {
                main_logger.critical(format_args!(
                    "All API proxy candidates failed. Last error: {}",
                    e
                ));
                return 12;
            }
        }
    } else {
        let api_client =
            match build_se_client(&args, base_dialer.clone(), roots.clone(), &args.api_proxy) {
                Ok(c) => Arc::new(c),
                Err((code, msg)) => {
                    main_logger.critical(format_args!("{}", msg));
                    return code;
                }
            };

        let c_reg = api_client.clone();
        let timeout = args.timeout;
        if retry_action(
            "anonymous registration",
            args.init_retries,
            args.init_retry_interval,
            &main_logger,
            &mut shutdown_rx,
            || {
                let c = c_reg.clone();
                async move { c.anon_register(timeout).await }
            },
        )
        .await
        .is_err()
        {
            return 9;
        }

        let c_dev = api_client.clone();
        if retry_action(
            "device registration",
            args.init_retries,
            args.init_retry_interval,
            &main_logger,
            &mut shutdown_rx,
            || {
                let c = c_dev.clone();
                async move { c.register_device(timeout).await }
            },
        )
        .await
        .is_err()
        {
            return 10;
        }

        if args.list_countries {
            let c_geo = api_client.clone();
            let list = match retry_action(
                "geolist",
                args.init_retries,
                args.init_retry_interval,
                &main_logger,
                &mut shutdown_rx,
                || {
                    let c = c_geo.clone();
                    async move { c.geo_list(timeout).await }
                },
            )
            .await
            {
                Ok(l) => l,
                Err(_) => return 11,
            };
            let stdout = io::stdout();
            if let Err(e) = emit_country_csv(stdout.lock(), &list) {
                eprintln!("failed to write country list: {}", e);
                return 1;
            }
            return 0;
        }

        seclient = api_client;
    }

    let make_handler_dialer =
        |entry: &SeIpEntry, endpoint_addr: String| -> Arc<dyn ContextDialer> {
            let se_for_auth = seclient.clone();
            let auth_cb: AuthCallback = Arc::new(move || {
                let (login, pass) = se_for_auth.get_proxy_credentials();
                Ok(basic_auth_header(&login, &pass))
            });
            Arc::new(HttpProxyDialer::new(
                endpoint_addr,
                proxy_tls_server_name(entry),
                args.fake_sni.clone(),
                Some(auth_cb),
                roots.clone(),
                base_dialer.clone(),
            ))
        };

    if args.list_proxies || args.list_proxies_all || args.dp_export {
        let ips = if let Some(ips) = preloaded_ips.take() {
            ips
        } else {
            let args_ref = &args;
            let se_ref = &seclient;
            let bl_ref = &blacklist;
            let log_ref = &main_logger;
            match retry_action(
                "discover",
                args.init_retries,
                args.init_retry_interval,
                &main_logger,
                &mut shutdown_rx,
                || async move {
                    let res = if args_ref.list_proxies_all {
                        discover_all_countries(args_ref, se_ref, bl_ref, Some(log_ref)).await?
                    } else {
                        discover_country(args_ref, se_ref, bl_ref, Some(log_ref), &args_ref.country)
                            .await?
                    };
                    if res.is_empty() {
                        return Err("empty endpoints list!".to_string());
                    }
                    Ok(res)
                },
            )
            .await
            {
                Ok(v) => v,
                Err(_) => return 12,
            }
        };

        if args.list_proxies || args.list_proxies_all {
            let speed_results = if args.estimate_proxy_speed {
                main_logger.info(format_args!(
                    "Measuring proxy response time for {} endpoints using {:?}.",
                    count_proxy_ports(&ips),
                    args.proxy_speed_test_url
                ));
                Some(
                    benchmark_proxy_endpoints(
                        &args,
                        &ips,
                        &seclient,
                        base_dialer.clone(),
                        roots.clone(),
                        &main_logger,
                    )
                    .await,
                )
            } else {
                None
            };

            if !args.list_proxies_all_out.is_empty() {
                let file = match File::create(&args.list_proxies_all_out) {
                    Ok(f) => f,
                    Err(e) => {
                        main_logger.critical(format_args!("Unable to write proxy CSV: {}", e));
                        return 17;
                    }
                };
                if let Err(e) =
                    emit_proxy_csv(file, &ips, speed_results.as_ref(), &args.sort_proxies_by)
                {
                    main_logger.critical(format_args!("Unable to write proxy CSV: {}", e));
                    return 17;
                }
                println!("Proxy list saved to {}", args.list_proxies_all_out);
                return 0;
            }

            let (login, pass) = seclient.get_proxy_credentials();
            let stdout = io::stdout();
            if let Err(e) = emit_proxy_list_stdout(
                stdout.lock(),
                &ips,
                &login,
                &pass,
                speed_results.as_ref(),
                &args.sort_proxies_by,
            ) {
                eprintln!("failed to write proxy CSV: {}", e);
                return 1;
            }
            return 0;
        }

        if args.dp_export {
            let (login, pass) = seclient.get_proxy_credentials();
            let stdout = io::stdout();
            if let Err(e) = emit_dp_export(stdout.lock(), &ips, &login, &pass, &args.fake_sni) {
                eprintln!("failed to write dp-export: {}", e);
                return 1;
            }
            return 0;
        }
    }

    let mut handler_dialer: Arc<dyn ContextDialer> = if args.override_proxy_address.is_empty() {
        let ips = if let Some(ips) = preloaded_ips.take() {
            ips
        } else {
            let args_ref = &args;
            let se_ref = &seclient;
            let bl_ref = &blacklist;
            let log_ref = &main_logger;
            match retry_action(
                "discover",
                args.init_retries,
                args.init_retry_interval,
                &main_logger,
                &mut shutdown_rx,
                || async move {
                    let res = discover_country(
                        args_ref,
                        se_ref,
                        bl_ref,
                        Some(log_ref),
                        &args_ref.country,
                    )
                    .await?;
                    if res.is_empty() {
                        return Err("empty endpoints list!".to_string());
                    }
                    Ok(res)
                },
            )
            .await
            {
                Ok(v) => v,
                Err(_) => return 12,
            }
        };

        main_logger.info(format_args!(
            "Discovered endpoints: {:?}. Starting server selection routine {:?}.",
            proxy_endpoint_addrs(&ips),
            args.server_selection.as_str()
        ));

        let dialers: Vec<Arc<dyn ContextDialer>> = ips
            .iter()
            .map(|ep| make_handler_dialer(ep, ep.net_addr()))
            .collect();

        match select_server(
            args.server_selection,
            dialers,
            &args.server_selection_test_url,
            args.server_selection_dl_limit,
            roots.clone(),
            args.server_selection_timeout,
        )
        .await
        {
            Ok(chosen) => {
                if let Some(addr) = chosen.endpoint_address() {
                    main_logger.info(format_args!("Selected endpoint address: {}", addr));
                }
                chosen
            }
            Err(e) => {
                main_logger.critical(format_args!("Server selection failed: {}", e));
                return 12;
            }
        }
    } else {
        let sanitized = sanitize_fixed_proxy_address(&args.override_proxy_address);
        if blacklist.contains(&sanitized) {
            main_logger.critical(format_args!(
                "Endpoint override {} is blacklisted.",
                sanitized
            ));
            return 12;
        }
        let dummy = SeIpEntry {
            geo: SeGeoEntry {
                country: String::new(),
                country_code: args.country.clone(),
            },
            host: String::new(),
            ip: String::new(),
            ports: Vec::new(),
        };
        main_logger.info(format_args!("Endpoint override: {}", sanitized));
        make_handler_dialer(&dummy, sanitized)
    };

    if !args.proxy_bypass.is_empty() {
        match BypassDialer::new(&args.proxy_bypass, direct_dialer, handler_dialer) {
            Ok(b) => handler_dialer = Arc::new(b),
            Err(e) => {
                main_logger.critical(format_args!(
                    "Unable to configure proxy bypass rules: {}",
                    e
                ));
                return 7;
            }
        }
    }

    // Background wall-clock credential refresh ticker
    let refresh_se = seclient.clone();
    let refresh_log = main_logger.clone();
    let refresh_timeout = args.timeout;
    let refresh_handle = spawn_refresh_ticker(
        args.refresh,
        args.refresh_retry,
        shutdown_rx.clone(),
        Arc::new(move || {
            let se = refresh_se.clone();
            let log = refresh_log.clone();
            async move {
                log.info(format_args!("Refreshing login..."));
                if let Err(e) = se.login(refresh_timeout).await {
                    log.error(format_args!("Login refresh failed: {}", e));
                    return Err(e);
                }
                log.info(format_args!("Login refreshed."));
                log.info(format_args!("Refreshing device password..."));
                if let Err(e) = se.device_generate_password(refresh_timeout).await {
                    log.error(format_args!("Device password refresh failed: {}", e));
                    return Err(e);
                }
                log.info(format_args!("Device password refreshed."));
                Ok(())
            }
        }),
    );

    main_logger.info(format_args!("Starting proxy server..."));
    let listener = match TcpListener::bind(&args.bind_address).await {
        Ok(l) => l,
        Err(e) => {
            main_logger.critical(format_args!("Server terminated with a fatal error: {}", e));
            let _ = shutdown_tx.send(true);
            refresh_handle.abort();
            return 0;
        }
    };
    main_logger.info(format_args!("Init complete."));

    let serve_res = if args.socks_mode {
        serve_socks5_listener(listener, handler_dialer, socks_logger, shutdown_rx.clone()).await
    } else {
        serve_http_listener(
            listener,
            handler_dialer,
            roots,
            proxy_logger,
            shutdown_rx.clone(),
        )
        .await
    };

    if let Err(e) = serve_res {
        main_logger.critical(format_args!("Server terminated with a fatal error: {}", e));
    } else if *shutdown_rx.borrow() {
        main_logger.info(format_args!("Server terminated by signal."));
    }

    let _ = shutdown_tx.send(true);
    refresh_handle.abort();
    main_logger.info(format_args!("Shutting down..."));
    0
}

fn build_se_client(
    args: &CliArgs,
    base_dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    api_proxy: &str,
) -> Result<SeClient, (i32, String)> {
    let mut se_dialer = base_dialer;
    if !api_proxy.is_empty() {
        if url::Url::parse(api_proxy).is_err() {
            return Err((6, format!("Unable to parse api-proxy URL: {:?}", api_proxy)));
        }
        se_dialer = proxy_dialer_from_url(api_proxy, roots.clone(), se_dialer)
            .map_err(|e| (7, format!("Unable to instantiate api-proxy dialer: {}", e)))?;
    }
    if !args.api_address.is_empty() {
        se_dialer = Arc::new(FixedDialer::new(args.api_address.clone(), se_dialer));
    } else if !args.bootstrap_dns.is_empty() {
        let res = FastResolver::from_urls(roots.clone(), &args.bootstrap_dns)
            .map_err(|e| (4, format!("Unable to instantiate DNS resolver: {}", e)))?;
        se_dialer = Arc::new(ResolvingDialer::new(Arc::new(res), se_dialer));
    }

    let settings = SeSettings {
        client_version: args.api_client_version.clone(),
        client_type: args.api_client_type.clone(),
        user_agent: args.api_user_agent.clone(),
        ..SeSettings::default()
    };

    SeClient::new(
        args.api_login.clone(),
        args.api_password.clone(),
        settings,
        se_dialer,
        roots,
        args.fake_sni.clone(),
    )
    .map_err(|e| (8, format!("Unable to construct SEClient: {}", e)))
}

async fn discover_country(
    args: &CliArgs,
    seclient: &SeClient,
    blacklist: &HashSet<String>,
    logger: Option<&CondLogger>,
    country_code: &str,
) -> Result<Vec<SeIpEntry>, String> {
    if !args.discover_csv.is_empty() {
        return load_proxy_entries_from_csv(
            Path::new(&args.discover_csv),
            country_code,
            false,
            args.country_explicit,
            blacklist,
        );
    }

    let mut seen = HashSet::new();
    let mut aggregated = Vec::new();
    let requested_geo = format!("\"{}\",,", country_code);

    for attempt in 1..=args.discover_repeat {
        match seclient.discover(&requested_geo, args.timeout).await {
            Ok(res) => {
                if let Some(log) = logger {
                    log.info(format_args!(
                        "Discover for country {} returned {} endpoints on pass #{}: {:?}",
                        country_code,
                        res.len(),
                        attempt,
                        proxy_endpoint_addrs(&res)
                    ));
                }
                let (filtered, blocked) = filter_blacklisted_proxy_entries(res, blacklist);
                if let (Some(log), false) = (logger, blocked.is_empty()) {
                    log.info(format_args!(
                        "Discover for country {} skipped {} blacklisted endpoints on pass #{}: {:?}",
                        country_code,
                        blocked.len(),
                        attempt,
                        blocked
                    ));
                }
                append_unique_proxies(&mut aggregated, filtered, &mut seen);
            }
            Err(e) => {
                if is_discover_801(&e) {
                    let fallback = if !args.discover_csv.is_empty() {
                        args.discover_csv.as_str()
                    } else {
                        DEFAULT_DISCOVER_CSV_FALLBACK
                    };
                    if let Some(log) = logger {
                        log.warning(format_args!(
                            "Discover API returned 801 for country {}, falling back to CSV {:?}.",
                            country_code, fallback
                        ));
                    }
                    return load_proxy_entries_from_csv(
                        Path::new(fallback),
                        country_code,
                        false,
                        args.country_explicit,
                        blacklist,
                    )
                    .map_err(|csv_err| {
                        format!(
                            "discover API returned 801 and CSV fallback {:?} failed: {}",
                            fallback, csv_err
                        )
                    });
                }
                return Err(e);
            }
        }
    }
    sort_proxy_entries(&mut aggregated);
    Ok(aggregated)
}

async fn discover_all_countries(
    args: &CliArgs,
    seclient: &SeClient,
    blacklist: &HashSet<String>,
    logger: Option<&CondLogger>,
) -> Result<Vec<SeIpEntry>, String> {
    if !args.discover_csv.is_empty() {
        return load_proxy_entries_from_csv(
            Path::new(&args.discover_csv),
            &args.country,
            true,
            args.country_explicit,
            blacklist,
        );
    }

    let countries = seclient.geo_list(args.timeout).await?;
    let (filters, mut all_countries) = parse_country_filters(&args.country);
    if !args.country_explicit {
        all_countries = true;
    }
    let allowed: HashSet<String> = filters.into_iter().collect();

    let mut all = Vec::new();
    let mut seen = HashSet::new();
    for c in countries {
        if !all_countries && !allowed.contains(&c.country_code.to_ascii_uppercase()) {
            continue;
        }
        let res = discover_country(args, seclient, blacklist, logger, &c.country_code)
            .await
            .map_err(|e| format!("discover failed for country {}: {}", c.country_code, e))?;
        append_unique_proxies(&mut all, res, &mut seen);
    }
    if all.is_empty() && !all_countries {
        return Err(format!("no countries matched filter {:?}", args.country));
    }
    sort_proxy_entries(&mut all);
    Ok(all)
}

struct ApiProxyWinner {
    candidate: String,
    client: Arc<SeClient>,
    ips: Vec<SeIpEntry>,
    countries: Vec<SeGeoEntry>,
}

#[allow(clippy::too_many_arguments)]
async fn select_api_proxy_candidate(
    args: &CliArgs,
    base_dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    blacklist: &HashSet<String>,
    logger: &CondLogger,
    candidates: &[String],
    need_discover: bool,
    need_countries: bool,
    mut shutdown: watch::Receiver<bool>,
) -> Result<ApiProxyWinner, String> {
    if candidates.is_empty() {
        return Err("no API proxy candidates provided".to_string());
    }
    let parallelism = (args.api_proxy_parallel as usize)
        .min(candidates.len())
        .max(1);
    let sem = Arc::new(Semaphore::new(parallelism));
    let mut set = tokio::task::JoinSet::new();

    for (idx, candidate) in candidates.iter().enumerate() {
        let permit_sem = sem.clone();
        let args_c = args.clone();
        let base_c = base_dialer.clone();
        let roots_c = roots.clone();
        let bl_c = blacklist.clone();
        let log_c = logger.clone();
        let cand_c = candidate.clone();
        let total = candidates.len();

        set.spawn(async move {
            let _permit = permit_sem
                .acquire_owned()
                .await
                .map_err(|e| e.to_string())?;
            log_c.info(format_args!(
                "Trying API proxy candidate #{}/{}: {}",
                idx + 1,
                total,
                cand_c
            ));

            let client =
                build_se_client(&args_c, base_c, roots_c, &cand_c).map_err(|(_, msg)| msg)?;
            let client = Arc::new(client);

            client
                .anon_register(args_c.timeout)
                .await
                .map_err(|e| format!("anonymous registration failed: {}", e))?;
            client
                .register_device(args_c.timeout)
                .await
                .map_err(|e| format!("device registration failed: {}", e))?;

            let countries = if need_countries {
                client
                    .geo_list(args_c.timeout)
                    .await
                    .map_err(|e| format!("geo list request failed: {}", e))?
            } else {
                Vec::new()
            };

            let ips = if need_discover {
                let list = if args_c.list_proxies_all {
                    discover_all_countries(&args_c, &client, &bl_c, None).await
                } else {
                    discover_country(&args_c, &client, &bl_c, None, &args_c.country).await
                }
                .map_err(|e| format!("discover request failed: {}", e))?;
                if list.is_empty() {
                    return Err("discover request returned an empty endpoints list".to_string());
                }
                list
            } else {
                Vec::new()
            };

            Ok::<ApiProxyWinner, String>(ApiProxyWinner {
                candidate: cand_c,
                client,
                ips,
                countries,
            })
        });
    }

    let mut last_err = "all API proxy candidates failed".to_string();
    loop {
        tokio::select! {
            joined = set.join_next() => {
                match joined {
                    Some(Ok(Ok(winner))) => {
                        logger.info(format_args!("Using API proxy candidate: {}", winner.candidate));
                        set.abort_all();
                        return Ok(winner);
                    }
                    Some(Ok(Err(e))) => {
                        logger.warning(format_args!("API proxy candidate failed: {}", e));
                        last_err = e;
                    }
                    Some(Err(e)) => {
                        last_err = format!("candidate task error: {}", e);
                    }
                    None => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    set.abort_all();
                    return Err("API proxy candidate selection cancelled".to_string());
                }
            }
        }
    }
    Err(last_err)
}

async fn benchmark_proxy_endpoints(
    args: &CliArgs,
    ips: &[SeIpEntry],
    seclient: &Arc<SeClient>,
    base_dialer: Arc<dyn ContextDialer>,
    roots: Arc<RootCertStore>,
    logger: &CondLogger,
) -> HashMap<ProxyEndpointKey, ProxySpeedResult> {
    let sem = Arc::new(Semaphore::new(BENCH_WORKERS));
    let mut set = tokio::task::JoinSet::new();

    for entry in ips {
        let ports: Vec<u16> = if entry.ports.is_empty() {
            vec![443]
        } else {
            entry.ports.clone()
        };
        for port in ports {
            let key = ProxyEndpointKey {
                country_code: entry.geo.country_code.clone(),
                ip: entry.ip.clone(),
                port,
            };
            let endpoint = format_host_port(&entry.ip, port);
            let tls_name = proxy_tls_server_name(entry);
            let fake_sni = args.fake_sni.clone();
            let se = seclient.clone();
            let base = base_dialer.clone();
            let r = roots.clone();
            let url = args.proxy_speed_test_url.clone();
            let dl_limit = args.proxy_speed_dl_limit;
            let timeout = args.proxy_speed_timeout;
            let sem_c = sem.clone();
            let log_c = logger.clone();
            let cc = entry.geo.country_code.clone();

            set.spawn(async move {
                let _permit = sem_c.acquire_owned().await.ok();
                let auth_cb: AuthCallback = Arc::new(move || {
                    let (login, pass) = se.get_proxy_credentials();
                    Ok(basic_auth_header(&login, &pass))
                });
                let dialer: Arc<dyn ContextDialer> = Arc::new(HttpProxyDialer::new(
                    endpoint.clone(),
                    tls_name,
                    fake_sni,
                    Some(auth_cb),
                    r.clone(),
                    base,
                ));
                let start = Instant::now();
                let res = probe_dialer(dialer, &url, dl_limit, r, timeout).await;
                let elapsed = start.elapsed();
                match &res {
                    Ok(()) => {
                        log_c.info(format_args!(
                            "Speed probe for {} via {} completed in {} ms.",
                            cc,
                            endpoint,
                            elapsed.as_millis()
                        ));
                    }
                    Err(e) => {
                        log_c.warning(format_args!(
                            "Speed probe for {} via {} failed: {}",
                            cc, endpoint, e
                        ));
                    }
                }
                (
                    key,
                    ProxySpeedResult {
                        duration: elapsed,
                        err: res.err(),
                    },
                )
            });
        }
    }

    let mut out = HashMap::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((key, res)) = joined {
            out.insert(key, res);
        }
    }
    out
}
