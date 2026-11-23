#![forbid(unsafe_code)]

fn main() {
    // Use a single-threaded Tokio runtime with bounded blocking pool to minimize RSS on OpenWrt routers.
    let rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(4)
        .thread_keep_alive(std::time::Duration::from_secs(2))
        .enable_all()
        .build()
        .expect("failed to initialize tokio runtime");

    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = rt.block_on(opera_proxy::app::run_with_args(args));
    std::process::exit(code);
}
