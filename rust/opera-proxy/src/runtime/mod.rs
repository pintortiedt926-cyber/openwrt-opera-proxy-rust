use std::fmt;
use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

pub const SILENT: i32 = 60;
pub const CRITICAL: i32 = 50;
pub const ERROR: i32 = 40;
pub const WARNING: i32 = 30;
pub const INFO: i32 = 20;
pub const DEBUG: i32 = 10;
pub const NOTSET: i32 = 0;

/// Lightweight conditional logger matching upstream Go CondLogger levels
/// (10 debug, 20 info, 30 warning, 40 error, 50 critical, >=60 silent).
#[derive(Clone)]
pub struct CondLogger {
    prefix: &'static str,
    verbosity: i32,
}

impl CondLogger {
    pub fn new(prefix: &'static str, verbosity: i32) -> Self {
        Self { prefix, verbosity }
    }

    pub fn is_silent(&self) -> bool {
        self.verbosity >= SILENT
    }

    pub fn verbosity(&self) -> i32 {
        self.verbosity
    }

    pub fn log(&self, level: i32, label: &str, args: fmt::Arguments<'_>) {
        if self.verbosity >= SILENT || level < self.verbosity {
            return;
        }
        let ts = format_utc_timestamp(SystemTime::now());
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}{} {} {}", self.prefix, ts, label, args);
    }

    pub fn critical(&self, args: fmt::Arguments<'_>) {
        self.log(CRITICAL, "CRITICAL", args);
    }

    pub fn error(&self, args: fmt::Arguments<'_>) {
        self.log(ERROR, "ERROR   ", args);
    }

    pub fn warning(&self, args: fmt::Arguments<'_>) {
        self.log(WARNING, "WARNING ", args);
    }

    pub fn info(&self, args: fmt::Arguments<'_>) {
        self.log(INFO, "INFO    ", args);
    }

    pub fn debug(&self, args: fmt::Arguments<'_>) {
        self.log(DEBUG, "DEBUG   ", args);
    }
}

/// Format SystemTime as `YYYY/MM/DD HH:MM:SS` (UTC) without pulling in chrono.
pub fn format_utc_timestamp(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Sleep until `wall_duration` has elapsed according to wall-clock (`SystemTime`),
/// polling every 1s (or sooner for short durations) so suspend/resume or NTP jumps
/// are detected within 1s, matching Go `clock.AfterWallClock`.
/// Returns `false` if cancelled via `shutdown`.
pub async fn sleep_wall_clock(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return false;
    }
    if duration.is_zero() {
        return true;
    }
    let deadline = SystemTime::now() + duration;
    let step = duration.min(Duration::from_secs(1));
    loop {
        let now = SystemTime::now();
        if now >= deadline {
            return true;
        }
        let remaining = deadline.duration_since(now).unwrap_or_default();
        let wait = remaining.min(step);
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return false;
                }
            }
        }
    }
}

/// Run an initialization action up to `retries` times (`retries <= 0` means unlimited),
/// waiting `retry_interval` between attempts and cancelling immediately on shutdown.
pub async fn retry_action<F, Fut, T, E>(
    name: &str,
    retries: i32,
    retry_interval: Duration,
    logger: &CondLogger,
    shutdown: &mut watch::Receiver<bool>,
    mut f: F,
) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: fmt::Display,
{
    let mut last_err = String::new();
    let mut attempt: i32 = 1;
    loop {
        if retries > 0 && attempt > retries {
            logger.critical(format_args!(
                "All attempts for action {:?} have failed. Last error: {}",
                name, last_err
            ));
            return Err(last_err);
        }
        if attempt > 1 {
            logger.warning(format_args!(
                "Retrying action {:?} in {:?}...",
                name, retry_interval
            ));
            tokio::select! {
                _ = tokio::time::sleep(retry_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return Err("retry cancelled: shutdown".to_string());
                    }
                }
            }
        }
        if *shutdown.borrow() {
            return Err("retry cancelled: shutdown".to_string());
        }
        logger.info(format_args!(
            "Attempting action {:?}, attempt #{}...",
            name, attempt
        ));
        match f().await {
            Ok(v) => {
                logger.info(format_args!(
                    "Action {:?} succeeded on attempt #{}",
                    name, attempt
                ));
                return Ok(v);
            }
            Err(e) => {
                last_err = e.to_string();
                logger.warning(format_args!("Action {:?} failed: {}", name, last_err));
            }
        }
        attempt = attempt.saturating_add(1);
    }
}

/// Spawn a wall-clock resilient background refresh task matching Go `clock.RunTicker`.
pub fn spawn_refresh_ticker<F, Fut>(
    interval: Duration,
    retry_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
    callback: Arc<F>,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut last_failed = false;
        loop {
            let next_wait = if last_failed {
                retry_interval
            } else {
                interval
            };
            if !sleep_wall_clock(next_wait, &mut shutdown).await {
                break;
            }
            last_failed = callback().await.is_err();
        }
    })
}

/// Wait for SIGINT or SIGTERM (on Unix) or Ctrl-C (on Windows).
pub async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(_) => None,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => "SIGTERM",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "SIGINT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_civil_from_days_epoch_and_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_262), (2020, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }

    #[test]
    fn test_logger_silent_flag() {
        assert!(!CondLogger::new("MAIN: ", INFO).is_silent());
        assert!(CondLogger::new("MAIN: ", SILENT).is_silent());
        assert!(CondLogger::new("MAIN: ", 100).is_silent());
    }

    #[tokio::test]
    async fn test_retry_action_succeeds_after_failures() {
        let (_tx, mut rx) = watch::channel(false);
        let logger = CondLogger::new("TEST: ", SILENT);
        let count = AtomicUsize::new(0);
        let res = retry_action("op", 3, Duration::from_millis(10), &logger, &mut rx, || {
            let c = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if c < 2 {
                    Err("transient")
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(res.unwrap(), 42);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_action_cancels_on_shutdown() {
        let (tx, mut rx) = watch::channel(false);
        let logger = CondLogger::new("TEST: ", SILENT);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let _ = tx.send(true);
        });
        let res: Result<(), String> = retry_action(
            "op",
            0,
            Duration::from_secs(60),
            &logger,
            &mut rx,
            || async { Err::<(), _>("always fails") },
        )
        .await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("cancelled"));
    }

    #[tokio::test]
    async fn test_sleep_wall_clock_cancels_immediately() {
        let (tx, mut rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(true);
        });
        let completed = sleep_wall_clock(Duration::from_secs(30), &mut rx).await;
        assert!(!completed);
    }
}
