//! repsheet-status-codes: a passive detector that blocks client addresses
//! producing too many error responses.
//!
//! Collectors (repsheet-collector) connect and send one event per request.
//! Every event whose status is in --statuses counts against its address; an
//! address that reaches --threshold within --window gets a Repsheet decision
//! (`REPSHEET.BLOCK <addr> REASON ... TTL ... BY status-codes`).

mod window;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use repsheet_event::{Event, StatusSet, parse_duration};
use tokio::io::AsyncBufReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    Block,
    Mark,
}

impl Action {
    fn command(self) -> &'static str {
        match self {
            Action::Block => "REPSHEET.BLOCK",
            Action::Mark => "REPSHEET.MARK",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Mark => "mark",
        }
    }
}

/// Block (or mark) addresses that produce too many error responses.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Where collectors connect.
    #[arg(
        long,
        env = "REPSHEET_STATUS_CODES_LISTEN",
        default_value = "127.0.0.1:7400"
    )]
    listen: SocketAddr,

    /// Valkey/Redis with the Repsheet module (the primary):
    /// redis://[user:password@]host:port[/db] or unix:///path/to/socket.
    #[arg(long, env = "REPSHEET_REDIS", default_value = "redis://127.0.0.1:6379")]
    redis: String,

    /// Responses from one address within --window that trigger a decision.
    #[arg(long, env = "REPSHEET_STATUS_CODES_THRESHOLD", default_value_t = 50)]
    threshold: u32,

    /// The window: seconds, or 30s / 5m / 1h.
    #[arg(long, env = "REPSHEET_STATUS_CODES_WINDOW", default_value = "60s", value_parser = parse_duration)]
    window: u64,

    /// The statuses that count: ranges and lists, e.g. 400-599 (the
    /// default), 404,429, or 100-199,201-599 for everything but 200.
    #[arg(long, env = "REPSHEET_STATUS_CODES_STATUSES", default_value = "400-599", value_parser = StatusSet::parse)]
    statuses: StatusSet,

    /// The decision to record.
    #[arg(long, env = "REPSHEET_STATUS_CODES_ACTION", value_enum, default_value_t = Action::Block)]
    action: Action,

    /// How long the decision lasts: seconds, or 30m / 1h / 1d.
    #[arg(long, env = "REPSHEET_STATUS_CODES_TTL", default_value = "1h", value_parser = parse_duration)]
    ttl: u64,

    /// The author recorded with each decision (BY).
    #[arg(
        long,
        env = "REPSHEET_STATUS_CODES_NAME",
        default_value = "status-codes"
    )]
    name: String,

    /// Buckets the window is divided into (precision of the sliding window).
    #[arg(long, default_value_t = 12)]
    buckets: usize,

    /// Most addresses tracked at once; beyond this new addresses are not
    /// counted until idle ones age out.
    #[arg(
        long,
        env = "REPSHEET_STATUS_CODES_MAX_TRACKED",
        default_value_t = 1_000_000
    )]
    max_tracked: usize,

    /// Prometheus metrics and /healthz.
    #[arg(
        long,
        env = "REPSHEET_STATUS_CODES_METRICS",
        default_value = "127.0.0.1:7401"
    )]
    metrics: SocketAddr,
}

#[derive(Default)]
struct Stats {
    events: AtomicU64,
    counted: AtomicU64,
    skipped_repsheet: AtomicU64,
    stale: AtomicU64,
    untracked: AtomicU64,
    parse_errors: AtomicU64,
    connections: AtomicU64,
    decisions: AtomicU64,
    decision_errors: AtomicU64,
    tracked: AtomicU64,
}

struct Decision {
    addr: String,
    count: u32,
}

struct Detector {
    statuses: StatusSet,
    windows: Mutex<window::Windows>,
    stats: Stats,
    decisions: mpsc::UnboundedSender<Decision>,
}

impl Detector {
    fn handle(&self, line: &str) {
        let event = match Event::parse(line) {
            Ok(e) => e,
            Err(_) => {
                self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        self.stats.events.fetch_add(1, Ordering::Relaxed);
        if !self.statuses.contains(event.status) {
            return;
        }
        // Requests Repsheet already blocked (its own 403s) or trusted do not
        // count: the first would re-block forever, the second must not block.
        if event.repsheet == "block" || event.repsheet == "allow" {
            self.stats.skipped_repsheet.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let outcome = self
            .windows
            .lock()
            .unwrap()
            .record(&event.addr, event.time_ms(), now_ms());
        match outcome {
            window::Outcome::Counted => {
                self.stats.counted.fetch_add(1, Ordering::Relaxed);
            }
            window::Outcome::Tripped(count) => {
                self.stats.counted.fetch_add(1, Ordering::Relaxed);
                let _ = self.decisions.send(Decision {
                    addr: event.addr,
                    count,
                });
            }
            window::Outcome::Stale => {
                self.stats.stale.fetch_add(1, Ordering::Relaxed);
            }
            window::Outcome::Untracked => {
                self.stats.untracked.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn serve_collector(detector: Arc<Detector>, stream: TcpStream, peer: SocketAddr) {
    detector.stats.connections.fetch_add(1, Ordering::Relaxed);
    tracing::info!("collector connected from {peer}");
    let mut lines = tokio::io::BufReader::new(stream).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => detector.handle(&line),
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("collector {peer}: {e}");
                break;
            }
        }
    }
    tracing::info!("collector {peer} disconnected");
    detector.stats.connections.fetch_sub(1, Ordering::Relaxed);
}

fn window_text(seconds: u64) -> String {
    match seconds {
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

async fn record_decisions(
    conn: ConnectionManager,
    args: Arc<Args>,
    detector: Arc<Detector>,
    mut rx: mpsc::UnboundedReceiver<Decision>,
) {
    while let Some(d) = rx.recv().await {
        let reason = format!(
            "{} responses with status {} in {}",
            d.count,
            args.statuses.as_str(),
            window_text(args.window)
        );
        let mut cmd = redis::cmd(args.action.command());
        cmd.arg(&d.addr)
            .arg("REASON")
            .arg(&reason)
            .arg("TTL")
            .arg(args.ttl)
            .arg("BY")
            .arg(&args.name);

        let mut ok = false;
        for attempt in 0..2 {
            let mut c = conn.clone();
            match cmd.query_async::<redis::Value>(&mut c).await {
                Ok(_) => {
                    ok = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        "{} {} failed (attempt {}): {e}",
                        args.action.command(),
                        d.addr,
                        attempt + 1
                    );
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        if ok {
            detector.stats.decisions.fetch_add(1, Ordering::Relaxed);
            tracing::info!("{} {}: {reason}", args.action.name(), d.addr);
        } else {
            detector
                .stats
                .decision_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn render(d: &Detector, action: Action) -> String {
    let s = &d.stats;
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, labels: &str, value: u64| {
        out.push_str(&format!(
            "# HELP repsheet_status_codes_{name} {help}\n# TYPE repsheet_status_codes_{name} {kind}\nrepsheet_status_codes_{name}{labels} {value}\n"
        ));
    };
    let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
    metric(
        "events_total",
        "counter",
        "Events received from collectors.",
        "",
        get(&s.events),
    );
    metric(
        "counted_total",
        "counter",
        "Events whose status counted against the address.",
        "",
        get(&s.counted),
    );
    metric(
        "skipped_total",
        "counter",
        "Matching events not counted because Repsheet already blocked or allowed the request.",
        "",
        get(&s.skipped_repsheet),
    );
    metric(
        "stale_total",
        "counter",
        "Events older than the window.",
        "",
        get(&s.stale),
    );
    metric(
        "untracked_total",
        "counter",
        "Events not counted because the address table was full.",
        "",
        get(&s.untracked),
    );
    metric(
        "parse_errors_total",
        "counter",
        "Lines from collectors that were not events.",
        "",
        get(&s.parse_errors),
    );
    metric(
        "decisions_total",
        "counter",
        "Decisions recorded.",
        &format!("{{action=\"{}\"}}", action.name()),
        get(&s.decisions),
    );
    metric(
        "decision_errors_total",
        "counter",
        "Decisions that could not be written.",
        "",
        get(&s.decision_errors),
    );
    metric(
        "collectors",
        "gauge",
        "Connected collectors.",
        "",
        get(&s.connections),
    );
    metric(
        "tracked_addresses",
        "gauge",
        "Addresses with events in the window.",
        "",
        get(&s.tracked),
    );
    out
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "repsheet_status_codes=info".into()),
        )
        .init();
    let args = Arc::new(Args::parse());

    let client = redis::Client::open(args.redis.as_str())?;
    let config = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(Duration::from_secs(2)))
        .set_response_timeout(Some(Duration::from_secs(5)))
        .set_max_delay(Duration::from_secs(5))
        .set_number_of_retries(1);
    let conn = client.get_connection_manager_lazy(config)?;

    let (tx, rx) = mpsc::unbounded_channel();
    let window_ms = (args.window as i64).saturating_mul(1000);
    let detector = Arc::new(Detector {
        statuses: args.statuses.clone(),
        windows: Mutex::new(window::Windows::new(
            window_ms,
            args.buckets,
            args.threshold,
            args.max_tracked,
        )),
        stats: Stats::default(),
        decisions: tx,
    });
    tokio::spawn(record_decisions(conn, args.clone(), detector.clone(), rx));

    // Forget idle addresses.
    {
        let detector = detector.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let mut w = detector.windows.lock().unwrap();
                w.evict(now_ms());
                detector
                    .stats
                    .tracked
                    .store(w.len() as u64, Ordering::Relaxed);
            }
        });
    }

    let metrics = TcpListener::bind(args.metrics).await?;
    {
        let (detector, action) = (detector.clone(), args.action);
        tokio::spawn(repsheet_event::serve_metrics(
            metrics,
            Arc::new(move || render(&detector, action)),
        ));
    }

    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!(
        "listening on {} for collectors: {} addresses after {} responses with status {} in {} (TTL {}s)",
        args.listen,
        args.action.name(),
        args.threshold,
        args.statuses.as_str(),
        window_text(args.window),
        args.ttl
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                if let Ok((stream, peer)) = accepted {
                    tokio::spawn(serve_collector(detector.clone(), stream, peer));
                }
            }
            _ = repsheet_event::shutdown_signal() => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_text_is_compact() {
        assert_eq!(window_text(60), "1m");
        assert_eq!(window_text(90), "90s");
        assert_eq!(window_text(7200), "2h");
        assert_eq!(window_text(86400), "1d");
    }
}
