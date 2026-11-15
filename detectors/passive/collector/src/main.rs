//! repsheet-collector: follows nginx's JSON access log and forwards each
//! request, as an event, to one or more passive detectors.
//!
//! Run one next to every nginx. It reads only new lines (unless
//! --from-start), follows log rotation, and keeps a bounded queue per
//! analyzer so a restarting analyzer misses nothing unless the queue fills.

mod tail;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use repsheet_event::Event;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

/// Forward nginx's JSON access log to Repsheet passive detectors.
///
/// nginx needs a second access log in the repsheet_events format (see
/// `repsheet-collector --print-log-format`).
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// The access log written with the repsheet_events format.
    #[arg(
        long,
        env = "REPSHEET_COLLECTOR_FILE",
        required_unless_present = "print_log_format"
    )]
    file: Option<PathBuf>,

    /// An analyzer to send events to, host:port. Repeat for several.
    #[arg(
        long = "forward",
        env = "REPSHEET_COLLECTOR_FORWARD",
        value_delimiter = ',',
        required_unless_present = "print_log_format"
    )]
    forward: Vec<String>,

    /// Events held per analyzer while it is unreachable; the oldest are
    /// dropped beyond this.
    #[arg(long, env = "REPSHEET_COLLECTOR_QUEUE", default_value_t = 100_000)]
    queue: usize,

    /// Prometheus metrics and /healthz.
    #[arg(
        long,
        env = "REPSHEET_COLLECTOR_METRICS",
        default_value = "127.0.0.1:7402"
    )]
    metrics: SocketAddr,

    /// Read the lines already in the file too (default: only new ones).
    #[arg(long)]
    from_start: bool,

    /// How often to check the file for new lines, in milliseconds.
    #[arg(long, default_value_t = 250)]
    poll_ms: u64,

    /// Print the nginx log_format to use, and exit.
    #[arg(long)]
    print_log_format: bool,
}

/// Events waiting for one analyzer.
struct Queue {
    analyzer: String,
    lines: Mutex<VecDeque<String>>,
    notify: Notify,
    cap: usize,
    forwarded: AtomicU64,
    dropped: AtomicU64,
    connected: AtomicBool,
}

impl Queue {
    fn push(&self, line: String) {
        let mut q = self.lines.lock().unwrap();
        if q.len() >= self.cap {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(line);
        drop(q);
        self.notify.notify_one();
    }

    fn take(&self, max: usize) -> Vec<String> {
        let mut q = self.lines.lock().unwrap();
        let n = q.len().min(max);
        q.drain(..n).collect()
    }

    /// Put back a batch that could not be sent (at least once delivery).
    fn put_back(&self, batch: Vec<String>) {
        let mut q = self.lines.lock().unwrap();
        for line in batch.into_iter().rev() {
            if q.len() >= self.cap {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            q.push_front(line);
        }
    }

    fn len(&self) -> usize {
        self.lines.lock().unwrap().len()
    }
}

#[derive(Default)]
struct Stats {
    lines: AtomicU64,
    parse_errors: AtomicU64,
    rotations: AtomicU64,
}

async fn forward(queue: Arc<Queue>) {
    let mut backoff = Duration::from_millis(250);
    loop {
        let mut stream = match TcpStream::connect(&queue.analyzer).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("cannot reach {}: {e}", queue.analyzer);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        tracing::info!("connected to analyzer {}", queue.analyzer);
        queue.connected.store(true, Ordering::Relaxed);
        backoff = Duration::from_millis(250);

        loop {
            // The analyzer never sends anything, so a readable socket means
            // it closed (EOF) or failed. Checking before each write keeps a
            // batch from vanishing into the buffer of a dead connection.
            if peer_closed(&stream) {
                tracing::warn!("analyzer {} closed the connection", queue.analyzer);
                break;
            }
            let batch = queue.take(1000);
            if batch.is_empty() {
                let mut probe = [0u8; 1];
                tokio::select! {
                    _ = queue.notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    r = stream.read(&mut probe) => {
                        if matches!(r, Ok(0) | Err(_)) {
                            tracing::warn!("analyzer {} closed the connection", queue.analyzer);
                            break;
                        }
                    }
                }
                continue;
            }
            let mut buf = String::with_capacity(batch.iter().map(|l| l.len() + 1).sum());
            for line in &batch {
                buf.push_str(line);
                buf.push('\n');
            }
            match stream.write_all(buf.as_bytes()).await {
                Ok(()) => {
                    queue
                        .forwarded
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!("lost analyzer {}: {e}", queue.analyzer);
                    queue.put_back(batch);
                    break;
                }
            }
        }
        queue.connected.store(false, Ordering::Relaxed);
    }
}

/// True if the analyzer closed its end (or the socket failed).
fn peer_closed(stream: &TcpStream) -> bool {
    let mut probe = [0u8; 1];
    match stream.try_read(&mut probe) {
        Ok(0) => true,
        Ok(_) => false, // unexpected data; ignore it
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
    }
}

fn render(stats: &Stats, queues: &[Arc<Queue>]) -> String {
    let mut out = format!(
        "# HELP repsheet_collector_lines_total Log lines read.\n\
         # TYPE repsheet_collector_lines_total counter\n\
         repsheet_collector_lines_total {}\n\
         # HELP repsheet_collector_parse_errors_total Lines that were not valid events.\n\
         # TYPE repsheet_collector_parse_errors_total counter\n\
         repsheet_collector_parse_errors_total {}\n\
         # HELP repsheet_collector_rotations_total Times the log file was rotated or truncated.\n\
         # TYPE repsheet_collector_rotations_total counter\n\
         repsheet_collector_rotations_total {}\n",
        stats.lines.load(Ordering::Relaxed),
        stats.parse_errors.load(Ordering::Relaxed),
        stats.rotations.load(Ordering::Relaxed),
    );
    for (name, help, kind) in [
        (
            "events_forwarded_total",
            "Events delivered to the analyzer.",
            "counter",
        ),
        (
            "events_dropped_total",
            "Events dropped because the analyzer's queue was full.",
            "counter",
        ),
        ("queue_events", "Events waiting for the analyzer.", "gauge"),
        ("connected", "1 if connected to the analyzer.", "gauge"),
    ] {
        out.push_str(&format!(
            "# HELP repsheet_collector_{name} {help}\n# TYPE repsheet_collector_{name} {kind}\n"
        ));
        for q in queues {
            let value = match name {
                "events_forwarded_total" => q.forwarded.load(Ordering::Relaxed),
                "events_dropped_total" => q.dropped.load(Ordering::Relaxed),
                "queue_events" => q.len() as u64,
                _ => q.connected.load(Ordering::Relaxed) as u64,
            };
            out.push_str(&format!(
                "repsheet_collector_{name}{{analyzer=\"{}\"}} {value}\n",
                q.analyzer
            ));
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "repsheet_collector=info".into()),
        )
        .init();
    let args = Args::parse();

    if args.print_log_format {
        println!("{}", repsheet_event::NGINX_LOG_FORMAT);
        return Ok(());
    }
    let file = args.file.expect("required by clap");

    let queues: Vec<Arc<Queue>> = args
        .forward
        .iter()
        .map(|a| {
            Arc::new(Queue {
                analyzer: a.trim().to_string(),
                lines: Mutex::new(VecDeque::new()),
                notify: Notify::new(),
                cap: args.queue.max(1),
                forwarded: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                connected: AtomicBool::new(false),
            })
        })
        .collect();
    for q in &queues {
        tokio::spawn(forward(q.clone()));
    }

    let stats = Arc::new(Stats::default());
    let listener = tokio::net::TcpListener::bind(args.metrics).await?;
    {
        let (stats, queues) = (stats.clone(), queues.clone());
        tokio::spawn(repsheet_event::serve_metrics(
            listener,
            Arc::new(move || render(&stats, &queues)),
        ));
    }

    tracing::info!(
        "following {} for {} analyzer(s)",
        file.display(),
        queues.len()
    );

    // The file is read on a plain thread; events go to the queues.
    let (poll, from_start) = (Duration::from_millis(args.poll_ms.max(10)), args.from_start);
    let tail_stats = stats.clone();
    std::thread::spawn(move || {
        let mut tailer = tail::Tailer::new(file, from_start);
        let mut logged_errors = 0;
        loop {
            for line in tailer.poll() {
                tail_stats.lines.fetch_add(1, Ordering::Relaxed);
                match Event::parse(&line) {
                    Ok(event) => {
                        let out = event.to_line();
                        for q in &queues {
                            q.push(out.clone());
                        }
                    }
                    Err(e) => {
                        tail_stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                        if logged_errors < 10 {
                            tracing::warn!(
                                "skipping a line that is not an event ({e}): {line:.200}"
                            );
                            logged_errors += 1;
                        }
                    }
                }
            }
            tail_stats
                .rotations
                .store(tailer.rotations, Ordering::Relaxed);
            std::thread::sleep(poll);
        }
    });

    repsheet_event::shutdown_signal().await;
    Ok(())
}
