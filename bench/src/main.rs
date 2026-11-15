//! repsheet-bench: measure what Repsheet adds to the cost of serving a request.
//!
//! Each scenario starts two nginx servers with identical configuration except
//! for Repsheet (the baseline has none), sends both the same requests in
//! alternating runs, and compares the nginx worker's CPU time per request.

mod env;
mod load;
mod report;
mod scenarios;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use env::{Nginx, NginxConf, Paths, Valkey};
use report::{Report, Run, ScenarioResult, Settings, Side};

#[derive(Parser)]
#[command(
    version,
    about = "Measure the request-path overhead of the Repsheet nginx module"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run benchmark scenarios (all by default) and report the overhead.
    Run(RunArgs),
    /// List the scenarios.
    List,
    /// Plain load generator against an existing server.
    Load(LoadArgs),
}

#[derive(clap::Args)]
struct RunArgs {
    /// Scenarios to run (repeatable). Default: all. "aa" (noise floor) is always added.
    #[arg(long = "scenario", short)]
    scenarios: Vec<String>,
    /// Seconds per measured run.
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    /// Seconds of warm-up per server before measuring.
    #[arg(long, default_value_t = 2.0)]
    warmup: f64,
    /// Concurrent keep-alive connections.
    #[arg(long, default_value_t = 64)]
    connections: usize,
    /// Fixed request rate (requests/s) instead of as fast as possible.
    #[arg(long)]
    rate: Option<f64>,
    /// Runs per side; medians are reported.
    #[arg(long, default_value_t = 3)]
    repeat: usize,
    /// Pin nginx to CPU 0 and the load generator to the other CPUs.
    #[arg(long)]
    pin: bool,
    /// Write the full results as JSON.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Compare against an earlier --json file.
    #[arg(long)]
    compare: Option<PathBuf>,
}

#[derive(clap::Args)]
struct LoadArgs {
    /// Server address, host:port.
    #[arg(long)]
    addr: String,
    #[arg(long, default_value = "/")]
    path: String,
    /// Extra request header "Name: value" (repeatable).
    #[arg(long = "header", short = 'H')]
    headers: Vec<String>,
    #[arg(long, default_value_t = 64)]
    connections: usize,
    #[arg(long, default_value_t = 10.0)]
    duration: f64,
    #[arg(long)]
    rate: Option<f64>,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::List => {
            for (name, about) in scenarios::NAMES {
                println!("{name:<12} {about}");
            }
            Ok(())
        }
        Command::Load(args) => load_command(args),
        Command::Run(args) => run_command(args),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn runtime(threads: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads.max(1))
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

fn load_command(args: LoadArgs) -> Result<(), String> {
    let addr = args
        .addr
        .parse()
        .map_err(|_| format!("bad address {:?}", args.addr))?;
    let headers: Vec<(String, String)> = args
        .headers
        .iter()
        .map(|h| {
            h.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect::<Option<_>>()
        .ok_or("headers must look like \"Name: value\"")?;
    let refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let spec = load::Spec {
        addr,
        connections: args.connections,
        duration: Duration::from_secs_f64(args.duration),
        rate: args.rate,
        requests: Arc::new(vec![load::request(&args.path, &refs)]),
    };
    let out = runtime(cpus()).block_on(load::run(spec));
    println!(
        "{} requests in {:.1}s: {:.0} req/s, {} errors, statuses 2xx={} 3xx={} 4xx={} 5xx={}",
        out.requests,
        out.elapsed.as_secs_f64(),
        out.throughput(),
        out.errors,
        out.by_status[2],
        out.by_status[3],
        out.by_status[4],
        out.by_status[5]
    );
    println!(
        "latency p50 {}µs  p75 {}µs  p95 {}µs  p99 {}µs  p99.99 {}µs  max {}µs",
        out.percentile_us(0.5),
        out.percentile_us(0.75),
        out.percentile_us(0.95),
        out.percentile_us(0.99),
        out.percentile_us(0.9999),
        out.latency.max()
    );
    Ok(())
}

/// Writes new decisions at a steady rate until stopped.
fn start_writer(
    valkey_port: u16,
    per_sec: u32,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{valkey_port}/")) else {
            return 0;
        };
        let Ok(mut conn) = client.get_connection() else {
            return 0;
        };
        let batch = (per_sec / 100).max(1);
        let tick = Duration::from_secs_f64(batch as f64 / per_sec as f64);
        let (mut written, mut next) = (0u64, Instant::now());
        while !stop.load(Ordering::Relaxed) {
            let mut pipe = redis::pipe();
            for _ in 0..batch {
                let addr = scenarios::stored_v4(2_000_000 + written);
                pipe.cmd("REPSHEET.MARK")
                    .arg(addr.to_string())
                    .arg("REASON")
                    .arg("churn")
                    .arg("TTL")
                    .arg(60)
                    .ignore();
                written += 1;
            }
            if pipe.exec(&mut conn).is_err() {
                break;
            }
            next += tick;
            if let Some(wait) = next.checked_duration_since(Instant::now()) {
                std::thread::sleep(wait);
            }
        }
        written
    })
}

fn measure(rt: &tokio::runtime::Runtime, nginx: &Nginx, spec: &load::Spec) -> Result<Run, String> {
    let cpu0 = nginx.worker_cpu_ns()?;
    let out = rt.block_on(load::run(spec.clone()));
    let cpu1 = nginx.worker_cpu_ns()?;
    Ok(Run {
        requests: out.requests,
        errors: out.errors,
        non_2xx: out.requests - out.by_status[2],
        seconds: out.elapsed.as_secs_f64(),
        cpu_ns: cpu1.saturating_sub(cpu0),
        p50_us: out.percentile_us(0.5),
        p75_us: out.percentile_us(0.75),
        p90_us: out.percentile_us(0.9),
        p95_us: out.percentile_us(0.95),
        p99_us: out.percentile_us(0.99),
        p999_us: out.percentile_us(0.999),
        p9999_us: out.percentile_us(0.9999),
    })
}

fn run_scenario(
    paths: &Paths,
    rt: &tokio::runtime::Runtime,
    args: &RunArgs,
    name: &str,
    base_dir: &std::path::Path,
) -> Result<ScenarioResult, String> {
    let s =
        scenarios::build(name).ok_or_else(|| format!("unknown scenario {name:?} (see `list`)"))?;
    let about = scenarios::NAMES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, a)| *a)
        .unwrap_or("");
    let dir = base_dir.join(name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let pin = args.pin.then_some(0);

    eprintln!("== {name}: {about}");
    let valkey = if s.repsheet {
        Some(Valkey::start(paths, &dir)?)
    } else {
        None
    };
    if let Some(v) = valkey.as_ref().filter(|_| !s.preload.is_empty()) {
        let t = Instant::now();
        let n = v.pipeline(s.preload.iter().cloned())?;
        eprintln!(
            "   loaded {n} decisions into valkey in {:.1}s",
            t.elapsed().as_secs_f64()
        );
    }

    let baseline = Nginx::start(
        paths,
        &dir.join("baseline"),
        &NginxConf {
            http: "",
            location: "",
        },
        pin,
    )?;
    std::fs::create_dir_all(dir.join("repsheet")).map_err(|e| e.to_string())?;
    for (file, contents) in &s.files {
        std::fs::write(dir.join("repsheet").join(file), contents).map_err(|e| e.to_string())?;
    }
    let http = valkey
        .as_ref()
        .map(|v| s.variant_http(v.port, &dir.join("repsheet")))
        .unwrap_or_default();
    let variant = Nginx::start(
        paths,
        &dir.join("repsheet"),
        &NginxConf {
            http: &http,
            location: "",
        },
        pin,
    )?;
    if s.decisions > 0 {
        let t = Instant::now();
        variant.wait_decisions(s.decisions, Duration::from_secs(120))?;
        eprintln!("   nginx synced them in {:.1}s", t.elapsed().as_secs_f64());
    }

    let spec = |addr| load::Spec {
        addr,
        connections: args.connections,
        duration: Duration::from_secs_f64(args.duration),
        rate: args.rate,
        requests: Arc::new(s.requests.clone()),
    };
    let warm = |addr| load::Spec {
        duration: Duration::from_secs_f64(args.warmup),
        ..spec(addr)
    };
    rt.block_on(load::run(warm(baseline.addr)));
    rt.block_on(load::run(warm(variant.addr)));

    let (mut base_runs, mut rs_runs) = (vec![], vec![]);
    for i in 0..args.repeat {
        // Alternate which side goes first, so drift affects both equally.
        for side in if i % 2 == 0 { [0, 1] } else { [1, 0] } {
            if side == 0 {
                let run = measure(rt, &baseline, &spec(baseline.addr))?;
                base_runs.push(run);
            } else {
                let stop = Arc::new(AtomicBool::new(false));
                let writer = (s.writes_per_sec > 0).then(|| {
                    start_writer(
                        valkey.as_ref().expect("valkey").port,
                        s.writes_per_sec,
                        stop.clone(),
                    )
                });
                let run = measure(rt, &variant, &spec(variant.addr));
                stop.store(true, Ordering::Relaxed);
                if let Some(w) = writer {
                    let written = w.join().unwrap_or(0);
                    eprintln!("   wrote {written} decisions during the run");
                }
                rs_runs.push(run?);
            }
        }
    }

    for (label, runs, n) in [
        ("baseline", &base_runs, &baseline),
        ("repsheet", &rs_runs, &variant),
    ] {
        let errors: u64 = runs.iter().map(|r| r.errors).sum();
        let non_2xx: u64 = runs.iter().map(|r| r.non_2xx).sum();
        if errors > 0 || non_2xx > 0 {
            let log = n.error_log();
            let tail: Vec<&str> = log.lines().rev().take(3).collect();
            eprintln!(
                "   warning: {label}: {errors} errors, {non_2xx} non-2xx responses; error.log: {tail:?}"
            );
        }
    }

    let result = ScenarioResult {
        name: name.into(),
        about: about.into(),
        decisions: s.decisions,
        baseline: Side::from_runs(base_runs),
        repsheet: Side::from_runs(rs_runs),
        failed: None,
    };
    eprintln!(
        "   {:.2} µs/req -> {:.2} µs/req ({:+.2} µs, {:+.1}%)",
        result.baseline.cpu_us_per_request,
        result.repsheet.cpu_us_per_request,
        result.overhead_us(),
        result.overhead_pct()
    );
    Ok(result)
}

fn run_command(args: RunArgs) -> Result<(), String> {
    let paths = Paths::discover()?;
    let mut names: Vec<String> = if args.scenarios.is_empty() {
        scenarios::NAMES
            .iter()
            .map(|(n, _)| n.to_string())
            .collect()
    } else {
        args.scenarios.clone()
    };
    if !names.iter().any(|n| n == "aa") {
        names.insert(0, "aa".into());
    }
    for n in &names {
        if scenarios::build(n).is_none() {
            return Err(format!("unknown scenario {n:?} (see `list`)"));
        }
    }

    let threads = if args.pin {
        let others: Vec<usize> = (1..cpus()).collect();
        if others.is_empty() {
            return Err("--pin needs at least 2 CPUs".into());
        }
        env::pin_self(&others)?;
        others.len()
    } else {
        cpus()
    };
    let rt = runtime(threads);

    let base_dir = std::env::temp_dir().join(format!("repsheet-bench-{}", std::process::id()));
    let mut results = vec![];
    for name in &names {
        match run_scenario(&paths, &rt, &args, name, &base_dir) {
            Ok(r) => results.push(r),
            Err(e) => {
                // Report it and carry on with the other scenarios.
                eprintln!("   FAILED: {e}");
                results.push(ScenarioResult {
                    name: name.clone(),
                    about: String::new(),
                    decisions: 0,
                    baseline: Side::from_runs(vec![]),
                    repsheet: Side::from_runs(vec![]),
                    failed: Some(e),
                });
            }
        }
    }
    let _ = std::fs::remove_dir_all(&base_dir);

    let report = Report {
        created: now(),
        host: hostname(),
        settings: Settings {
            duration_s: args.duration,
            connections: args.connections,
            rate: args.rate,
            repeat: args.repeat,
            pinned: args.pin,
            nginx: paths.nginx.display().to_string(),
        },
        scenarios: results,
    };

    println!();
    print!("{}", report.table());
    print!("{}", report.latency_table());
    if let Some(path) = &args.compare {
        let old: Report = std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        print!("{}", report.compare(&old));
    }
    if let Some(path) = &args.json {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, serde_json::to_vec_pretty(&report).expect("json"))
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        eprintln!("\nresults written to {}", path.display());
    }
    Ok(())
}

fn now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // ISO 8601 without a date library: days since epoch -> civil date.
    let (days, rem) = (secs / 86400, secs % 86400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}
