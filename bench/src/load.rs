//! A small HTTP/1.1 load generator: keep-alive connections, one request in
//! flight per connection, requests taken round-robin from a prebuilt pool.
//!
//! Closed loop (default): each connection sends as fast as responses come
//! back; this finds the maximum throughput. Fixed rate (`rate`): requests are
//! scheduled at evenly spaced times and latency is measured from the time a
//! request *should* have been sent, so a stalled server shows up in the
//! percentiles instead of slowing the generator down (coordinated omission).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct Spec {
    pub addr: SocketAddr,
    pub connections: usize,
    pub duration: Duration,
    /// Total requests per second across all connections; None = closed loop.
    pub rate: Option<f64>,
    /// Complete HTTP/1.1 requests, sent in turn.
    pub requests: Arc<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub requests: u64,
    pub errors: u64,
    pub by_status: [u64; 6], // 0: other, 1xx..5xx
    pub elapsed: Duration,
    /// Latency in microseconds.
    pub latency: Histogram<u64>,
}

impl Outcome {
    pub fn throughput(&self) -> f64 {
        self.requests as f64 / self.elapsed.as_secs_f64()
    }

    pub fn percentile_us(&self, q: f64) -> u64 {
        self.latency.value_at_quantile(q)
    }
}

/// Build a GET request.
pub fn request(path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut r = format!("GET {path} HTTP/1.1\r\nHost: bench\r\n");
    for (k, v) in headers {
        r.push_str(k);
        r.push_str(": ");
        r.push_str(v);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r.into_bytes()
}

/// Parse a complete response at the start of `buf`: (status, total length).
/// None if more bytes are needed. Requires Content-Length (no chunked bodies).
pub fn parse_response(buf: &[u8]) -> Result<Option<(u16, usize)>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > 64 * 1024 {
            return Err("response headers too large".into());
        }
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| "non-UTF-8 headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line {status_line:?}"))?;
    let mut length = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                length = v.trim().parse::<usize>().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                return Err("chunked responses are not supported".into());
            }
        }
    }
    let total = end + 4 + length.ok_or("response without Content-Length")?;
    Ok((buf.len() >= total).then_some((status, total)))
}

struct Shared {
    stop: AtomicBool,
    next: AtomicU64,
}

async fn connection(
    spec: Spec,
    shared: Arc<Shared>,
    index: usize,
    start: Instant,
) -> (Histogram<u64>, u64, u64, [u64; 6]) {
    let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("histogram");
    let (mut done, mut errors, mut by_status) = (0u64, 0u64, [0u64; 6]);
    let interval = spec
        .rate
        .map(|r| Duration::from_secs_f64(spec.connections as f64 / r));
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut stream: Option<TcpStream> = None;
    let mut sent = 0u64;

    while !shared.stop.load(Ordering::Relaxed) {
        // When the request is due (fixed rate), offset per connection to spread them.
        let intended = match interval {
            Some(iv) => {
                let t = start + iv.mul_f64(sent as f64 + index as f64 / spec.connections as f64);
                let now = Instant::now();
                if t > now {
                    tokio::time::sleep(t - now).await;
                }
                t
            }
            None => Instant::now(),
        };
        sent += 1;
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }

        if stream.is_none() {
            match TcpStream::connect(spec.addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    stream = Some(s);
                    buf.clear();
                }
                Err(_) => {
                    errors += 1;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            }
        }
        let s = stream.as_mut().expect("connected");
        let i = shared.next.fetch_add(1, Ordering::Relaxed) as usize % spec.requests.len();

        let result: Result<u16, String> = async {
            s.write_all(&spec.requests[i])
                .await
                .map_err(|e| e.to_string())?;
            loop {
                if let Some((status, len)) = parse_response(&buf)? {
                    buf.drain(..len);
                    return Ok(status);
                }
                let mut chunk = [0u8; 8192];
                let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("connection closed".into());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
        .await;

        match result {
            Ok(status) => {
                let us = intended.elapsed().as_micros().max(1) as u64;
                let _ = hist.record(us.min(60_000_000));
                done += 1;
                by_status[(status / 100).min(5) as usize] += 1;
            }
            Err(_) => {
                errors += 1;
                stream = None;
            }
        }
    }
    (hist, done, errors, by_status)
}

/// Run the load for `spec.duration` and return what happened.
pub async fn run(spec: Spec) -> Outcome {
    let shared = Arc::new(Shared {
        stop: AtomicBool::new(false),
        next: AtomicU64::new(0),
    });
    let start = Instant::now();
    let tasks: Vec<_> = (0..spec.connections)
        .map(|i| tokio::spawn(connection(spec.clone(), shared.clone(), i, start)))
        .collect();

    tokio::time::sleep(spec.duration).await;
    shared.stop.store(true, Ordering::Relaxed);
    let elapsed = start.elapsed();

    let mut out = Outcome {
        requests: 0,
        errors: 0,
        by_status: [0; 6],
        elapsed,
        latency: Histogram::new_with_bounds(1, 60_000_000, 3).expect("histogram"),
    };
    for t in tasks {
        // A request in flight when time is up still completes; it is counted.
        if let Ok((hist, done, errors, by_status)) = t.await {
            out.latency.add(hist).expect("histogram");
            out.requests += done;
            out.errors += errors;
            for (total, n) in out.by_status.iter_mut().zip(by_status) {
                *total += n;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_complete_responses() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nhello\nHTTP/1.1";
        assert_eq!(parse_response(r).unwrap(), Some((200, r.len() - 8)));
    }

    #[test]
    fn waits_for_more() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Le").unwrap(),
            None
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 10\r\n\r\nabc").unwrap(),
            None
        );
    }

    #[test]
    fn rejects_unsupported() {
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
        assert!(parse_response(b"garbage\r\n\r\n").is_err());
    }

    #[test]
    fn builds_requests() {
        let r = request("/", &[("X-Real-IP", "10.0.0.1")]);
        assert_eq!(
            r,
            b"GET / HTTP/1.1\r\nHost: bench\r\nX-Real-IP: 10.0.0.1\r\n\r\n"
        );
    }
}
