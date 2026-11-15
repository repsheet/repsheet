//! What the Repsheet log collector sends to passive detectors, and small
//! pieces both sides share.
//!
//! nginx writes one JSON object per request (see `NGINX_LOG_FORMAT`); the
//! collector validates it and forwards it to analyzers as one JSON object per
//! line over TCP.

use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The nginx `log_format` that produces events. `$remote_addr` is the client
/// address after the realip module; `$repsheet_status` is what Repsheet
/// decided for the request (`block`, `allow`, `mark` or empty).
pub const NGINX_LOG_FORMAT: &str = r#"log_format repsheet_events escape=json '{"time":$msec,"addr":"$remote_addr","status":$status,"method":"$request_method","host":"$host","uri":"$uri","ua":"$http_user_agent","repsheet":"$repsheet_status"}';"#;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Seconds since the epoch, with milliseconds (`$msec`).
    pub time: f64,
    /// The client address.
    pub addr: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uri: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ua: String,
    /// Repsheet's decision for the request: "block", "allow", "mark" or "".
    #[serde(default)]
    pub repsheet: String,
}

impl Event {
    /// Parse and validate one log line.
    pub fn parse(line: &str) -> Result<Event, String> {
        let e: Event = serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
        if !(e.time.is_finite() && e.time > 0.0) {
            return Err(format!("bad time {}", e.time));
        }
        if !(100..=599).contains(&e.status) {
            return Err(format!("bad status {}", e.status));
        }
        if e.addr.parse::<IpAddr>().is_err() {
            return Err(format!("addr {:?} is not an IP address", e.addr));
        }
        Ok(e)
    }

    /// One line of the collector-to-analyzer protocol (no trailing newline).
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("event serializes")
    }

    /// Milliseconds since the epoch.
    pub fn time_ms(&self) -> i64 {
        (self.time * 1000.0).round() as i64
    }
}

/// A set of HTTP statuses: "400-599", "404,429,500-599", "100-199,201-599".
#[derive(Debug, Clone, PartialEq)]
pub struct StatusSet {
    ranges: Vec<(u16, u16)>,
    text: String,
}

impl StatusSet {
    pub fn parse(text: &str) -> Result<StatusSet, String> {
        let mut ranges = vec![];
        for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (lo, hi) = match part.split_once('-') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (part, part),
            };
            let lo: u16 = lo.parse().map_err(|_| format!("bad status {part:?}"))?;
            let hi: u16 = hi.parse().map_err(|_| format!("bad status {part:?}"))?;
            if !(100..=599).contains(&lo) || !(100..=599).contains(&hi) || lo > hi {
                return Err(format!("bad status range {part:?} (statuses are 100-599)"));
            }
            ranges.push((lo, hi));
        }
        if ranges.is_empty() {
            return Err("no statuses given".into());
        }
        Ok(StatusSet {
            ranges,
            text: text.split_whitespace().collect(),
        })
    }

    pub fn contains(&self, status: u16) -> bool {
        self.ranges
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&status))
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// Parse a duration: plain seconds, or 30s / 15m / 2h / 7d.
pub fn parse_duration(input: &str) -> Result<u64, String> {
    let s = input.trim().to_ascii_lowercase();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        _ => (s.as_str(), 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("{input:?} is not a duration like 60, 30s, 15m, 2h or 7d"))
}

/// Serve `/metrics` (Prometheus text from `render`) and `/healthz` over plain
/// HTTP. Small on purpose: these programs have no other HTTP surface.
pub async fn serve_metrics<F>(listener: TcpListener, render: Arc<F>)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let render = render.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or("/");
            let (status, ctype, body) = match path {
                "/metrics" => ("200 OK", "text/plain; version=0.0.4", render()),
                "/healthz" => ("200 OK", "text/plain", "ok\n".to_string()),
                _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// Resolves on SIGINT or SIGTERM (what `docker stop` sends; a process
/// running as PID 1 would otherwise ignore it).
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"time":1700000000.123,"addr":"203.0.113.9","status":404,"method":"GET","host":"example.com","uri":"/wp-login.php","ua":"curl/8","repsheet":""}"#;

    #[test]
    fn parses_nginx_lines() {
        let e = Event::parse(LINE).unwrap();
        assert_eq!(
            (e.addr.as_str(), e.status, e.time_ms()),
            ("203.0.113.9", 404, 1_700_000_000_123)
        );
        assert_eq!(Event::parse(&e.to_line()).unwrap(), e);
    }

    #[test]
    fn rejects_bad_lines() {
        for bad in [
            "",
            "not json",
            r#"{"time":1,"addr":"x","status":404}"#,
            r#"{"time":1,"addr":"10.0.0.1","status":99}"#,
            r#"{"time":-1,"addr":"10.0.0.1","status":404}"#,
            r#"{"addr":"10.0.0.1","status":404}"#,
        ] {
            assert!(Event::parse(bad).is_err(), "{bad}");
        }
        assert!(Event::parse(r#"{"time":1.5,"addr":"2001:db8::1","status":200}"#).is_ok());
    }

    #[test]
    fn status_sets() {
        let s = StatusSet::parse("400-599").unwrap();
        assert!(s.contains(404) && s.contains(599) && !s.contains(304) && !s.contains(200));
        let literal = StatusSet::parse("100-199, 201-599").unwrap();
        assert!(literal.contains(304) && literal.contains(404) && !literal.contains(200));
        assert_eq!(literal.as_str(), "100-199,201-599");
        let list = StatusSet::parse("404,429").unwrap();
        assert!(list.contains(429) && !list.contains(403));
        for bad in ["", "abc", "600", "500-400", "0-99", "400-"] {
            assert!(StatusSet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("60"), Ok(60));
        assert_eq!(parse_duration("15m"), Ok(900));
        assert_eq!(parse_duration("2H"), Ok(7200));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("soon").is_err());
    }
}
