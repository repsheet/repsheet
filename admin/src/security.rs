//! Protections for a UI that has no login of its own.
//!
//! * Host check: refuse requests whose Host header is a name we were not told
//!   about. This defeats DNS rebinding, where a malicious site points its own
//!   hostname at 127.0.0.1 to read and drive the UI from the victim's browser.
//! * Origin check: every POST must come from a page served by this UI.
//!   This stops other sites from submitting forms through the user's browser.
//! * Response headers that keep pages from being framed or running foreign
//!   scripts.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub struct Policy {
    /// Hostnames (lowercase, no port) accepted besides IP literals and localhost.
    pub allowed_hosts: Vec<String>,
    pub read_only: bool,
}

/// The host part of a Host header value, lowercased, without the port.
fn host_name(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(rest[..end].to_ascii_lowercase());
    }
    let name = match value.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => value,
    };
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

impl Policy {
    pub fn host_allowed(&self, host: &str) -> bool {
        let Some(name) = host_name(host) else {
            return false;
        };
        name == "localhost" || name.parse::<IpAddr>().is_ok() || self.allowed_hosts.contains(&name)
    }
}

/// True if the request's Origin (or, failing that, Referer) is this server.
fn same_origin(headers: &HeaderMap, host: &str) -> bool {
    let origin_ok = |origin: &str| {
        let rest = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"));
        rest.is_some_and(|r| r.split('/').next() == Some(host))
    };
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin.to_str().is_ok_and(origin_ok);
    }
    if let Some(referer) = headers.get(header::REFERER) {
        return referer.to_str().is_ok_and(origin_ok);
    }
    false
}

pub async fn middleware(State(policy): State<Arc<Policy>>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !policy.host_allowed(&host) {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            "Unknown Host. Use --allowed-host to permit this name.\n",
        )
            .into_response();
    }

    if req.method() != Method::GET && req.method() != Method::HEAD {
        if policy.read_only {
            return (StatusCode::FORBIDDEN, "This admin UI is read-only.\n").into_response();
        }
        if !same_origin(req.headers(), &host) {
            return (StatusCode::FORBIDDEN, "Cross-origin request refused.\n").into_response();
        }
    }

    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            allowed_hosts: vec!["admin.example.com".into()],
            read_only: false,
        }
    }

    #[test]
    fn hosts() {
        let p = policy();
        for ok in [
            "localhost:8090",
            "127.0.0.1:8090",
            "[::1]:8090",
            "10.0.0.5",
            "Admin.Example.com:443",
            "localhost",
        ] {
            assert!(p.host_allowed(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.example:8090",
            "localhost.evil.example",
            "[::1",
            "attacker.com",
        ] {
            assert!(!p.host_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn origins() {
        let mut h = HeaderMap::new();
        assert!(!same_origin(&h, "localhost:8090"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:8090"),
        );
        assert!(same_origin(&h, "localhost:8090"));
        assert!(!same_origin(&h, "localhost:9999"));
        h.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert!(!same_origin(&h, "localhost:8090"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:8090.evil.com"),
        );
        assert!(!same_origin(&h, "localhost:8090"));

        let mut h = HeaderMap::new();
        h.insert(
            header::REFERER,
            HeaderValue::from_static("http://localhost:8090/actor?q=x"),
        );
        assert!(same_origin(&h, "localhost:8090"));
        h.insert(
            header::REFERER,
            HeaderValue::from_static("https://evil.com/http://localhost:8090/"),
        );
        assert!(!same_origin(&h, "localhost:8090"));
    }
}
