//! Pages and form handlers.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use askama::Template;
use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::actor;
use crate::mirror;
use crate::valkey::{Change, Status, Valkey};

const PER_PAGE: usize = 100;
const MAX_REASON: usize = 1024;
const MAX_BY: usize = 256;

pub struct App {
    pub valkey: Valkey,
    pub mirror: mirror::Shared,
    pub read_only: bool,
    pub user_header: Option<String>,
    pub default_by: String,
}

type Shared = State<Arc<App>>;

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/decisions", get(decisions).post(set_decision))
        .route("/actor", get(actor_page))
        .route("/new", get(new_form))
        .route("/clear", post(clear_decision))
        .route("/activity", get(activity))
        .route("/static/app.css", get(css))
        .route("/healthz", get(healthz))
        .with_state(app)
}

// --------------------------------------------------------------------------
// Formatting
// --------------------------------------------------------------------------

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn fmt_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let format =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .ok()
        .and_then(|t| t.format(&format).ok())
        .unwrap_or_default()
}

fn fmt_span(secs: i64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    match () {
        _ if d > 0 => format!("{d}d {h}h"),
        _ if h > 0 => format!("{h}h {m}m"),
        _ if m > 0 => format!("{m}m"),
        _ => format!("{s}s"),
    }
}

/// "in 3h 5m", "5m ago", "never"
fn fmt_relative(ms: i64, now: i64) -> String {
    if ms <= 0 {
        return "never".into();
    }
    let delta = (ms - now) / 1000;
    if delta.abs() < 5 {
        "now".into()
    } else if delta > 0 {
        format!("in {}", fmt_span(delta))
    } else {
        format!("{} ago", fmt_span(-delta))
    }
}

/// TTL from the form: empty/"never", plain seconds, or 30s/15m/2h/7d.
pub fn parse_ttl(input: &str) -> Result<Option<u64>, String> {
    let s = input.trim().to_ascii_lowercase();
    if s.is_empty() || s == "never" {
        return Ok(None);
    }
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86400),
        _ => (s.as_str(), 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("TTL {input:?} is not a duration like 3600, 15m, 2h or 7d"))?;
    let secs = n.checked_mul(mult).filter(|&t| t > 0 && t <= 315_360_000);
    secs.map(Some)
        .ok_or_else(|| "TTL must be between 1 second and 10 years".into())
}

/// Who to record as the author of a change.
fn author(app: &App, headers: &HeaderMap) -> String {
    app.user_header
        .as_deref()
        .and_then(|name| headers.get(name))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= MAX_BY && !v.chars().any(char::is_control))
        .map_or_else(|| app.default_by.clone(), str::to_string)
}

fn render(t: impl Template) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("template error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}

// --------------------------------------------------------------------------
// View models
// --------------------------------------------------------------------------

pub struct Row {
    pub actor: String,
    pub status: &'static str,
    pub reason: String,
    pub expires: String,
    pub expires_title: String,
}

pub struct ChangeRow {
    pub seq: u64,
    pub actor: String,
    pub status: String,
    pub reason: String,
    pub expires: String,
    pub by: String,
    pub at: String,
    pub at_title: String,
}

impl ChangeRow {
    fn from(c: Change, now: i64) -> Self {
        let status = if c.op == "del" {
            "cleared".into()
        } else {
            c.status
        };
        ChangeRow {
            seq: c.seq,
            actor: c.actor,
            status,
            reason: c.reason,
            expires: if c.expires > 0 {
                fmt_time(c.expires)
            } else {
                String::new()
            },
            by: c.by,
            at: if c.at > 0 {
                fmt_relative(c.at, now)
            } else {
                String::new()
            },
            at_title: fmt_time(c.at),
        }
    }
}

pub struct TypeCount {
    pub name: String,
    pub block: usize,
    pub allow: usize,
    pub mark: usize,
}

// --------------------------------------------------------------------------
// Dashboard
// --------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: &'static str,
    read_only: bool,
    block: usize,
    allow: usize,
    mark: usize,
    types: Vec<TypeCount>,
    expiring: Vec<Row>,
    recent: Vec<ChangeRow>,
    server: String,
    module: String,
    stream_len: i64,
    synced: bool,
    seq: u64,
    last_sync: String,
    sync_error: String,
    error: String,
}

async fn dashboard(State(app): Shared) -> Response {
    let now = now_ms();
    let mut page = DashboardPage {
        nav: "dashboard",
        read_only: app.read_only,
        block: 0,
        allow: 0,
        mark: 0,
        types: vec![],
        expiring: vec![],
        recent: vec![],
        server: String::new(),
        module: String::new(),
        stream_len: 0,
        synced: false,
        seq: 0,
        last_sync: String::new(),
        sync_error: String::new(),
        error: String::new(),
    };

    {
        let m = app.mirror.read().unwrap();
        let mut types: BTreeMap<&str, TypeCount> = BTreeMap::new();
        let mut expiring = Vec::new();
        for e in m
            .entries
            .values()
            .filter(|e| e.expires == 0 || e.expires > now)
        {
            let t = actor::actor_type(&e.actor);
            let tc = types.entry(t).or_insert_with(|| TypeCount {
                name: t.into(),
                block: 0,
                allow: 0,
                mark: 0,
            });
            match e.status {
                Status::Block => {
                    page.block += 1;
                    tc.block += 1;
                }
                Status::Allow => {
                    page.allow += 1;
                    tc.allow += 1;
                }
                Status::Mark => {
                    page.mark += 1;
                    tc.mark += 1;
                }
                Status::None => {}
            }
            if e.expires > 0 && e.expires - now < 86_400_000 {
                expiring.push(e);
            }
        }
        expiring.sort_by_key(|e| e.expires);
        page.expiring = expiring.into_iter().take(10).map(|e| row(e, now)).collect();
        page.types = types.into_values().collect();
        page.synced = m.synced;
        page.seq = m.seq;
        page.last_sync = m
            .last_sync
            .map(|t| fmt_span(t.elapsed().as_secs() as i64))
            .unwrap_or_default();
        page.sync_error = m.last_error.clone().unwrap_or_default();
    }

    match app.valkey.info().await {
        Ok(info) => {
            page.server = info.server;
            page.module = info.module;
            page.stream_len = info.stream_len;
        }
        Err(e) => page.error = e.to_string(),
    }
    match app.valkey.history(None, 20).await {
        Ok(changes) => {
            page.recent = changes
                .into_iter()
                .map(|c| ChangeRow::from(c, now))
                .collect()
        }
        Err(e) => page.error = e.to_string(),
    }
    render(page)
}

fn row(e: &crate::valkey::Entry, now: i64) -> Row {
    Row {
        actor: e.actor.clone(),
        status: e.status.as_str(),
        reason: e.reason.clone(),
        expires: fmt_relative(e.expires, now),
        expires_title: fmt_time(e.expires),
    }
}

// --------------------------------------------------------------------------
// Decisions list
// --------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ListParams {
    #[serde(default)]
    status: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    q: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    page: usize,
}

#[derive(Template)]
#[template(path = "decisions.html")]
struct DecisionsPage {
    nav: &'static str,
    read_only: bool,
    rows: Vec<Row>,
    total: usize,
    page: usize,
    pages: usize,
    status: String,
    kind: String,
    q: String,
    sort: String,
    types: Vec<String>,
}

async fn decisions(State(app): Shared, Query(p): Query<ListParams>) -> Response {
    let now = now_ms();
    let status = Status::parse(&p.status).filter(|s| *s != Status::None);
    let q = p.q.trim().to_lowercase();
    let (mut matched, types) = {
        let m = app.mirror.read().unwrap();
        let mut types: Vec<String> = m
            .entries
            .keys()
            .map(|a| actor::actor_type(a).to_string())
            .collect();
        types.sort();
        types.dedup();
        let matched: Vec<_> = m
            .entries
            .values()
            .filter(|e| e.expires == 0 || e.expires > now)
            .filter(|e| status.is_none_or(|s| e.status == s))
            .filter(|e| p.kind.is_empty() || actor::actor_type(&e.actor) == p.kind)
            .filter(|e| {
                q.is_empty()
                    || e.actor.to_lowercase().contains(&q)
                    || e.reason.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();
        (matched, types)
    };
    match p.sort.as_str() {
        "expires" => matched.sort_by_key(|e| (e.expires == 0, e.expires, e.actor.clone())),
        "status" => {
            matched.sort_by(|a, b| b.status.cmp(&a.status).then_with(|| a.actor.cmp(&b.actor)))
        }
        _ => matched.sort_by(|a, b| a.actor.cmp(&b.actor)),
    }
    let total = matched.len();
    let pages = total.div_ceil(PER_PAGE).max(1);
    let page = p.page.clamp(1, pages);
    let rows = matched
        .iter()
        .skip((page - 1) * PER_PAGE)
        .take(PER_PAGE)
        .map(|e| row(e, now))
        .collect();
    render(DecisionsPage {
        nav: "decisions",
        read_only: app.read_only,
        rows,
        total,
        page,
        pages,
        status: status.map(|s| s.as_str().to_string()).unwrap_or_default(),
        kind: p.kind,
        q: p.q,
        sort: p.sort,
        types,
    })
}

// --------------------------------------------------------------------------
// Actor page
// --------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ActorParams {
    #[serde(default)]
    q: String,
    #[serde(default)]
    done: String,
}

#[derive(Template)]
#[template(path = "actor.html")]
struct ActorPage {
    nav: &'static str,
    read_only: bool,
    q: String,
    canonical: String,
    error: String,
    notice: &'static str,
    // effective result
    effective: &'static str,
    effective_reason: String,
    matched: String,
    via_other: bool,
    // exact decision
    has_decision: bool,
    status: &'static str,
    reason: String,
    created: String,
    expires: String,
    expires_title: String,
    by: String,
    history: Vec<ChangeRow>,
    form: FormValues,
}

#[derive(Default, Deserialize, Clone)]
pub struct FormValues {
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ttl: String,
}

async fn actor_page(State(app): Shared, Query(p): Query<ActorParams>) -> Response {
    let now = now_ms();
    let mut page = ActorPage {
        nav: "actor",
        read_only: app.read_only,
        q: p.q.trim().to_string(),
        canonical: String::new(),
        error: String::new(),
        notice: match p.done.as_str() {
            "set" => "Decision saved.",
            "cleared" => "Decision cleared.",
            "absent" => "There was no decision to clear.",
            _ => "",
        },
        effective: "none",
        effective_reason: String::new(),
        matched: String::new(),
        via_other: false,
        has_decision: false,
        status: "",
        reason: String::new(),
        created: String::new(),
        expires: String::new(),
        expires_title: String::new(),
        by: String::new(),
        history: vec![],
        form: FormValues::default(),
    };
    if page.q.is_empty() {
        return render(page);
    }
    let canonical = match actor::canonicalize(&page.q) {
        Ok(c) => c,
        Err(e) => {
            page.error = format!("Not a valid actor: {e}.");
            return render(page);
        }
    };
    page.canonical = canonical.clone();
    page.form = FormValues {
        actor: canonical.clone(),
        status: "block".into(),
        ..Default::default()
    };

    let result = async {
        let verdict = app.valkey.check(&[&canonical]).await?;
        let decision = app.valkey.get(&canonical).await?;
        let history = app.valkey.actor_history(&canonical, 50, 10_000).await?;
        Ok::<_, crate::valkey::Error>((verdict, decision, history))
    }
    .await;

    match result {
        Ok((verdict, decision, history)) => {
            page.effective = verdict.status.as_str();
            page.effective_reason = verdict.reason;
            page.via_other = verdict.status != Status::None && verdict.actor != canonical;
            page.matched = verdict.actor;
            if let Some(d) = decision {
                page.has_decision = true;
                page.status = d.status.as_str();
                page.reason = d.reason.clone();
                page.created = fmt_time(d.created);
                page.expires = fmt_relative(d.expires, now);
                page.expires_title = fmt_time(d.expires);
                page.by = d.by;
                page.form.status = d.status.as_str().into();
                page.form.reason = d.reason;
            }
            page.history = history
                .into_iter()
                .map(|c| ChangeRow::from(c, now))
                .collect();
        }
        Err(e) => page.error = e.to_string(),
    }
    render(page)
}

// --------------------------------------------------------------------------
// New / change / clear
// --------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "new.html")]
struct NewPage {
    nav: &'static str,
    read_only: bool,
    error: String,
    form: FormValues,
}

async fn new_form(State(app): Shared, Query(form): Query<FormValues>) -> Response {
    let form = FormValues {
        status: if form.status.is_empty() {
            "block".into()
        } else {
            form.status
        },
        ..form
    };
    render(NewPage {
        nav: "new",
        read_only: app.read_only,
        error: String::new(),
        form,
    })
}

fn actor_url(actor: &str, done: &str) -> String {
    let mut s = String::from("/actor?q=");
    for b in actor.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~:".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s.push_str("&done=");
    s.push_str(done);
    s
}

async fn set_decision(
    State(app): Shared,
    headers: HeaderMap,
    Form(form): Form<FormValues>,
) -> Response {
    let fail = |error: String, form: FormValues| {
        let mut res = render(NewPage {
            nav: "new",
            read_only: app.read_only,
            error,
            form,
        });
        *res.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        res
    };

    let canonical = match actor::canonicalize(form.actor.trim()) {
        Ok(c) => c,
        Err(e) => return fail(format!("Not a valid actor: {e}."), form),
    };
    let status = match Status::parse(&form.status) {
        Some(s) if s != Status::None => s,
        _ => return fail("Choose block, allow or mark.".into(), form),
    };
    if form.reason.len() > MAX_REASON {
        return fail(
            format!("The reason is longer than {MAX_REASON} bytes."),
            form,
        );
    }
    let ttl = match parse_ttl(&form.ttl) {
        Ok(t) => t,
        Err(e) => return fail(e, form),
    };

    let by = author(&app, &headers);
    match app
        .valkey
        .set(status, &canonical, form.reason.trim(), ttl, &by)
        .await
    {
        Ok(()) => {
            tracing::info!(actor = %canonical, status = status.as_str(), by = %by, "decision set");
            Redirect::to(&actor_url(&canonical, "set")).into_response()
        }
        Err(e) => fail(e.to_string(), form),
    }
}

#[derive(Deserialize)]
struct ClearForm {
    actor: String,
}

async fn clear_decision(
    State(app): Shared,
    headers: HeaderMap,
    Form(form): Form<ClearForm>,
) -> Response {
    let canonical = match actor::canonicalize(form.actor.trim()) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Not a valid actor: {e}.\n"),
            )
                .into_response();
        }
    };
    let by = author(&app, &headers);
    match app.valkey.clear(&canonical, &by).await {
        Ok(removed) => {
            tracing::info!(actor = %canonical, by = %by, removed, "decision cleared");
            Redirect::to(&actor_url(
                &canonical,
                if removed { "cleared" } else { "absent" },
            ))
            .into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e}\n")).into_response(),
    }
}

// --------------------------------------------------------------------------
// Activity
// --------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ActivityParams {
    before: Option<u64>,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityPage {
    nav: &'static str,
    read_only: bool,
    changes: Vec<ChangeRow>,
    next: u64,
    error: String,
}

async fn activity(State(app): Shared, Query(p): Query<ActivityParams>) -> Response {
    const COUNT: usize = 50;
    let now = now_ms();
    let mut page = ActivityPage {
        nav: "activity",
        read_only: app.read_only,
        changes: vec![],
        next: 0,
        error: String::new(),
    };
    match app.valkey.history(p.before, COUNT).await {
        Ok(changes) => {
            if changes.len() == COUNT {
                page.next = changes.last().map_or(0, |c| c.seq);
            }
            page.changes = changes
                .into_iter()
                .map(|c| ChangeRow::from(c, now))
                .collect();
        }
        Err(e) => page.error = e.to_string(),
    }
    render(page)
}

// --------------------------------------------------------------------------
// Static and health
// --------------------------------------------------------------------------

async fn css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/app.css"),
    )
        .into_response()
}

async fn healthz(State(app): Shared) -> Response {
    let (synced, err) = {
        let m = app.mirror.read().unwrap();
        (m.synced, m.last_error.clone())
    };
    match (synced, err) {
        (true, None) => (StatusCode::OK, "ok\n").into_response(),
        (_, Some(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("sync error: {e}\n"),
        )
            .into_response(),
        (false, None) => (StatusCode::SERVICE_UNAVAILABLE, "not synced yet\n").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl() {
        assert_eq!(parse_ttl(""), Ok(None));
        assert_eq!(parse_ttl("never"), Ok(None));
        assert_eq!(parse_ttl("3600"), Ok(Some(3600)));
        assert_eq!(parse_ttl("15m"), Ok(Some(900)));
        assert_eq!(parse_ttl(" 2H "), Ok(Some(7200)));
        assert_eq!(parse_ttl("7d"), Ok(Some(604_800)));
        assert_eq!(parse_ttl("30s"), Ok(Some(30)));
        assert!(parse_ttl("0").is_err());
        assert!(parse_ttl("-5").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("4000d").is_err());
        assert!(parse_ttl("99999999999999999999d").is_err());
    }

    #[test]
    fn relative_times() {
        assert_eq!(fmt_relative(0, 1000), "never");
        assert_eq!(
            fmt_relative(3_600_000 + 60_000 * 5 + 1000, 1000),
            "in 1h 5m"
        );
        assert_eq!(fmt_relative(1000, 1000 + 120_000), "2m ago");
        assert_eq!(fmt_relative(1000, 2000), "now");
        assert_eq!(fmt_relative(1000 + 86_400_000 * 2, 1000), "in 2d 0h");
    }

    #[test]
    fn times() {
        assert_eq!(fmt_time(1_700_000_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(fmt_time(0), "");
    }

    #[test]
    fn actor_urls() {
        assert_eq!(
            actor_url("ip:10.0.0.0/8", "set"),
            "/actor?q=ip:10.0.0.0%2F8&done=set"
        );
        assert_eq!(
            actor_url("session:a&b c", "set"),
            "/actor?q=session:a%26b%20c&done=set"
        );
    }
}
