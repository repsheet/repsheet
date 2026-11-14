//! repsheet-admin: a web UI for viewing and managing Repsheet decisions.

mod actor;
mod mirror;
mod security;
mod valkey;
mod web;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use clap::Parser;
use redis::aio::ConnectionManagerConfig;

/// Web administration UI for Repsheet.
///
/// There is no login. It listens on 127.0.0.1 by default; to expose it, put
/// it behind a proxy that authenticates users.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Valkey/Redis URL: redis://[user:password@]host:port[/db] or unix:///path/to/socket.
    #[arg(long, env = "REPSHEET_REDIS", default_value = "redis://127.0.0.1:6379")]
    redis: String,

    /// Address to listen on.
    #[arg(long, env = "REPSHEET_ADMIN_LISTEN", default_value = "127.0.0.1:8090")]
    listen: SocketAddr,

    /// Show decisions but refuse every change.
    #[arg(long, env = "REPSHEET_ADMIN_READ_ONLY")]
    read_only: bool,

    /// Hostname the UI may be reached under (besides IP addresses and
    /// localhost). Repeat for several names.
    #[arg(
        long = "allowed-host",
        env = "REPSHEET_ADMIN_ALLOWED_HOSTS",
        value_delimiter = ','
    )]
    allowed_hosts: Vec<String>,

    /// Request header carrying the user name, set by an authenticating proxy
    /// (e.g. X-Forwarded-User). Recorded as the author of changes. Only use
    /// this when every request passes through that proxy.
    #[arg(long, env = "REPSHEET_ADMIN_USER_HEADER")]
    user_header: Option<String>,

    /// Author recorded for changes when no user header is present.
    #[arg(
        long,
        env = "REPSHEET_ADMIN_DEFAULT_BY",
        default_value = "repsheet-admin"
    )]
    default_by: String,

    /// How often to poll for changes when no notification arrives.
    #[arg(
        long,
        env = "REPSHEET_ADMIN_SYNC_INTERVAL",
        default_value = "1",
        value_name = "SECONDS"
    )]
    sync_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "repsheet_admin=info".into()),
        )
        .init();
    let args = Args::parse();

    let client = redis::Client::open(args.redis.as_str())?;
    let config = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(Duration::from_secs(2)))
        .set_response_timeout(Some(Duration::from_secs(5)))
        .set_max_delay(Duration::from_secs(5))
        // Report failures right away; the sync loop and the next page load retry.
        .set_number_of_retries(1);
    let conn = client.get_connection_manager_lazy(config)?;
    let valkey = valkey::Valkey::new(conn);

    let state: mirror::Shared = Arc::new(RwLock::new(mirror::State::default()));
    tokio::spawn(mirror::run(
        client.clone(),
        valkey.clone(),
        state.clone(),
        Duration::from_secs(args.sync_interval.max(1)),
    ));

    let policy = Arc::new(security::Policy {
        allowed_hosts: args
            .allowed_hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect(),
        read_only: args.read_only,
    });
    let app = Arc::new(web::App {
        valkey,
        mirror: state,
        read_only: args.read_only,
        user_header: args.user_header.clone(),
        default_by: args.default_by.clone(),
    });
    let router = web::router(app).layer(axum::middleware::from_fn_with_state(
        policy,
        security::middleware,
    ));

    if !args.listen.ip().is_loopback() {
        tracing::warn!(
            "listening on {} without authentication: anyone who can reach this address can change decisions. \
             Put it behind an authenticating proxy or use --read-only.",
            args.listen
        );
    }
    if args.user_header.is_some() && args.listen.ip().is_unspecified() {
        tracing::warn!(
            "--user-header is trusted as sent; make sure only your proxy can reach this port"
        );
    }

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
