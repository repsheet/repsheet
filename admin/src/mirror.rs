//! An in-memory copy of every decision, kept current the same way nginx does:
//! a snapshot, then the ordered change log, woken by pubsub notifications.
//! Lists and counts are served from here instead of scanning Valkey.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio::sync::Notify;

use crate::valkey::{Changes, Entry, NOTIFY_CHANNEL, Valkey};

const PAGE: u64 = 1000;

#[derive(Default)]
pub struct State {
    pub entries: HashMap<String, Entry>,
    pub epoch: String,
    pub seq: u64,
    pub synced: bool,
    pub last_sync: Option<Instant>,
    pub last_error: Option<String>,
}

impl State {
    pub fn load(&mut self, epoch: String, seq: u64, entries: Vec<Entry>) {
        self.entries = entries.into_iter().map(|e| (e.actor.clone(), e)).collect();
        self.epoch = epoch;
        self.seq = seq;
        self.synced = true;
    }

    /// Apply a page of changes. `entry` is None for deletions.
    pub fn apply(
        &mut self,
        epoch: String,
        cursor: u64,
        changes: Vec<(u64, Option<Entry>, String)>,
    ) {
        for (_, entry, actor) in changes {
            match entry {
                Some(e) => {
                    self.entries.insert(actor, e);
                }
                None => {
                    self.entries.remove(&actor);
                }
            }
        }
        self.epoch = epoch;
        self.seq = cursor;
    }
}

pub type Shared = Arc<RwLock<State>>;

/// Run forever, keeping `state` in sync with Valkey.
pub async fn run(client: redis::Client, valkey: Valkey, state: Shared, interval: Duration) {
    let wake = Arc::new(Notify::new());
    tokio::spawn(listen(client, wake.clone()));

    let mut backoff = Duration::from_millis(250);
    loop {
        match sync_once(&valkey, &state).await {
            Ok(more) => {
                backoff = Duration::from_millis(250);
                {
                    let mut s = state.write().unwrap();
                    s.last_sync = Some(Instant::now());
                    s.last_error = None;
                }
                if more {
                    continue;
                }
                tokio::select! {
                    _ = wake.notified() => {}
                    _ = tokio::time::sleep(interval) => {}
                }
            }
            Err(e) => {
                tracing::warn!("sync failed: {e}");
                state.write().unwrap().last_error = Some(e.to_string());
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    }
}

/// One step. Returns true if there are more changes to fetch right away.
async fn sync_once(valkey: &Valkey, state: &Shared) -> crate::valkey::Result<bool> {
    let (synced, epoch, seq) = {
        let s = state.read().unwrap();
        (s.synced, s.epoch.clone(), s.seq)
    };

    if synced {
        match valkey.changes(&epoch, seq, PAGE).await? {
            Changes::Ok {
                epoch,
                cursor,
                changes,
            } => {
                let full = changes.len() as u64 >= PAGE;
                state.write().unwrap().apply(epoch, cursor, changes);
                return Ok(full);
            }
            Changes::Resync => tracing::info!("change log says resync; taking a snapshot"),
        }
    }

    let snap = valkey.snapshot().await?;
    tracing::info!(
        "snapshot: {} decisions at seq {}",
        snap.entries.len(),
        snap.seq
    );
    state
        .write()
        .unwrap()
        .load(snap.epoch, snap.seq, snap.entries);
    Ok(false)
}

/// Subscribe to change notifications and wake the sync loop. Reconnects on error.
async fn listen(client: redis::Client, wake: Arc<Notify>) {
    loop {
        match client.get_async_pubsub().await {
            Ok(mut pubsub) => {
                if pubsub.subscribe(NOTIFY_CHANNEL).await.is_ok() {
                    // Catch anything that happened while we were not subscribed.
                    wake.notify_one();
                    let mut messages = pubsub.on_message();
                    while messages.next().await.is_some() {
                        wake.notify_one();
                    }
                }
            }
            Err(e) => tracing::debug!("pubsub connect failed: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::valkey::Status;

    fn entry(actor: &str, status: Status) -> Entry {
        Entry {
            actor: actor.into(),
            status,
            reason: String::new(),
            expires: 0,
        }
    }

    #[test]
    fn load_then_apply() {
        let mut s = State::default();
        s.load(
            "e".into(),
            2,
            vec![
                entry("ip:1.1.1.1", Status::Block),
                entry("ip:2.2.2.2", Status::Mark),
            ],
        );
        s.apply(
            "e".into(),
            4,
            vec![
                (3, None, "ip:1.1.1.1".into()),
                (
                    4,
                    Some(entry("ip:2.2.2.2", Status::Allow)),
                    "ip:2.2.2.2".into(),
                ),
            ],
        );
        assert_eq!(s.seq, 4);
        assert!(!s.entries.contains_key("ip:1.1.1.1"));
        assert_eq!(s.entries["ip:2.2.2.2"].status, Status::Allow);
    }

    #[test]
    fn load_replaces_everything() {
        let mut s = State::default();
        s.load("a".into(), 1, vec![entry("ip:1.1.1.1", Status::Block)]);
        s.load("b".into(), 0, vec![]);
        assert!(s.entries.is_empty());
        assert_eq!((s.epoch.as_str(), s.seq), ("b", 0));
    }
}
