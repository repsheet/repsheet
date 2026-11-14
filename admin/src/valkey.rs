//! Typed wrappers around the REPSHEET.* commands and the change stream.

use redis::Value;
use redis::aio::ConnectionManager;

pub const CHANGES_KEY: &str = "{repsheet}:changes";
pub const NOTIFY_CHANNEL: &str = "{repsheet}:notify";

#[derive(Debug)]
pub enum Error {
    /// The server rejected the command (invalid actor, reason too long...).
    /// The message is meant for the user.
    Rejected(String),
    /// Connection problems or an unexpected reply.
    Backend(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rejected(m) => write!(f, "{m}"),
            Error::Backend(m) => write!(f, "Valkey/Redis error: {m}"),
        }
    }
}

impl From<redis::RedisError> for Error {
    fn from(e: redis::RedisError) -> Self {
        if e.is_io_error()
            || e.is_timeout()
            || e.is_connection_dropped()
            || e.is_unrecoverable_error()
        {
            return Error::Backend(e.to_string());
        }
        match (e.code(), e.detail()) {
            (Some("ERR"), Some(detail)) => Error::Rejected(detail.to_string()),
            (Some(code), Some(detail)) => Error::Rejected(format!("{code} {detail}")),
            _ => Error::Backend(e.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn unexpected(what: &str) -> Error {
    Error::Backend(format!("unexpected reply to {what}"))
}

// --------------------------------------------------------------------------
// Value helpers
// --------------------------------------------------------------------------

fn as_string(v: &Value) -> Option<String> {
    match v {
        Value::BulkString(b) => Some(String::from_utf8_lossy(b).into_owned()),
        Value::SimpleString(s) => Some(s.clone()),
        Value::VerbatimString { text, .. } => Some(text.clone()),
        Value::Okay => Some("OK".into()),
        Value::Int(i) => Some(i.to_string()),
        _ => None,
    }
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        Value::BulkString(_) | Value::SimpleString(_) => as_string(v)?.parse().ok(),
        _ => None,
    }
}

fn as_array(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Array(a) | Value::Set(a) => Some(a),
        _ => None,
    }
}

/// Key/value pairs from a RESP3 map or a flattened RESP2 array.
fn as_pairs(v: &Value) -> Option<Vec<(String, &Value)>> {
    match v {
        Value::Map(m) => m.iter().map(|(k, v)| Some((as_string(k)?, v))).collect(),
        Value::Array(a) if a.len() % 2 == 0 => a
            .chunks(2)
            .map(|c| Some((as_string(&c[0])?, &c[1])))
            .collect(),
        _ => None,
    }
}

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    None,
    Mark,
    Block,
    Allow,
}

impl Status {
    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "none" => Some(Status::None),
            "mark" => Some(Status::Mark),
            "block" => Some(Status::Block),
            "allow" => Some(Status::Allow),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::None => "none",
            Status::Mark => "mark",
            Status::Block => "block",
            Status::Allow => "allow",
        }
    }

    fn command(self) -> Option<&'static str> {
        match self {
            Status::Mark => Some("REPSHEET.MARK"),
            Status::Block => Some("REPSHEET.BLOCK"),
            Status::Allow => Some("REPSHEET.ALLOW"),
            Status::None => None,
        }
    }
}

/// A decision as stored, from REPSHEET.GET.
#[derive(Debug, Clone)]
pub struct Decision {
    pub status: Status,
    pub reason: String,
    pub created: i64,
    pub expires: i64,
    pub by: String,
}

/// The effective result for a set of actors, from REPSHEET.CHECK.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub status: Status,
    pub reason: String,
    /// The decision that matched (may be a network containing the address).
    pub actor: String,
}

/// An entry from REPSHEET.SNAPSHOT or REPSHEET.CHANGES.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub actor: String,
    pub status: Status,
    pub reason: String,
    pub expires: i64,
}

pub struct Snapshot {
    pub epoch: String,
    pub seq: u64,
    pub entries: Vec<Entry>,
}

pub enum Changes {
    Ok {
        epoch: String,
        cursor: u64,
        changes: Vec<(u64, Option<Entry>, String)>,
    },
    Resync,
}

/// A change from the stream, with author and time.
#[derive(Debug, Clone)]
pub struct Change {
    pub seq: u64,
    pub op: String,
    pub actor: String,
    pub status: String,
    pub reason: String,
    pub expires: i64,
    pub by: String,
    pub at: i64,
}

pub struct ServerInfo {
    pub server: String,
    pub module: String,
    pub stream_len: i64,
}

// --------------------------------------------------------------------------
// Client
// --------------------------------------------------------------------------

#[derive(Clone)]
pub struct Valkey {
    conn: ConnectionManager,
}

impl Valkey {
    pub fn new(conn: ConnectionManager) -> Self {
        Valkey { conn }
    }

    async fn query(&self, cmd: &redis::Cmd) -> Result<Value> {
        let mut conn = self.conn.clone();
        Ok(cmd.query_async::<Value>(&mut conn).await?)
    }

    pub async fn set(
        &self,
        status: Status,
        actor: &str,
        reason: &str,
        ttl: Option<u64>,
        by: &str,
    ) -> Result<()> {
        let Some(name) = status.command() else {
            return Err(Error::Rejected(
                "status must be allow, block or mark".into(),
            ));
        };
        let mut cmd = redis::cmd(name);
        cmd.arg(actor).arg("REASON").arg(reason).arg("BY").arg(by);
        if let Some(ttl) = ttl {
            cmd.arg("TTL").arg(ttl);
        }
        self.query(&cmd).await?;
        Ok(())
    }

    pub async fn clear(&self, actor: &str, by: &str) -> Result<bool> {
        let v = self
            .query(redis::cmd("REPSHEET.CLEAR").arg(actor).arg("BY").arg(by))
            .await?;
        Ok(as_int(&v) == Some(1))
    }

    pub async fn get(&self, actor: &str) -> Result<Option<Decision>> {
        let v = self.query(redis::cmd("REPSHEET.GET").arg(actor)).await?;
        if v == Value::Nil {
            return Ok(None);
        }
        let pairs = as_pairs(&v).ok_or_else(|| unexpected("REPSHEET.GET"))?;
        let field = |name: &str| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| *v);
        let text = |name: &str| field(name).and_then(as_string).unwrap_or_default();
        let int = |name: &str| field(name).and_then(as_int).unwrap_or(0);
        Ok(Some(Decision {
            status: Status::parse(&text("status")).ok_or_else(|| unexpected("REPSHEET.GET"))?,
            reason: text("reason"),
            created: int("created"),
            expires: int("expires"),
            by: text("by"),
        }))
    }

    pub async fn check(&self, actors: &[&str]) -> Result<Verdict> {
        let v = self.query(redis::cmd("REPSHEET.CHECK").arg(actors)).await?;
        let a = as_array(&v)
            .filter(|a| a.len() == 3)
            .ok_or_else(|| unexpected("REPSHEET.CHECK"))?;
        Ok(Verdict {
            status: as_string(&a[0])
                .and_then(|s| Status::parse(&s))
                .ok_or_else(|| unexpected("REPSHEET.CHECK"))?,
            reason: as_string(&a[1]).unwrap_or_default(),
            actor: as_string(&a[2]).unwrap_or_default(),
        })
    }

    /// The whole store, read in pages so Valkey is never busy for long.
    ///
    /// Pages are not consistent with each other: the returned seq is the one
    /// of the first page, and replaying REPSHEET.CHANGES from it (as the
    /// mirror does next) repairs anything that changed while paging. If the
    /// dataset is flushed or replaced meanwhile, paging starts over.
    pub async fn snapshot(&self) -> Result<Snapshot> {
        const PAGE: u64 = 1000;
        let bad = || unexpected("REPSHEET.SNAPSHOT");
        'start: loop {
            let (mut cursor, mut first): (String, Option<(String, u64)>) = ("0".into(), None);
            let mut entries: std::collections::HashMap<String, Entry> =
                std::collections::HashMap::new();
            loop {
                let v = self
                    .query(
                        redis::cmd("REPSHEET.SNAPSHOT")
                            .arg("CURSOR")
                            .arg(&cursor)
                            .arg("COUNT")
                            .arg(PAGE),
                    )
                    .await?;
                let a = as_array(&v).filter(|a| a.len() == 4).ok_or_else(bad)?;
                let epoch = as_string(&a[0]).ok_or_else(bad)?;
                let seq = as_int(&a[1]).ok_or_else(bad)? as u64;
                match &first {
                    None => first = Some((epoch, seq)),
                    Some((e, _)) if *e != epoch => continue 'start,
                    Some(_) => {}
                }
                for e in as_array(&a[3]).ok_or_else(bad)? {
                    let entry = parse_entry(as_array(e).ok_or_else(bad)?).ok_or_else(bad)?;
                    entries.insert(entry.actor.clone(), entry);
                }
                cursor = as_string(&a[2]).ok_or_else(bad)?;
                if cursor == "0" {
                    let (epoch, seq) = first.ok_or_else(bad)?;
                    return Ok(Snapshot {
                        epoch,
                        seq,
                        entries: entries.into_values().collect(),
                    });
                }
            }
        }
    }

    pub async fn changes(&self, epoch: &str, seq: u64, count: u64) -> Result<Changes> {
        let v = self
            .query(
                redis::cmd("REPSHEET.CHANGES")
                    .arg(epoch)
                    .arg(seq)
                    .arg("COUNT")
                    .arg(count),
            )
            .await?;
        let bad = || unexpected("REPSHEET.CHANGES");
        let a = as_array(&v).ok_or_else(bad)?;
        match a.first().and_then(as_string).as_deref() {
            Some("RESYNC") => return Ok(Changes::Resync),
            Some("OK") if a.len() == 4 => {}
            _ => return Err(bad()),
        }
        let mut changes = Vec::new();
        for c in as_array(&a[3]).ok_or_else(bad)? {
            let c = as_array(c).filter(|c| c.len() == 6).ok_or_else(bad)?;
            let seq = as_int(&c[0]).ok_or_else(bad)? as u64;
            let op = as_string(&c[1]).ok_or_else(bad)?;
            let actor = as_string(&c[2]).ok_or_else(bad)?;
            let entry = if op == "set" {
                Some(parse_entry(&c[2..]).ok_or_else(bad)?)
            } else {
                None
            };
            changes.push((seq, entry, actor));
        }
        Ok(Changes::Ok {
            epoch: as_string(&a[1]).ok_or_else(bad)?,
            cursor: as_int(&a[2]).ok_or_else(bad)? as u64,
            changes,
        })
    }

    /// Changes newest first, starting below `before` (a sequence number).
    pub async fn history(&self, before: Option<u64>, count: usize) -> Result<Vec<Change>> {
        let end = match before {
            Some(seq) => format!("({seq}-0"),
            None => "+".to_string(),
        };
        let v = self
            .query(
                redis::cmd("XREVRANGE")
                    .arg(CHANGES_KEY)
                    .arg(end)
                    .arg("-")
                    .arg("COUNT")
                    .arg(count),
            )
            .await?;
        parse_stream(&v)
    }

    /// The most recent changes to one actor, scanning at most `scan` entries.
    pub async fn actor_history(
        &self,
        actor: &str,
        limit: usize,
        scan: usize,
    ) -> Result<Vec<Change>> {
        let mut found = Vec::new();
        let mut before = None;
        let mut scanned = 0;
        while scanned < scan && found.len() < limit {
            let page = self.history(before, 1000.min(scan - scanned)).await?;
            if page.is_empty() {
                break;
            }
            scanned += page.len();
            before = page.last().map(|c| c.seq);
            found.extend(page.into_iter().filter(|c| c.actor == actor));
        }
        found.truncate(limit);
        Ok(found)
    }

    pub async fn info(&self) -> Result<ServerInfo> {
        let module =
            as_string(&self.query(&redis::cmd("REPSHEET.VERSION")).await?).unwrap_or_default();
        let info =
            as_string(&self.query(redis::cmd("INFO").arg("server")).await?).unwrap_or_default();
        let field = |name: &str| {
            info.lines()
                .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')))
                .map(str::trim)
        };
        let server = match (field("valkey_version"), field("redis_version")) {
            (Some(v), _) => format!("Valkey {v}"),
            (None, Some(v)) => format!("Redis {v}"),
            _ => "unknown".into(),
        };
        let stream_len =
            as_int(&self.query(redis::cmd("XLEN").arg(CHANGES_KEY)).await?).unwrap_or(0);
        Ok(ServerInfo {
            server,
            module,
            stream_len,
        })
    }
}

/// [actor, status, reason, expires]
fn parse_entry(e: &[Value]) -> Option<Entry> {
    if e.len() != 4 {
        return None;
    }
    Some(Entry {
        actor: as_string(&e[0])?,
        status: Status::parse(&as_string(&e[1])?)?,
        reason: as_string(&e[2])?,
        expires: as_int(&e[3])?,
    })
}

fn parse_stream(v: &Value) -> Result<Vec<Change>> {
    let bad = || unexpected("XREVRANGE");
    let mut out = Vec::new();
    for item in as_array(v).ok_or_else(bad)? {
        let item = as_array(item).filter(|i| i.len() == 2).ok_or_else(bad)?;
        let id = as_string(&item[0]).ok_or_else(bad)?;
        let seq = id
            .split_once('-')
            .and_then(|(s, _)| s.parse().ok())
            .ok_or_else(bad)?;
        let fields = as_pairs(&item[1]).ok_or_else(bad)?;
        let text = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| as_string(v))
                .unwrap_or_default()
        };
        let int = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| as_int(v))
                .unwrap_or(0)
        };
        out.push(Change {
            seq,
            op: text("op"),
            actor: text("actor"),
            status: text("status"),
            reason: text("reason"),
            expires: int("expires"),
            by: text("by"),
            at: int("at"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulk(s: &str) -> Value {
        Value::BulkString(s.as_bytes().to_vec())
    }

    #[test]
    fn parses_stream_entries() {
        let v = Value::Array(vec![Value::Array(vec![
            bulk("7-0"),
            Value::Array(vec![
                bulk("op"),
                bulk("set"),
                bulk("actor"),
                bulk("ip:1.2.3.4"),
                bulk("status"),
                bulk("block"),
                bulk("reason"),
                bulk("r"),
                bulk("expires"),
                bulk("0"),
                bulk("by"),
                bulk("alice"),
                bulk("at"),
                bulk("1700000000000"),
            ]),
        ])]);
        let c = &parse_stream(&v).unwrap()[0];
        assert_eq!(
            (c.seq, c.op.as_str(), c.by.as_str(), c.at),
            (7, "set", "alice", 1_700_000_000_000)
        );
    }

    #[test]
    fn older_entries_without_by_or_at() {
        let v = Value::Array(vec![Value::Array(vec![
            bulk("3-0"),
            Value::Array(vec![
                bulk("op"),
                bulk("del"),
                bulk("actor"),
                bulk("ip:1.2.3.4"),
            ]),
        ])]);
        let c = &parse_stream(&v).unwrap()[0];
        assert_eq!((c.by.as_str(), c.at), ("", 0));
    }

    #[test]
    fn parses_entry() {
        let e =
            parse_entry(&[bulk("ip:10.0.0.0/8"), bulk("mark"), bulk(""), Value::Int(5)]).unwrap();
        assert_eq!(e.status, Status::Mark);
        assert!(parse_entry(&[bulk("x"), bulk("bogus"), bulk(""), Value::Int(0)]).is_none());
    }
}
