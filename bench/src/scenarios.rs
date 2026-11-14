//! What each scenario loads, how the variant nginx is configured, and the
//! requests sent. Baseline and variant always get the same requests; the
//! baseline has no Repsheet configuration at all.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::load::request;

pub const NAMES: &[(&str, &str)] = &[
    ("aa", "baseline against itself: the noise floor"),
    ("store-0", "repsheet on, empty store"),
    (
        "store-10k",
        "10k single-address decisions; 1% of requests hit one",
    ),
    ("store-100k", "100k single-address decisions; 1% hit"),
    ("store-1m", "1M single-address decisions; 1% hit"),
    (
        "networks",
        "decisions at every IPv4 /8-/32 and IPv6 /16-/128 length; v4 and v6 clients that miss them all",
    ),
    (
        "actors",
        "100k session decisions; repsheet_actor on a cookie and a header; 1% hit",
    ),
    (
        "sync",
        "100k decisions and 1,000 new decisions per second written during the run",
    ),
    (
        "bot-ua",
        "bot verifier on; browser User-Agents only (cost of recognizing claims)",
    ),
    (
        "bot-claims",
        "Googlebot claims from addresses in its published ranges (answered from ranges and cache)",
    ),
];

pub struct Scenario {
    /// False for "aa": the variant is the baseline.
    pub repsheet: bool,
    /// Commands run before nginx starts (decisions).
    pub preload: Vec<Vec<String>>,
    /// Decisions nginx must hold before measuring.
    pub decisions: usize,
    /// Inside http{} for the variant; {redis} and {dir} are substituted.
    pub http: String,
    pub requests: Vec<Vec<u8>>,
    /// New decisions per second written during each variant run.
    pub writes_per_sec: u32,
    /// Files written into the variant's directory: (name, contents).
    pub files: Vec<(String, String)>,
}

const POOL: usize = 4096;
const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
const BROWSERS: &[&str] = &[
    BROWSER,
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
];
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

/// Deterministic pseudo-random numbers (splitmix64).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The i-th distinct address in 10.0.0.0/8 (an odd multiplier permutes 2^24).
pub fn stored_v4(i: u64) -> Ipv4Addr {
    Ipv4Addr::from(0x0a00_0000 | ((i.wrapping_mul(2_654_435_761)) & 0x00ff_ffff) as u32)
}

/// An address in 100.64.0.0/10, never covered by any decision.
fn miss_v4(rng: &mut Rng) -> Ipv4Addr {
    Ipv4Addr::from(0x6440_0000 | (rng.next() as u32 & 0x003f_ffff))
}

/// An address in 2001:db8::/32, never covered by any decision.
fn miss_v6(rng: &mut Rng) -> Ipv6Addr {
    let low = ((rng.next() as u128) << 64) | rng.next() as u128;
    Ipv6Addr::from((0x2001_0db8u128 << 96) | (low & ((1u128 << 96) - 1)))
}

fn mark(actor: String) -> Vec<String> {
    vec![
        "REPSHEET.MARK".into(),
        actor,
        "REASON".into(),
        "bench".into(),
    ]
}

fn plain(addr: impl ToString, ua: &str) -> Vec<u8> {
    request("/", &[("X-Real-IP", &addr.to_string()), ("User-Agent", ua)])
}

fn store(n: u64) -> Scenario {
    let mut rng = Rng::new(1);
    let hits = (POOL / 100) as u64;
    let requests = (0..POOL as u64)
        .map(|i| {
            if i < hits && i < n {
                plain(stored_v4(i * (n / hits.max(1)).max(1) % n.max(1)), BROWSER)
            } else {
                plain(miss_v4(&mut rng), BROWSER)
            }
        })
        .collect();
    Scenario {
        repsheet: true,
        preload: (0..n).map(|i| mark(stored_v4(i).to_string())).collect(),
        decisions: n as usize,
        http: String::new(),
        requests,
        writes_per_sec: 0,
        files: vec![],
    }
}

fn networks() -> Scenario {
    let mut rng = Rng::new(2);
    let mut preload = vec![];
    // IPv4: every prefix length /8../32, inside 10.0.0.0/8.
    for len in 8..=32u32 {
        let count = 1u64 << (len - 8).min(9); // up to 512 per length
        for _ in 0..count {
            let host_bits = 32 - len;
            let addr = (0x0a00_0000 | (rng.next() as u32 & 0x00ff_ffff)) >> host_bits << host_bits;
            let addr = if len == 8 { 0x0a00_0000 } else { addr };
            preload.push(mark(format!("{}/{len}", Ipv4Addr::from(addr))));
        }
    }
    // IPv6: every prefix length /16../128, inside fd00::/8.
    for len in 16..=128u32 {
        for _ in 0..64 {
            let raw = (0xfdu128 << 120) | (((rng.next() as u128) << 64 | rng.next() as u128) >> 8);
            let addr = if len == 128 {
                raw
            } else {
                raw >> (128 - len) << (128 - len)
            };
            preload.push(mark(format!("{}/{len}", Ipv6Addr::from(addr))));
        }
    }
    let requests = (0..POOL)
        .map(|i| {
            if i % 2 == 0 {
                plain(miss_v4(&mut rng), BROWSER)
            } else {
                plain(miss_v6(&mut rng), BROWSER)
            }
        })
        .collect();
    Scenario {
        repsheet: true,
        // Duplicate networks collapse into one decision; wait for most of them.
        decisions: preload.len() * 9 / 10,
        preload,
        http: String::new(),
        requests,
        writes_per_sec: 0,
        files: vec![],
    }
}

fn actors() -> Scenario {
    let mut rng = Rng::new(3);
    let n = 100_000u64;
    let session = |i: u64| format!("{:016x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let requests = (0..POOL as u64)
        .map(|i| {
            let s = if i % 100 == 0 {
                session(i % n)
            } else {
                format!("{:016x}", rng.next())
            };
            let cookie = format!("session={s}; theme=dark");
            let key = format!("k-{:x}", rng.next());
            request(
                "/",
                &[
                    ("X-Real-IP", &miss_v4(&mut rng).to_string()),
                    ("User-Agent", BROWSER),
                    ("Cookie", &cookie),
                    ("X-Api-Key", &key),
                ],
            )
        })
        .collect();
    Scenario {
        repsheet: true,
        preload: (0..n)
            .map(|i| mark(format!("session:{}", session(i))))
            .collect(),
        decisions: n as usize,
        http:
            "repsheet_actor session $cookie_session;\n    repsheet_actor api_key $http_x_api_key;"
                .into(),
        requests,
        writes_per_sec: 0,
        files: vec![],
    }
}

fn bot_ua() -> Scenario {
    let mut rng = Rng::new(4);
    Scenario {
        repsheet: true,
        preload: vec![],
        decisions: 0,
        http: "resolver 127.0.0.1:1;\n    repsheet_bot_verifier on;".into(),
        requests: (0..POOL)
            .map(|i| plain(miss_v4(&mut rng), BROWSERS[i % BROWSERS.len()]))
            .collect(),
        writes_per_sec: 0,
        files: vec![],
    }
}

fn bot_claims() -> Scenario {
    // 66.249.64.0/19: 8192 addresses, all in the "published" range.
    let requests = (0..POOL as u32)
        .map(|i| plain(Ipv4Addr::from(0x42f9_4000 | (i * 2 + 1)), GOOGLEBOT))
        .collect();
    Scenario {
        repsheet: true,
        preload: vec![],
        decisions: 0,
        http: "resolver 127.0.0.1:1;\n    repsheet_bot_verifier on;\n    \
               repsheet_bot_verifier_ranges google {dir}/google.json;"
            .into(),
        requests,
        writes_per_sec: 0,
        files: vec![(
            "google.json".into(),
            r#"{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"},{"ipv6Prefix":"2001:4860:4801::/48"}]}"#.into(),
        )],
    }
}

pub fn build(name: &str) -> Option<Scenario> {
    Some(match name {
        "aa" => Scenario {
            repsheet: false,
            ..store(0)
        },
        "store-0" => store(0),
        "store-10k" => store(10_000),
        "store-100k" => store(100_000),
        "store-1m" => Scenario {
            // A 1M-decision REPSHEET.SNAPSHOT takes about 1s in Valkey, longer
            // than the default repsheet_redis_timeout, so sync would never finish.
            // The longer timeout lets this measure lookups at 1M decisions.
            http: "repsheet_redis_timeout 10s;".into(),
            ..store(1_000_000)
        },
        "networks" => networks(),
        "actors" => actors(),
        "sync" => Scenario {
            writes_per_sec: 1000,
            ..store(100_000)
        },
        "bot-ua" => bot_ua(),
        "bot-claims" => bot_claims(),
        _ => return None,
    })
}

impl Scenario {
    /// The variant's http{} additions.
    pub fn variant_http(&self, redis_port: u16, dir: &Path) -> String {
        if !self.repsheet {
            return String::new();
        }
        let extra = self.http.replace("{dir}", &dir.display().to_string());
        format!(
            "repsheet_redis 127.0.0.1:{redis_port};\n    repsheet_zone_size 512m;\n    repsheet on;\n    {extra}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_addresses_are_distinct() {
        let set: std::collections::HashSet<_> = (0..200_000).map(stored_v4).collect();
        assert_eq!(set.len(), 200_000);
        assert!(set.iter().all(|a| a.octets()[0] == 10));
    }

    #[test]
    fn misses_stay_outside_decisions() {
        let mut rng = Rng::new(9);
        for _ in 0..1000 {
            let a = miss_v4(&mut rng).octets();
            assert_eq!(a[0], 100);
            assert!((64..128).contains(&a[1]));
            assert!(miss_v6(&mut rng).to_string().starts_with("2001:db8:"));
        }
    }

    #[test]
    fn every_scenario_builds() {
        for (name, _) in NAMES {
            let s = build(name).unwrap();
            assert_eq!(s.requests.len(), POOL, "{name}");
        }
    }

    #[test]
    fn store_hits_are_one_percent() {
        let s = build("store-10k").unwrap();
        let hits = s
            .requests
            .iter()
            .filter(|r| String::from_utf8_lossy(r).contains("X-Real-IP: 10."))
            .count();
        assert_eq!(hits, POOL / 100);
    }
}
