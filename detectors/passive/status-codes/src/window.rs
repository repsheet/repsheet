//! Counting events per address over a sliding window.
//!
//! The window is split into buckets; an address keeps one count per bucket,
//! so its total covers the last `window` (to within one bucket) and memory
//! per address is fixed.

use std::collections::HashMap;

pub struct Counter {
    head: i64,
    counts: Vec<u32>,
    total: u32,
}

pub enum Outcome {
    /// Counted; the address is below the threshold.
    Counted,
    /// The address reached the threshold; its count is reset.
    Tripped(u32),
    /// The event is older than the window.
    Stale,
    /// The table is full and this is a new address.
    Untracked,
}

pub struct Windows {
    bucket_ms: i64,
    buckets: usize,
    threshold: u32,
    max_tracked: usize,
    table: HashMap<String, Counter>,
}

impl Windows {
    pub fn new(window_ms: i64, buckets: usize, threshold: u32, max_tracked: usize) -> Windows {
        let buckets = buckets.max(1);
        Windows {
            bucket_ms: (window_ms / buckets as i64).max(1),
            buckets,
            threshold: threshold.max(1),
            max_tracked,
            table: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Count one event for `addr` that happened at `time_ms`, as of `now_ms`.
    /// Events older than the window are stale; events from the future (a
    /// clock ahead of ours) count as now.
    pub fn record(&mut self, addr: &str, time_ms: i64, now_ms: i64) -> Outcome {
        if time_ms <= now_ms - self.bucket_ms * self.buckets as i64 {
            return Outcome::Stale;
        }
        let bucket = time_ms.min(now_ms).div_euclid(self.bucket_ms);
        let n = self.buckets;
        if !self.table.contains_key(addr) {
            if self.table.len() >= self.max_tracked {
                return Outcome::Untracked;
            }
            self.table.insert(
                addr.to_string(),
                Counter {
                    head: bucket,
                    counts: vec![0; n],
                    total: 0,
                },
            );
        }
        let c = self.table.get_mut(addr).expect("inserted above");

        if bucket > c.head {
            // Move the window forward, emptying the buckets it leaves behind.
            let steps = (bucket - c.head).min(n as i64);
            for i in 1..=steps {
                let slot = (c.head + i).rem_euclid(n as i64) as usize;
                c.total -= c.counts[slot];
                c.counts[slot] = 0;
            }
            c.head = bucket;
        } else if bucket <= c.head - n as i64 {
            return Outcome::Stale;
        }
        c.counts[bucket.rem_euclid(n as i64) as usize] += 1;
        c.total += 1;

        if c.total >= self.threshold {
            let total = c.total;
            self.table.remove(addr);
            return Outcome::Tripped(total);
        }
        Outcome::Counted
    }

    /// Forget addresses with nothing in the window ending at `now_ms`.
    pub fn evict(&mut self, now_ms: i64) -> usize {
        let oldest = now_ms.div_euclid(self.bucket_ms) - self.buckets as i64;
        let before = self.table.len();
        self.table.retain(|_, c| c.head > oldest);
        before - self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trips(o: Outcome) -> Option<u32> {
        match o {
            Outcome::Tripped(n) => Some(n),
            _ => None,
        }
    }

    #[test]
    fn trips_at_the_threshold_and_resets() {
        let mut w = Windows::new(60_000, 12, 3, 100);
        assert_eq!(trips(w.record("a", 1_000, 1_000)), None);
        assert_eq!(trips(w.record("a", 2_000, 2_000)), None);
        assert_eq!(trips(w.record("a", 3_000, 3_000)), Some(3));
        assert_eq!(w.len(), 0);
        assert_eq!(trips(w.record("a", 4_000, 4_000)), None);
    }

    #[test]
    fn addresses_are_counted_separately() {
        let mut w = Windows::new(60_000, 12, 2, 100);
        assert_eq!(trips(w.record("a", 1_000, 1_000)), None);
        assert_eq!(trips(w.record("b", 1_000, 1_000)), None);
        assert_eq!(trips(w.record("b", 1_500, 1_500)), Some(2));
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn old_events_slide_out() {
        let mut w = Windows::new(60_000, 12, 3, 100);
        w.record("a", 0, 0);
        w.record("a", 1_000, 1_000);
        // 70s later both have left the window.
        assert_eq!(trips(w.record("a", 71_000, 71_000)), None);
        assert_eq!(trips(w.record("a", 72_000, 72_000)), None);
        assert_eq!(trips(w.record("a", 73_000, 73_000)), Some(3));
    }

    #[test]
    fn partially_slid_window_keeps_recent_events() {
        let mut w = Windows::new(60_000, 12, 3, 100);
        w.record("a", 0, 0); // bucket 0
        w.record("a", 30_000, 30_000); // bucket 6
        // At 62s bucket 0 has left; bucket 6 is still in.
        assert_eq!(trips(w.record("a", 62_000, 62_000)), None);
        assert_eq!(trips(w.record("a", 63_000, 63_000)), Some(3));
    }

    #[test]
    fn late_events_count_if_in_the_window() {
        let mut w = Windows::new(60_000, 12, 3, 100);
        w.record("a", 50_000, 50_000);
        w.record("a", 20_000, 50_000); // earlier, still within 60s
        assert!(matches!(w.record("a", -20_000, 50_000), Outcome::Stale));
        assert_eq!(trips(w.record("a", 51_000, 51_000)), Some(3));
    }

    #[test]
    fn a_stale_backlog_never_trips() {
        let mut w = Windows::new(60_000, 12, 2, 100);
        // Ten minutes old when it arrives (an analyzer restart, say).
        for t in [0, 1_000, 2_000] {
            assert!(matches!(w.record("a", t, 600_000), Outcome::Stale));
        }
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn future_timestamps_count_as_now() {
        let mut w = Windows::new(60_000, 12, 3, 100);
        w.record("a", 500_000, 0); // a clock far ahead
        w.record("a", 1_000, 1_000);
        assert_eq!(trips(w.record("a", 2_000, 2_000)), Some(3));
    }

    #[test]
    fn eviction_and_the_cap() {
        let mut w = Windows::new(60_000, 12, 10, 2);
        w.record("a", 0, 0);
        w.record("b", 50_000, 50_000);
        assert!(matches!(w.record("c", 50_000, 50_000), Outcome::Untracked));
        assert_eq!(w.evict(70_000), 1); // a is idle for over a window
        assert_eq!(w.len(), 1);
        assert!(matches!(w.record("c", 70_000, 70_000), Outcome::Counted));
    }
}
