//! Results: per-run numbers, medians, the table, JSON and comparisons.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub requests: u64,
    pub errors: u64,
    pub non_2xx: u64,
    pub seconds: f64,
    pub cpu_ns: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
}

impl Run {
    pub fn cpu_us_per_request(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.cpu_ns as f64 / 1000.0 / self.requests as f64
        }
    }
    pub fn throughput(&self) -> f64 {
        self.requests as f64 / self.seconds
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Side {
    pub runs: Vec<Run>,
    pub cpu_us_per_request: f64,
    pub throughput: f64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
}

fn median(mut v: Vec<f64>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

impl Side {
    pub fn from_runs(runs: Vec<Run>) -> Side {
        Side {
            cpu_us_per_request: median(runs.iter().map(Run::cpu_us_per_request).collect()),
            throughput: median(runs.iter().map(Run::throughput).collect()),
            p50_us: median(runs.iter().map(|r| r.p50_us as f64).collect()) as u64,
            p99_us: median(runs.iter().map(|r| r.p99_us as f64).collect()) as u64,
            p999_us: median(runs.iter().map(|r| r.p999_us as f64).collect()) as u64,
            runs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub name: String,
    pub about: String,
    pub decisions: usize,
    pub baseline: Side,
    pub repsheet: Side,
    /// Set when the scenario could not be measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
}

impl ScenarioResult {
    pub fn overhead_us(&self) -> f64 {
        self.repsheet.cpu_us_per_request - self.baseline.cpu_us_per_request
    }
    pub fn overhead_pct(&self) -> f64 {
        if self.baseline.cpu_us_per_request == 0.0 {
            0.0
        } else {
            100.0 * self.overhead_us() / self.baseline.cpu_us_per_request
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub created: String,
    pub host: String,
    pub settings: Settings,
    pub scenarios: Vec<ScenarioResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub duration_s: f64,
    pub connections: usize,
    pub rate: Option<f64>,
    pub repeat: usize,
    pub pinned: bool,
    pub nginx: String,
}

impl Report {
    /// The A/A scenario's |overhead|, if it ran: differences below it are noise.
    pub fn noise_pct(&self) -> Option<f64> {
        self.scenarios
            .iter()
            .find(|s| s.name == "aa")
            .map(|s| s.overhead_pct().abs())
    }

    pub fn table(&self) -> String {
        let noise = self.noise_pct();
        let mut out = String::new();
        out.push_str(&format!(
            "{:<12} {:>9} {:>9} {:>9} {:>8}   {:>9} {:>9}   {:>8} {:>8}\n",
            "scenario",
            "base µs",
            "rs µs",
            "+µs/req",
            "+cpu",
            "base r/s",
            "rs r/s",
            "base p99",
            "rs p99"
        ));
        out.push_str(&format!("{}\n", "-".repeat(98)));
        for s in &self.scenarios {
            if let Some(why) = &s.failed {
                out.push_str(&format!("{:<12} FAILED: {why}\n", s.name));
                continue;
            }
            let pct = s.overhead_pct();
            let flag = match noise {
                Some(n) if s.name != "aa" && pct.abs() <= n => " ~",
                _ => "",
            };
            out.push_str(&format!(
                "{:<12} {:>9.2} {:>9.2} {:>+9.2} {:>+7.1}%{:<2} {:>9.0} {:>9.0}   {:>6}µs {:>6}µs\n",
                s.name,
                s.baseline.cpu_us_per_request,
                s.repsheet.cpu_us_per_request,
                s.overhead_us(),
                pct,
                flag,
                s.baseline.throughput,
                s.repsheet.throughput,
                s.baseline.p99_us,
                s.repsheet.p99_us,
            ));
        }
        out.push_str(
            "\nµs = nginx worker CPU time per request (median of runs). +cpu = Repsheet's share on top of\n\
             serving the request. r/s = requests per second. p99 = latency seen by the client.\n",
        );
        if let Some(n) = noise {
            out.push_str(&format!(
                "~ = within the noise floor measured by \"aa\" (±{n:.1}%).\n"
            ));
        }
        out
    }

    pub fn compare(&self, old: &Report) -> String {
        let mut out = format!("\nCompared with {} ({}):\n", old.created, old.host);
        out.push_str(&format!(
            "{:<12} {:>12} {:>12} {:>10}\n",
            "scenario", "old +µs/req", "new +µs/req", "change"
        ));
        for s in &self.scenarios {
            if let Some(o) = old
                .scenarios
                .iter()
                .find(|o| o.name == s.name && o.failed.is_none())
            {
                if s.failed.is_some() {
                    continue;
                }
                out.push_str(&format!(
                    "{:<12} {:>+12.2} {:>+12.2} {:>+10.2}\n",
                    s.name,
                    o.overhead_us(),
                    s.overhead_us(),
                    s.overhead_us() - o.overhead_us()
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(requests: u64, cpu_ns: u64) -> Run {
        Run {
            requests,
            errors: 0,
            non_2xx: 0,
            seconds: 1.0,
            cpu_ns,
            p50_us: 1,
            p90_us: 2,
            p99_us: 3,
            p999_us: 4,
        }
    }

    #[test]
    fn medians() {
        assert_eq!(median(vec![3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(vec![4.0, 1.0, 2.0, 3.0]), 2.5);
        assert_eq!(median(vec![]), 0.0);
    }

    #[test]
    fn overhead() {
        let s = ScenarioResult {
            name: "x".into(),
            about: String::new(),
            decisions: 0,
            baseline: Side::from_runs(vec![
                run(1000, 10_000_000),
                run(1000, 12_000_000),
                run(1000, 11_000_000),
            ]),
            repsheet: Side::from_runs(vec![run(1000, 12_100_000)]),
            failed: None,
        };
        assert!((s.baseline.cpu_us_per_request - 11.0).abs() < 1e-9);
        assert!((s.overhead_us() - 1.1).abs() < 1e-9);
        assert!((s.overhead_pct() - 10.0).abs() < 1e-9);
    }
}
