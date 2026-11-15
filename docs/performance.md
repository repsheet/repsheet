# Performance

`bench/` holds `repsheet-bench`, which measures what Repsheet adds to the cost
of serving a request. Each scenario runs two nginx servers with identical
configuration except that one has no Repsheet at all, sends both the same
requests in alternating runs, and compares the nginx worker's **CPU time per
request** (from `/proc/<pid>/schedstat`), along with throughput and client
latency. An "aa" scenario runs the baseline against itself to show the noise
floor.

```sh
make bench                                   # full suite (~13 min), results in bench/results/
make bench BENCH_ARGS="-s store-1m -s actors"
make bench BENCH_ARGS="--compare bench/results/<earlier>.json"
make bench-quick                             # every scenario, briefly: checks it all works
bench/target/release/repsheet-bench list     # what each scenario does
```

It uses an optimized nginx (`script/bootstrap bench`: `-O2`, no debug
logging) with one worker pinned to CPU 0 and the load generator on the other
CPUs. Requests are 64 keep-alive connections fetching a 6-byte file, which
makes Repsheet's share as large as it can be; real requests cost more, so the
same microseconds are a smaller fraction.

Results below are from one full run of each mode on a 16-CPU Linux laptop
(nginx 1.30.6, Valkey 9.1.3), November 2026. Expect different absolute
numbers on other hardware; the differences between the columns are what
matter.

## CPU per request (as fast as possible)

`make bench`. Median of three 10-second runs per side; noise floor ±2.3%.

| Scenario | nginx alone | with Repsheet | added | throughput alone → with |
|----------|------------:|--------------:|------:|------------------------:|
| empty store | 3.50 µs | 3.59 µs | +0.09 µs (noise) | 231k → 226k req/s |
| 10k decisions | 3.51 µs | 3.73 µs | +0.22 µs | 229k → 220k |
| 100k decisions | 3.51 µs | 3.92 µs | +0.41 µs | 231k → 211k |
| 1M decisions | 3.54 µs | 4.03 µs | +0.49 µs | 228k → 204k |
| 100k decisions, 1,000 changes/s syncing | 3.49 µs | 3.95 µs | +0.46 µs | 232k → 209k |
| cookie and header actors, 100k decisions | 3.58 µs | 4.36 µs | +0.78 µs | 226k → 189k |
| decisions at every IPv4 and IPv6 prefix length | 3.64 µs | 4.76 µs | +1.12 µs | 223k → 175k |
| bot verifier, browser traffic | 3.56 µs | 3.91 µs | +0.34 µs | 228k → 211k |
| bot verifier, Googlebot from its ranges | 3.53 µs | 3.90 µs | +0.37 µs | 230k → 211k |

## Latency (fixed load)

`make bench BENCH_ARGS="--rate 50000"`: 50,000 requests/s, well below
capacity, measured from when each request was due. Microseconds, nginx alone
/ with Repsheet, median of three runs.

| Scenario | p50 | p75 | p95 | p99 | p99.99 |
|----------|----:|----:|----:|----:|-------:|
| empty store | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 39 | 1672 / 1016 |
| 10k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 39 / 40 | 859 / 1283 |
| 100k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 40 | 1160 / 967 |
| 1M decisions | 18 / 18 | 22 / 22 | 29 / 29 | 58 / 43 | 1965 / 1966 |
| 100k decisions, 1,000 changes/s syncing | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 41 | 1787 / 966 |
| cookie and header actors, 100k decisions | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 41 | 2167 / 1290 |
| decisions at every IPv4 and IPv6 prefix length | 18 / 19 | 22 / 23 | 29 / 30 | 41 / 41 | 1611 / 1133 |
| bot verifier, browser traffic | 18 / 18 | 22 / 22 | 29 / 29 | 40 / 40 | 1518 / 1098 |
| bot verifier, Googlebot from its ranges | 18 / 18 | 22 / 22 | 29 / 29 | 54 / 41 | 2025 / 1841 |

The p99.99 column (about 1-2 ms on both sides, with single runs up to 10 ms
either way) is scheduling noise on the test machine, not Repsheet: the A/A
scenario, which compares nginx alone against itself, varies just as much.

## What this means

* **Repsheet adds well under a microsecond of CPU per request** in every
  realistic case, and nothing measurable to latency from p50 to p99.
* **Lookups grow slowly with the store**: about half a microsecond at a
  million decisions. Sync churn adds nothing beyond that.
* **Each prefix length in use costs about 15 ns**: a per-length filter
  answers most lookups without touching the store. Most deployments use a
  handful of lengths; the worst case above uses all 138.
* **The bot verifier's User-Agent check** is one JIT-compiled match per
  request (about 130 ns for a browser User-Agent).
* **Large stores sync in pages**: nginx loads 1M decisions in about 2
  seconds, a thousand at a time, and no page keeps Valkey busy for more than
  about 2 ms.
* **Housekeeping runs in slices** (freeing expired decisions, removing what a
  new snapshot no longer contains, refreshing the prefix filters): about
  10,000 entries every 100 ms at a million decisions, so the store's lock is
  never held for long.
