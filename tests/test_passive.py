"""The status-codes passive detector: nginx -> repsheet-collector ->
repsheet-status-codes -> Valkey -> nginx."""

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import requests

from conftest import ROOT, free_port, metrics, wait_for

# Must match repsheet_event::NGINX_LOG_FORMAT.
LOG_FORMAT = (
    """log_format repsheet_events escape=json '{"time":$msec,"addr":"$remote_addr","status":$status,"""
    """"method":"$request_method","host":"$host","uri":"$uri","ua":"$http_user_agent","""
    """"repsheet":"$repsheet_status"}';"""
)

CONF = """
    repsheet_redis {redis};
    repsheet_sync_interval 100ms;
    repsheet_redis_timeout 500ms;
    repsheet on;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;
    %(log_format)s
    server {
        listen 127.0.0.1:{port};
        access_log %(events)s repsheet_events;
        location / { }
        location = /notmodified { return 304; }
        location = /moved { return 301 /; }
        location = /broken { return 503; }
        location = /metrics {
            repsheet off;
            access_log off;
            repsheet_metrics;
        }
    }
"""


def binary(name):
    env = os.environ.get("REPSHEET_" + name.upper().replace("-", "_"))
    if env:
        return env
    built = [p for p in (ROOT / "detectors" / "passive" / "target" / profile / f"repsheet-{name}"
                         for profile in ("release", "debug")) if p.exists()]
    if not built:
        pytest.skip("passive detectors not built; run make passive")
    return str(max(built, key=lambda p: p.stat().st_mtime))


class Proc:
    """A running collector or analyzer, with its metrics endpoint."""

    def __init__(self, tmp, name, args, metrics_port=None):
        self.name, self.args = name, list(args)
        self.metrics_port = metrics_port or free_port()
        self.log_path = Path(tempfile.mkdtemp(dir=tmp)) / f"{name}.log"
        self.start()

    def start(self):
        self.log = open(self.log_path, "a")
        self.proc = subprocess.Popen(
            [binary(self.name), *self.args, "--metrics", f"127.0.0.1:{self.metrics_port}"],
            stdout=self.log, stderr=subprocess.STDOUT,
        )
        wait_for(self.healthy, message=f"{self.name} to start; log: {self.log_path}")

    def healthy(self):
        try:
            return requests.get(f"http://127.0.0.1:{self.metrics_port}/healthz", timeout=1).ok
        except requests.ConnectionError:
            return False

    def metrics(self):
        out = {}
        text = requests.get(f"http://127.0.0.1:{self.metrics_port}/metrics", timeout=2).text
        for line in text.splitlines():
            if line and not line.startswith("#"):
                key, value = line.rsplit(" ", 1)
                out[key] = float(value)
        return out

    def metric(self, name):
        return self.metrics().get(name, 0)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.log.close()
        text = self.log_path.read_text()
        assert "panicked" not in text, text[-4000:]


class Rig:
    """Analyzer + any number of nginx instances, each with a collector."""

    def __init__(self, nginx_factory, server, tmp):
        self.nginx_factory, self.server, self.tmp = nginx_factory, server, tmp
        self.procs = []
        self.analyzer = None
        self.analyzer_port = free_port()

    def start_analyzer(self, *args, threshold=5, window="60s"):
        self.analyzer = Proc(self.tmp, "status-codes", [
            "--listen", f"127.0.0.1:{self.analyzer_port}",
            "--redis", f"redis://127.0.0.1:{self.server.port}",
            "--threshold", str(threshold), "--window", window, "--ttl", "600", *args,
        ])
        self.procs.append(self.analyzer)
        return self.analyzer

    def add_nginx(self):
        events = Path(tempfile.mkdtemp(dir=self.tmp)) / "events.log"
        n = self.nginx_factory(CONF % {"log_format": LOG_FORMAT, "events": events})
        wait_for(lambda: metrics(n).get("repsheet_sync_up") == 1, message="sync")
        n.events = events
        n.collector = Proc(self.tmp, "collector", [
            "--file", str(events), "--forward", f"127.0.0.1:{self.analyzer_port}", "--poll-ms", "20",
        ])
        self.procs.append(n.collector)
        wait_for(lambda: n.collector.metric(
            f'repsheet_collector_connected{{analyzer="127.0.0.1:{self.analyzer_port}"}}') == 1,
            message="collector to connect")
        return n

    def stop(self):
        for p in self.procs:
            p.stop()


@pytest.fixture
def rig(nginx_factory, server, r, tmp_path):
    rig = Rig(nginx_factory, server, tmp_path)
    yield rig
    rig.stop()


def hit(n, addr, path="/missing", count=1, **headers):
    for _ in range(count):
        n.get(path, headers={"X-Real-IP": addr, **headers}, allow_redirects=False)


def decision(r, actor):
    reply = r.execute_command("REPSHEET.GET", actor)
    if isinstance(reply, list):
        reply = dict(zip(reply[::2], reply[1::2]))
    return reply


def counted(rig, n):
    wait_for(lambda: rig.analyzer.metric("repsheet_status_codes_counted_total") == n,
             message=f"{n} counted events")


def events_seen(rig, n):
    wait_for(lambda: rig.analyzer.metric("repsheet_status_codes_events_total") == n,
             message=f"{n} events")


class TestStatusCodes:
    def test_blocks_after_threshold(self, rig, r):
        rig.start_analyzer(threshold=5)
        n = rig.add_nginx()
        hit(n, "10.1.0.1", count=5)
        d = wait_for(lambda: decision(r, "10.1.0.1"), message="decision")
        assert d["status"] == "block"
        assert d["by"] == "status-codes"
        assert d["reason"] == "5 responses with status 400-599 in 1m"
        remaining = int(d["expires"]) - time.time() * 1000  # --ttl 600
        assert 590_000 < remaining <= 600_000
        # nginx enforces it.
        wait_for(lambda: n.get("/", headers={"X-Real-IP": "10.1.0.1"}).status_code == 403,
                 message="nginx to block")
        assert n.get("/", headers={"X-Real-IP": "10.1.0.2"}).status_code == 200
        assert rig.analyzer.metric('repsheet_status_codes_decisions_total{action="block"}') == 1

    def test_below_threshold_is_not_blocked(self, rig, r):
        rig.start_analyzer(threshold=5)
        n = rig.add_nginx()
        hit(n, "10.1.0.3", count=4)
        counted(rig, 4)
        time.sleep(0.3)
        assert decision(r, "10.1.0.3") is None

    def test_successes_and_redirects_do_not_count_by_default(self, rig, r):
        rig.start_analyzer(threshold=3)
        n = rig.add_nginx()
        hit(n, "10.1.0.4", "/", count=3)
        hit(n, "10.1.0.4", "/notmodified", count=3)
        hit(n, "10.1.0.4", "/moved", count=3)
        events_seen(rig, 9)
        assert rig.analyzer.metric("repsheet_status_codes_counted_total") == 0
        assert decision(r, "10.1.0.4") is None
        hit(n, "10.1.0.4", "/broken", count=3)  # 5xx counts
        wait_for(lambda: decision(r, "10.1.0.4"), message="decision")

    def test_everything_but_200(self, rig, r):
        rig.start_analyzer("--statuses", "100-199,201-599", threshold=3)
        n = rig.add_nginx()
        hit(n, "10.1.0.5", "/", count=5)
        hit(n, "10.1.0.5", "/notmodified", count=3)
        d = wait_for(lambda: decision(r, "10.1.0.5"), message="decision")
        assert d["reason"] == "3 responses with status 100-199,201-599 in 1m"

    def test_mark_action(self, rig, r):
        rig.start_analyzer("--action", "mark", "--name", "error-burst", threshold=2)
        n = rig.add_nginx()
        hit(n, "10.1.0.6", count=2)
        d = wait_for(lambda: decision(r, "10.1.0.6"), message="decision")
        assert (d["status"], d["by"]) == ("mark", "error-burst")

    def test_repsheet_blocks_and_allows_do_not_count(self, rig, r):
        rig.start_analyzer(threshold=3)
        n = rig.add_nginx()
        r.execute_command("REPSHEET.BLOCK", "10.1.0.7", "REASON", "manual", "BY", "ops")
        r.execute_command("REPSHEET.ALLOW", "10.1.0.8", "BY", "ops")
        wait_for(lambda: n.get("/", headers={"X-Real-IP": "10.1.0.7"}).status_code == 403,
                 message="block to sync")
        hit(n, "10.1.0.7", count=5)  # Repsheet's own 403s
        hit(n, "10.1.0.8", count=5)  # allowed: 404s, but trusted
        wait_for(lambda: rig.analyzer.metric("repsheet_status_codes_skipped_total") >= 10,
                 message="skipped events")
        assert rig.analyzer.metric("repsheet_status_codes_counted_total") == 0
        assert decision(r, "10.1.0.7")["by"] == "ops"  # not overwritten
        assert decision(r, "10.1.0.8")["status"] == "allow"

    def test_window_expiry(self, rig, r):
        rig.start_analyzer("--buckets", "4", threshold=3, window="2s")
        n = rig.add_nginx()
        hit(n, "10.1.0.9", count=2)
        counted(rig, 2)
        time.sleep(2.6)
        hit(n, "10.1.0.9", count=2)
        counted(rig, 4)
        time.sleep(0.3)
        assert decision(r, "10.1.0.9") is None
        hit(n, "10.1.0.9")
        wait_for(lambda: decision(r, "10.1.0.9"), message="decision")

    def test_ipv6_addresses(self, rig, r):
        rig.start_analyzer(threshold=3)
        n = rig.add_nginx()
        hit(n, "2001:db8::7", count=3)
        d = wait_for(lambda: decision(r, "2001:db8::7"), message="decision")
        assert d["status"] == "block"

    def test_follows_log_rotation(self, rig, r):
        rig.start_analyzer(threshold=4)
        n = rig.add_nginx()
        hit(n, "10.1.1.1", count=2)
        counted(rig, 2)
        n.events.rename(n.events.with_suffix(".log.1"))
        hit(n, "10.1.1.1")  # still written to the renamed file
        n.proc.send_signal(10)  # SIGUSR1: reopen logs
        wait_for(n.events.exists, message="nginx to reopen the log")
        hit(n, "10.1.1.1")
        wait_for(lambda: decision(r, "10.1.1.1"), message="decision")
        wait_for(lambda: n.collector.metric("repsheet_collector_rotations_total") == 1,
                 message="rotation metric")

    def test_collector_buffers_while_analyzer_is_down(self, rig, r):
        analyzer = rig.start_analyzer(threshold=4)
        n = rig.add_nginx()
        analyzer.stop()
        hit(n, "10.1.1.2", count=4)
        key = f'repsheet_collector_queue_events{{analyzer="127.0.0.1:{rig.analyzer_port}"}}'
        wait_for(lambda: n.collector.metric(key) >= 1, message="events to queue")
        analyzer.start()
        wait_for(lambda: decision(r, "10.1.1.2"), timeout=15, message="decision after restart")
        assert n.collector.metric(key) == 0

    def test_counts_from_several_nginx_combine(self, rig, r):
        rig.start_analyzer(threshold=4)
        a, b = rig.add_nginx(), rig.add_nginx()
        hit(a, "10.1.1.3", count=2)
        hit(b, "10.1.1.3", count=2)
        wait_for(lambda: decision(r, "10.1.1.3"), message="decision")
        assert rig.analyzer.metric("repsheet_status_codes_collectors") == 2

    def test_collector_skips_lines_that_are_not_events(self, rig, r):
        rig.start_analyzer(threshold=2)
        n = rig.add_nginx()
        with open(n.events, "a") as f:
            f.write("garbage\n")
            f.write('{"time":1,"addr":"not-an-ip","status":404}\n')
        wait_for(lambda: n.collector.metric("repsheet_collector_parse_errors_total") == 2,
                 message="parse errors")
        hit(n, "10.1.1.4", count=2)
        wait_for(lambda: decision(r, "10.1.1.4"), message="decision")
        m = n.collector.metrics()
        assert m["repsheet_collector_lines_total"] == 4
        assert m[f'repsheet_collector_events_forwarded_total{{analyzer="127.0.0.1:{rig.analyzer_port}"}}'] == 2

    def test_old_events_do_not_count(self, rig, r):
        rig.start_analyzer(threshold=2)
        n = rig.add_nginx()
        old = time.time() - 3600
        with open(n.events, "a") as f:
            for i in range(5):
                f.write(f'{{"time":{old + i:.3f},"addr":"10.1.1.5","status":404,"repsheet":""}}\n')
        wait_for(lambda: rig.analyzer.metric("repsheet_status_codes_stale_total") == 5,
                 message="stale events")
        assert decision(r, "10.1.1.5") is None

    def test_print_log_format_matches(self):
        out = subprocess.run([binary("collector"), "--print-log-format"], capture_output=True,
                             text=True, check=True).stdout.strip()
        assert out == LOG_FORMAT

    def test_bad_flags_are_rejected(self):
        for flags in (["--statuses", "500-400"], ["--window", "soon"], ["--action", "allow"]):
            p = subprocess.run([binary("status-codes"), *flags], capture_output=True, text=True)
            assert p.returncode != 0, flags
