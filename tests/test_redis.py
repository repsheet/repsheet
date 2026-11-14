"""The Valkey/Redis cache tier and reporting to Repsheet."""

import time

import pytest

from conftest import GOOGLEBOT, Server, free_port, has_repsheet_nginx_module, metrics, wait_for

GOOGLE_IP = "66.249.66.1"
GOOGLE_HOST = "crawl-66-249-66-1.googlebot.com"


def redis_http(extra=""):
    return f"bot_verifier_redis {{redis}};\n{extra}"


def wait_ready(n):
    """Workers connect to Redis asynchronously after start."""
    time.sleep(0.3)


class TestRedisCache:
    def test_results_are_written(self, dns, r, server, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(http=redis_http(), redis_port=server.port)
        wait_ready(n)
        n.get(ip=GOOGLE_IP, ua=GOOGLEBOT)
        n.get(ip="203.0.113.9", ua=GOOGLEBOT)
        wait_for(lambda: r.get("{bot_verifier}:203.0.113.9"), message="redis write")
        assert r.get("{bot_verifier}:66.249.66.1") == "verified:google"
        assert r.get("{bot_verifier}:203.0.113.9") == "failed:google"
        assert 86000 < r.ttl("{bot_verifier}:66.249.66.1") <= 86400
        assert 3500 < r.ttl("{bot_verifier}:203.0.113.9") <= 3600

    def test_unknown_results_are_not_shared(self, dns, r, server, nginx_factory):
        dns.servfail.add(dns.reverse_name("198.51.100.20"))
        n = nginx_factory(http=redis_http(), redis_port=server.port)
        wait_ready(n)
        assert n.get(ip="198.51.100.20", ua=GOOGLEBOT).headers["X-Result"] == "unknown"
        time.sleep(0.2)
        assert r.get("{bot_verifier}:198.51.100.20") is None

    def test_cache_is_shared_between_servers(self, dns, r, server, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        a = nginx_factory(http=redis_http(), redis_port=server.port)
        b = nginx_factory(http=redis_http(), redis_port=server.port)
        wait_ready(a)
        assert a.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        wait_for(lambda: r.get("{bot_verifier}:66.249.66.1"), message="redis write")
        resp = b.get(ip=GOOGLE_IP, ua=GOOGLEBOT)
        assert (resp.status_code, resp.headers["X-Result"]) == (200, "verified")
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1
        mb = metrics(b)
        assert mb['bot_verifier_answers_total{source="redis"}'] == 1
        assert mb['bot_verifier_lookup_duration_seconds_count{source="redis"}'] == 1
        assert mb['bot_verifier_lookup_duration_seconds_bucket{source="redis",le="0.100"}'] == 1

    def test_shared_failure_blocks_without_dns(self, dns, r, server, nginx_factory):
        r.set("{bot_verifier}:203.0.113.77", "failed:google", ex=60)
        n = nginx_factory(http=redis_http(), redis_port=server.port)
        wait_ready(n)
        assert n.get(ip="203.0.113.77", ua=GOOGLEBOT).status_code == 403
        assert dns.queries == []

    @pytest.mark.parametrize("value", ["garbage", "verified:nosuchprovider", "maybe:google", ""])
    def test_bad_values_are_ignored(self, dns, r, server, nginx_factory, value):
        r.set("{bot_verifier}:66.249.66.1", value)
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(http=redis_http(), redis_port=server.port)
        wait_ready(n)
        assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_works_without_redis(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(http=redis_http(), redis_port=free_port())
        assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403

    def test_slow_redis_does_not_hold_requests(self, dns, tmp_path, nginx_factory):
        s = Server(tmp_path)
        try:
            dns.record(GOOGLE_IP, GOOGLE_HOST)
            n = nginx_factory(http=redis_http("bot_verifier_redis_timeout 100ms;"), redis_port=s.port)
            wait_ready(n)
            s.proc.send_signal(19)  # SIGSTOP: connected but never answers
            start = time.monotonic()
            assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
            assert time.monotonic() - start < 1.0
            s.proc.send_signal(18)  # SIGCONT
        finally:
            s.stop()

    def test_reconnects(self, dns, tmp_path, nginx_factory):
        port = free_port()
        s = Server(tmp_path, port=port)
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(http=redis_http(), redis_port=port)
        wait_ready(n)
        s.stop()
        assert n.get(ip="203.0.113.1", ua=GOOGLEBOT).status_code == 403
        s = Server(tmp_path, port=port)
        attempts = iter(range(2, 250))

        def fresh_failure_written():
            # Only fresh results are written, so use a new address each time.
            ip = f"203.0.113.{next(attempts)}"
            n.get(ip=ip, ua=GOOGLEBOT)
            return wait_for(lambda: s.client.get("{bot_verifier}:" + ip), timeout=0.3)

        try:
            wait_for(fresh_failure_written, timeout=8, interval=0.2, message="reconnect and write")
        finally:
            s.stop()


def repsheet_get(r, actor):
    reply = r.execute_command("REPSHEET.GET", actor)
    if isinstance(reply, list):
        reply = dict(zip(reply[::2], reply[1::2]))
    return reply


class TestRepsheet:
    def test_failed_verification_is_marked(self, dns, r, server, nginx_factory):
        n = nginx_factory(http=redis_http("bot_verifier_repsheet mark 10m;"), redis_port=server.port)
        wait_ready(n)
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403
        d = wait_for(lambda: repsheet_get(r, "203.0.113.9"), message="repsheet report")
        assert d["status"] == "mark"
        assert d["by"] == "bot_verifier"
        assert d["reason"] == "bot_verifier: claimed google: no reverse DNS"
        assert 0 < r.ttl("{repsheet}:actor:ip:203.0.113.9") <= 600
        assert metrics(n)["bot_verifier_repsheet_reports_total"] == 1

    def test_block_and_ipv6(self, dns, r, server, nginx_factory):
        n = nginx_factory(http=redis_http("bot_verifier_repsheet block;"), redis_port=server.port)
        wait_ready(n)
        n.get(ip="2001:db8::66", ua=GOOGLEBOT)
        d = wait_for(lambda: repsheet_get(r, "2001:db8::66"), message="repsheet report")
        assert d["status"] == "block" and d["actor"] == "ip:2001:db8::66"

    def test_only_fresh_failures_are_reported(self, dns, r, server, nginx_factory):
        n = nginx_factory(http=redis_http("bot_verifier_repsheet mark;"), redis_port=server.port)
        wait_ready(n)
        for _ in range(3):
            n.get(ip="203.0.113.9", ua=GOOGLEBOT)
        wait_for(lambda: repsheet_get(r, "203.0.113.9"), message="repsheet report")
        changes = r.xlen("{repsheet}:changes")
        assert changes == 1

    def test_verified_and_unknown_are_not_reported(self, dns, r, server, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.servfail.add(dns.reverse_name("198.51.100.20"))
        n = nginx_factory(http=redis_http("bot_verifier_repsheet mark;"), redis_port=server.port)
        wait_ready(n)
        n.get(ip=GOOGLE_IP, ua=GOOGLEBOT)
        n.get(ip="198.51.100.20", ua=GOOGLEBOT)
        time.sleep(0.3)
        assert r.scard("{repsheet}:index") == 0

    def test_missing_module_is_logged_once(self, dns, tmp_path, nginx_factory):
        import subprocess
        port = free_port()
        proc = subprocess.Popen(["sh", "-c", f"exec {Server.__init__.__globals__['server_binary']()} "
                                             f"--port {port} --save '' --bind 127.0.0.1"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            import redis as redislib
            wait_for(lambda: redislib.Redis(port=port).ping(), message="plain valkey")
            n = nginx_factory(http=redis_http("bot_verifier_repsheet mark;"), redis_port=port)
            wait_ready(n)
            n.get(ip="203.0.113.1", ua=GOOGLEBOT)
            n.get(ip="203.0.113.2", ua=GOOGLEBOT)
            wait_for(lambda: "is the repsheet module loaded?" in n.error_log(), message="error logged")
            time.sleep(0.2)
            assert n.error_log().count("is the repsheet module loaded?") == 1
        finally:
            proc.terminate()
            proc.wait()


@pytest.fixture
def with_repsheet_module():
    if not has_repsheet_nginx_module():
        pytest.skip("nginx built without the repsheet module (WITH_REPSHEET=0)")


class TestRepsheetDirectives:
    """With the Repsheet nginx module loaded, repsheet_redis is reused (#16)."""

    def test_uses_repsheet_redis(self, with_repsheet_module, dns, r, server, nginx_factory):
        n = nginx_factory(http="repsheet_redis {redis};\nbot_verifier_repsheet mark;", redis_port=server.port)
        wait_ready(n)
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403
        wait_for(lambda: r.get("{bot_verifier}:203.0.113.9") == "failed:google", message="shared cache write")
        d = wait_for(lambda: repsheet_get(r, "203.0.113.9"), message="repsheet report")
        assert d["by"] == "bot_verifier"

    def test_uses_repsheet_redis_auth(self, with_repsheet_module, dns, tmp_path, nginx_factory):
        s = Server(tmp_path, password="s3cret")
        try:
            n = nginx_factory(http="repsheet_redis {redis};\nrepsheet_redis_auth s3cret;", redis_port=s.port)
            wait_ready(n)
            n.get(ip="203.0.113.9", ua=GOOGLEBOT)
            wait_for(lambda: s.client.get("{bot_verifier}:203.0.113.9"), message="authenticated write")
        finally:
            s.stop()

    def test_bot_verifier_redis_takes_precedence(self, with_repsheet_module, dns, r, server, tmp_path,
                                                  nginx_factory):
        other = Server(tmp_path)
        try:
            n = nginx_factory(http=f"repsheet_redis {{redis}};\nbot_verifier_redis 127.0.0.1:{other.port};",
                              redis_port=server.port)
            wait_ready(n)
            n.get(ip="203.0.113.9", ua=GOOGLEBOT)
            wait_for(lambda: other.client.get("{bot_verifier}:203.0.113.9"), message="write to the other server")
            assert r.get("{bot_verifier}:203.0.113.9") is None
        finally:
            other.stop()

    def test_off_ignores_repsheet_redis(self, with_repsheet_module, dns, r, server, nginx_factory):
        n = nginx_factory(http="repsheet_redis {redis};\nbot_verifier_redis off;", redis_port=server.port)
        wait_ready(n)
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403
        time.sleep(0.3)
        assert r.get("{bot_verifier}:203.0.113.9") is None

    def test_off_and_repsheet_reporting_conflict(self, with_repsheet_module, nginx_factory):
        with pytest.raises(RuntimeError, match="requires repsheet_redis or bot_verifier_redis"):
            nginx_factory(http="repsheet_redis 127.0.0.1:6379;\nbot_verifier_redis off;\nbot_verifier_repsheet mark;")

    def test_without_repsheet_redis_nothing_is_shared(self, with_repsheet_module, dns, r, server, nginx_factory):
        n = nginx_factory(redis_port=server.port)
        wait_ready(n)
        n.get(ip="203.0.113.9", ua=GOOGLEBOT)
        time.sleep(0.3)
        assert r.dbsize() == 0
