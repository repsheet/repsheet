"""The bot verifier active detector, against a fake DNS server."""

import json
import re
import socket
import threading
import time

import pytest

from conftest import metrics, wait_for

GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
DDG = "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"

GOOGLE_IP = "66.249.66.1"
GOOGLE_HOST = "crawl-66-249-66-1.googlebot.com"

CONF = """
    resolver {resolver} valid=1s;
    resolver_timeout 2s;
    repsheet_redis {redis};
    repsheet on;
    %(http)s
    server {
        listen 127.0.0.1:{port};
        set_real_ip_from 127.0.0.1;
        real_ip_header X-Real-IP;
        add_header X-Result $repsheet_bot_verifier_result always;
        add_header X-Provider $repsheet_bot_verifier_provider always;
        add_header X-Time $repsheet_bot_verifier_time always;
        add_header X-Repsheet $repsheet_status always;

        location / {
            %(location)s
        }
        location = /metrics {
            repsheet off;
            repsheet_metrics;
        }
        %(server)s
    }
"""


@pytest.fixture
def bv(r, dns, nginx_factory):
    """Start nginx with the bot verifier; returns a factory."""

    def make(location="repsheet_bot_verifier on;", http="", server="", raw=None, workers=1, redis_port=None):
        conf = raw if raw is not None else CONF % {"http": http, "location": location, "server": server}
        return nginx_factory(conf.replace("{resolver}", f"127.0.0.1:{dns.port}"), workers=workers,
                             redis_port=redis_port)

    return make


def get(n, ip=None, ua=None, headers=None, path="/"):
    h = dict(headers or {})
    if ip is not None:
        h["X-Real-IP"] = ip
    if ua is not None:
        h["User-Agent"] = ua
    return n.get(path, headers=h)


def verdict(resp):
    return resp.status_code, resp.headers.get("X-Result", ""), resp.headers.get("X-Provider", "")


def decision(r, actor):
    reply = r.execute_command("REPSHEET.GET", actor)
    if isinstance(reply, list):
        reply = dict(zip(reply[::2], reply[1::2]))
    return reply


class TestClaims:
    def test_real_googlebot_is_verified(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = bv()
        assert verdict(get(n, GOOGLE_IP, GOOGLEBOT)) == (200, "verified", "google")

    def test_spoofed_googlebot_is_blocked(self, dns, bv):
        n = bv()
        assert verdict(get(n, "203.0.113.9", GOOGLEBOT)) == (403, "failed", "google")
        assert "203.0.113.9 failed verification, claimed google: no reverse DNS" in n.error_log()

    def test_browsers_are_not_checked(self, dns, bv):
        n = bv()
        for ua in (BROWSER, None, ""):
            assert verdict(get(n, "203.0.113.9", ua)) == (200, "", "")
        assert dns.queries == []

    @pytest.mark.parametrize("host", [
        "crawl-1.evilgooglebot.com", "googlebot.com.evil.net", "crawl.googlebot.co", "googlebot.com.au",
    ])
    def test_lookalike_domains_fail(self, dns, bv, host):
        dns.record("198.51.100.7", host)
        n = bv()
        assert verdict(get(n, "198.51.100.7", GOOGLEBOT))[:2] == (403, "failed")

    def test_forward_lookup_must_return_the_address(self, dns, bv):
        dns.record("198.51.100.8", "crawl-x.googlebot.com", forward=["198.51.100.99"])
        n = bv()
        assert verdict(get(n, "198.51.100.8", GOOGLEBOT))[:2] == (403, "failed")

    def test_any_forward_address_may_match(self, dns, bv):
        dns.record("198.51.100.8", "crawl-x.googlebot.com", forward=["198.51.100.1", "198.51.100.8"])
        n = bv()
        assert verdict(get(n, "198.51.100.8", GOOGLEBOT))[:2] == (200, "verified")

    def test_ipv6(self, dns, bv):
        dns.record("2001:4860:4801:10::1", "crawl-2001-4860-4801-10--1.googlebot.com")
        n = bv()
        assert verdict(get(n, "2001:4860:4801:10::1", GOOGLEBOT)) == (200, "verified", "google")
        assert verdict(get(n, "2001:db8::bad", GOOGLEBOT))[:2] == (403, "failed")

    @pytest.mark.parametrize("ua,host,provider", [
        (BINGBOT, "msnbot-157-55-39-1.search.msn.com", "bing"),
        ("Mozilla/5.0 (compatible; Baiduspider/2.0)", "baiduspider-1.crawl.baidu.com", "baidu"),
        ("Mozilla/5.0 (compatible; Yahoo! Slurp)", "b1.crawl.yahoo.net", "yahoo"),
        ("Mozilla/5.0 (compatible; YandexBot/3.0)", "1-2-3-4.spider.yandex.com", "yandex"),
        ("Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)", "17-58-1-1.applebot.apple.com",
         "apple"),
    ])
    def test_builtin_providers(self, dns, bv, ua, host, provider):
        dns.record("192.0.2.10", host)
        n = bv()
        assert verdict(get(n, "192.0.2.10", ua)) == (200, "verified", provider)

    def test_verified_as_one_crawler_fails_as_another(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = bv()
        assert get(n, GOOGLE_IP, GOOGLEBOT).status_code == 200
        queries = len(dns.queries)
        assert verdict(get(n, GOOGLE_IP, BINGBOT)) == (403, "failed", "bing")
        assert len(dns.queries) == queries


class TestDecisions:
    """A failed verification becomes a Repsheet decision."""

    def test_failure_is_recorded(self, r, dns, bv):
        n = bv()
        get(n, "203.0.113.9", GOOGLEBOT)
        d = wait_for(lambda: decision(r, "203.0.113.9"), message="decision in valkey")
        assert d["status"] == "block" and d["by"] == "bot_verifier"
        assert d["reason"] == "bot_verifier: claimed google: no reverse DNS"
        assert 3500 < r.ttl("{repsheet}:actor:ip:203.0.113.9") <= 3600
        assert metrics(n)["repsheet_bot_verifier_decisions_total"] == 1

    def test_decision_blocks_every_request_from_the_address(self, dns, bv):
        n = bv()
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403
        resp = get(n, "203.0.113.9", BROWSER)
        assert (resp.status_code, resp.headers["X-Repsheet"]) == (403, "block")
        assert len(dns.reverse_queries("203.0.113.9")) == 1

    def test_applies_at_once_to_all_workers(self, dns, bv):
        n = bv(workers=4)
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403
        assert all(get(n, "203.0.113.9", BROWSER).status_code == 403 for _ in range(20))

    def test_other_nginx_enforces_after_sync(self, dns, bv):
        a, b = bv(), bv()
        assert get(b, "203.0.113.9", BROWSER).status_code == 200
        assert get(a, "203.0.113.9", GOOGLEBOT).status_code == 403
        wait_for(lambda: get(b, "203.0.113.9", BROWSER).status_code == 403, message="sync to the other nginx")

    def test_mark_action(self, r, dns, bv):
        n = bv(http="repsheet_bot_verifier_action mark 10m;")
        resp = get(n, "203.0.113.9", GOOGLEBOT)
        assert (resp.status_code, resp.headers["X-Result"], resp.headers["X-Repsheet"]) == (200, "failed", "mark")
        d = wait_for(lambda: decision(r, "203.0.113.9"), message="decision")
        assert d["status"] == "mark"
        assert 0 < r.ttl("{repsheet}:actor:ip:203.0.113.9") <= 600
        assert get(n, "203.0.113.9", BROWSER).headers["X-Repsheet"] == "mark"
        # A mark does not stop detectors; a known failure is not recorded again.
        get(n, "203.0.113.9", GOOGLEBOT)
        assert r.xlen("{repsheet}:changes") == 1

    def test_recorded_again_after_being_cleared(self, r, dns, bv):
        n = bv()
        get(n, "203.0.113.9", GOOGLEBOT)
        wait_for(lambda: decision(r, "203.0.113.9"), message="decision")
        r.execute_command("REPSHEET.CLEAR", "203.0.113.9", "BY", "admin")
        wait_for(lambda: get(n, "203.0.113.9", BROWSER).status_code == 200, message="clear synced")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403   # still faking
        wait_for(lambda: decision(r, "203.0.113.9"), message="recorded again")

    def test_allowed_actors_skip_detection(self, r, dns, bv):
        r.execute_command("REPSHEET.ALLOW", "203.0.113.0/24", "REASON", "partner")
        n = bv()
        wait_for(lambda: get(n, "203.0.113.9", BROWSER).headers.get("X-Repsheet") == "allow", message="sync")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 200
        assert dns.queries == []

    def test_blocked_actors_are_rejected_without_lookups(self, r, dns, bv):
        r.execute_command("REPSHEET.BLOCK", "203.0.113.9")
        n = bv()
        wait_for(lambda: get(n, "203.0.113.9", BROWSER).status_code == 403, message="sync")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403
        assert dns.queries == []

    def test_monitor_records_nothing(self, r, dns, bv):
        n = bv(location="repsheet_bot_verifier monitor;")
        assert verdict(get(n, "203.0.113.9", GOOGLEBOT)) == (200, "failed", "google")
        assert "would record a block decision" in n.error_log()
        time.sleep(0.3)
        assert decision(r, "203.0.113.9") is None

    def test_repsheet_monitor_records_but_does_not_block(self, r, dns, bv):
        n = bv(location="repsheet monitor; repsheet_bot_verifier on;")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 200
        wait_for(lambda: decision(r, "203.0.113.9"), message="decision")

    def test_block_status(self, dns, bv):
        n = bv(location="repsheet_bot_verifier on; repsheet_block_status 429;")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 429

    def test_works_while_redis_is_down(self, dns, bv):
        from conftest import free_port
        n = bv(redis_port=free_port())
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403
        assert get(n, "203.0.113.9", BROWSER).status_code == 403   # applied locally
        assert "applies to this nginx only" in n.error_log()


class TestOff:
    def test_off_by_default(self, dns, bv):
        n = bv(location="")
        assert verdict(get(n, "203.0.113.9", GOOGLEBOT)) == (200, "", "")
        assert dns.queries == []
        assert not any(k.startswith("repsheet_bot_verifier") for k in metrics(n))

    def test_off_in_a_location(self, dns, bv):
        n = bv(http="repsheet_bot_verifier on;", location="repsheet_bot_verifier off;")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 200
        assert dns.queries == []

    def test_only_where_repsheet_is_on(self, dns, bv):
        n = bv(location="repsheet off; repsheet_bot_verifier on;")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 200
        assert dns.queries == []


class TestDnsErrors:
    def test_servfail_is_unknown_and_allowed(self, dns, bv):
        dns.servfail.add(dns.reverse_name("198.51.100.20"))
        n = bv()
        assert verdict(get(n, "198.51.100.20", GOOGLEBOT))[:2] == (200, "unknown")

    def test_timeout_is_unknown_and_allowed(self, dns, bv):
        dns.silent.add(dns.reverse_name("198.51.100.21"))
        n = bv(location="repsheet_bot_verifier on; repsheet_bot_verifier_timeout 300ms;")
        assert verdict(get(n, "198.51.100.21", GOOGLEBOT))[:2] == (200, "unknown")


class TestCaching:
    def test_verified_result_is_cached(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = bv()
        for _ in range(3):
            assert get(n, GOOGLE_IP, GOOGLEBOT).status_code == 200
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1
        assert metrics(n)['repsheet_bot_verifier_answers_total{source="zone"}'] == 2

    def test_results_are_shared_through_redis(self, r, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        a, b = bv(), bv()
        time.sleep(0.3)
        assert get(a, GOOGLE_IP, GOOGLEBOT).status_code == 200
        wait_for(lambda: r.get("{repsheet}:bot_verifier:66.249.66.1"), message="shared result")
        assert r.get("{repsheet}:bot_verifier:66.249.66.1") == "verified:google"
        assert verdict(get(b, GOOGLE_IP, GOOGLEBOT))[:2] == (200, "verified")
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1
        m = metrics(b)
        assert m['repsheet_bot_verifier_answers_total{source="redis"}'] == 1
        assert m['repsheet_bot_verifier_lookup_duration_seconds_count{source="redis"}'] == 1

    @pytest.mark.parametrize("value", ["garbage", "verified:nosuchprovider", "maybe:google"])
    def test_bad_shared_values_are_ignored(self, r, dns, bv, value):
        r.set("{repsheet}:bot_verifier:66.249.66.1", value)
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = bv()
        time.sleep(0.3)
        assert get(n, GOOGLE_IP, GOOGLEBOT).status_code == 200
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_concurrent_requests_share_one_lookup(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.3
        n = bv()
        results = []
        threads = [threading.Thread(target=lambda: results.append(get(n, GOOGLE_IP, GOOGLEBOT).status_code))
                   for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [200] * 10
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_requests_do_not_block_the_worker(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 1.0
        n = bv(workers=1)
        slow = threading.Thread(target=lambda: get(n, GOOGLE_IP, GOOGLEBOT))
        slow.start()
        wait_for(lambda: dns.reverse_queries(GOOGLE_IP), message="lookup started")
        start = time.monotonic()
        assert get(n, "203.0.113.1", BROWSER).status_code == 200
        assert time.monotonic() - start < 0.5
        slow.join()

    def test_client_going_away_mid_lookup(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.5
        n = bv()
        s = socket.create_connection(("127.0.0.1", n.port))
        s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nX-Real-IP: {GOOGLE_IP}\r\nUser-Agent: {GOOGLEBOT}\r\n\r\n".encode())
        wait_for(lambda: dns.reverse_queries(GOOGLE_IP), message="lookup started")
        s.close()
        wait_for(lambda: dns.queries_for(GOOGLE_HOST), timeout=3, message="forward lookup")
        dns.delay = 0
        assert verdict(get(n, GOOGLE_IP, GOOGLEBOT))[:2] == (200, "verified")
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1


class TestRanges:
    def test_json_ranges_verify_without_dns(self, dns, bv, tmp_path):
        f = tmp_path / "google.json"
        f.write_text(json.dumps({"prefixes": [{"ipv4Prefix": "66.249.64.0/27"},
                                              {"ipv6Prefix": "2001:4860:4801:10::/64"}]}))
        n = bv(http=f"repsheet_bot_verifier_ranges google {f};")
        for ip in ("66.249.64.5", "2001:4860:4801:10::abcd"):
            assert verdict(get(n, ip, GOOGLEBOT))[:2] == (200, "verified")
        assert dns.queries == []

    def test_ranges_only_provider(self, r, dns, bv, tmp_path):
        f = tmp_path / "ddg.txt"
        f.write_text("# DuckDuckBot\n20.191.45.212\n")
        n = bv(http=f"repsheet_bot_verifier_ranges duckduckgo {f};")
        assert get(n, "20.191.45.212", DDG).status_code == 200
        assert verdict(get(n, "203.0.113.5", DDG))[:2] == (403, "failed")
        d = wait_for(lambda: decision(r, "203.0.113.5"), message="decision")
        assert d["reason"] == "bot_verifier: claimed duckduckgo: not in its published ranges"
        assert dns.queries == []

    def test_bad_file(self, bv, tmp_path):
        f = tmp_path / "bad.txt"
        f.write_text("not-an-address\n")
        with pytest.raises(RuntimeError, match="invalid range"):
            bv(http=f"repsheet_bot_verifier_ranges google {f};")


class TestCustomProviders:
    def test_new_provider(self, dns, bv):
        dns.record("192.0.2.30", "bot-1.crawler.example.org")
        n = bv(http="""
            repsheet_bot_verifier_provider examplebot {
                user_agent "ExampleBot/\\d";
                domain crawler.example.org;
            }""")
        assert verdict(get(n, "192.0.2.30", "ExampleBot/1.0")) == (200, "verified", "examplebot")
        assert get(n, "192.0.2.31", "ExampleBot/2").status_code == 403

    def test_invalid(self, bv):
        with pytest.raises(RuntimeError, match="requires \"user_agent\""):
            bv(http="repsheet_bot_verifier_provider p { domain x.example; }")


class TestTiming:
    def test_wait_time_and_histogram(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.3
        n = bv()
        first = get(n, GOOGLE_IP, GOOGLEBOT)
        assert 0.55 <= float(first.headers["X-Time"]) < 2.0
        assert get(n, GOOGLE_IP, GOOGLEBOT).headers["X-Time"] == "0.000"
        m = metrics(n)
        h = "repsheet_bot_verifier_lookup_duration_seconds"
        assert m[f'{h}_count{{source="dns"}}'] == 1
        assert m[f'{h}_bucket{{source="dns",le="0.500"}}'] == 0
        assert m[f'{h}_bucket{{source="dns",le="1.000"}}'] == 1

    def test_duration_in_log(self, dns, bv):
        n = bv()
        get(n, "203.0.113.9", GOOGLEBOT)
        assert re.search(r"203\.0\.113\.9 failed verification, claimed google: no reverse DNS \(\d+ms\)",
                         n.error_log())


class TestMetricsAndCounting:
    def test_counted_once(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.2
        n = bv()
        before = metrics(n)   # the readiness probe is a request too
        get(n, GOOGLE_IP, GOOGLEBOT)   # suspended, resumed, then redirected to /index.html
        get(n, "203.0.113.9", GOOGLEBOT)
        m = metrics(n)
        assert m['repsheet_bot_verifier_requests_total{result="verified"}'] == 1
        assert m['repsheet_bot_verifier_requests_total{result="failed"}'] == 1
        none = 'repsheet_requests_total{decision="none"}'
        assert m[none] - before[none] == 1
        assert m['repsheet_requests_total{decision="block"}'] == 1
        assert m["repsheet_blocked_total"] == 1
        assert m["repsheet_detector_decisions_total"] == 1


class TestConfig:
    def test_requires_resolver(self, bv):
        raw = """
            repsheet_redis {redis};
            repsheet on;
            server {
                listen 127.0.0.1:{port};
                location / { repsheet_bot_verifier on; }
            }
        """
        with pytest.raises(RuntimeError, match="needs a DNS resolver"):
            bv(raw=raw)

    def test_requires_repsheet_redis(self, bv):
        raw = """
            resolver {resolver};
            server {
                listen 127.0.0.1:{port};
                location / { repsheet_bot_verifier on; }
            }
        """
        with pytest.raises(RuntimeError, match="requires repsheet_redis"):
            bv(raw=raw)

    def test_satisfy_any_cannot_override_a_block(self, dns, bv):
        n = bv(location="repsheet_bot_verifier on; satisfy any; allow all;")
        assert get(n, "203.0.113.9", GOOGLEBOT).status_code == 403

    def test_x_forwarded_for_is_not_trusted(self, dns, bv):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        raw = """
            resolver {resolver};
            repsheet_redis {redis};
            repsheet on;
            server {
                listen 127.0.0.1:{port};
                add_header X-Result $repsheet_bot_verifier_result always;
                location / { repsheet_bot_verifier on; }
            }
        """
        n = bv(raw=raw)
        resp = get(n, ua=GOOGLEBOT, headers={"X-Forwarded-For": GOOGLE_IP})
        assert (resp.status_code, resp.headers["X-Result"]) == (403, "failed")
        assert not dns.reverse_queries(GOOGLE_IP)
