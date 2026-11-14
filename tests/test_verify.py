"""Verification against a fake DNS server."""

import threading

import pytest

from conftest import BINGBOT, BROWSER, GOOGLEBOT, metrics, wait_for

GOOGLE_IP = "66.249.66.1"
GOOGLE_HOST = "crawl-66-249-66-1.googlebot.com"


def verdict(resp):
    return resp.status_code, resp.headers.get("X-Result", ""), resp.headers.get("X-Provider", "")


class TestClaims:
    def test_real_googlebot_is_verified(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory()
        assert verdict(n.get(ip=GOOGLE_IP, ua=GOOGLEBOT)) == (200, "verified", "google")

    def test_spoofed_googlebot_is_blocked(self, dns, nginx_factory):
        n = nginx_factory()  # 203.0.113.9 has no PTR record
        assert verdict(n.get(ip="203.0.113.9", ua=GOOGLEBOT)) == (403, "failed", "google")
        assert "203.0.113.9 failed verification, claimed google: no reverse DNS" in n.error_log()

    def test_browsers_are_not_checked(self, dns, nginx_factory):
        n = nginx_factory()
        for ua in (BROWSER, None, ""):
            resp = n.get(ip="203.0.113.9", ua=ua)
            assert verdict(resp) == (200, "", "")
        assert dns.queries == []

    def test_cached_failure_does_not_block_other_traffic_from_that_address(self, dns, nginx_factory):
        n = nginx_factory()
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403
        assert n.get(ip="203.0.113.9", ua=BROWSER).status_code == 200

    @pytest.mark.parametrize("host", [
        "crawl-1.evilgooglebot.com",
        "googlebot.com.evil.net",
        "crawl.googlebot.co",
        "googlebot.com.au",
        "evil.net",
    ])
    def test_lookalike_domains_fail(self, dns, nginx_factory, host):
        dns.record("198.51.100.7", host)
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.7", ua=GOOGLEBOT))[:2] == (403, "failed")
        assert "is not one of its domains" in n.error_log()

    def test_forward_lookup_must_return_the_address(self, dns, nginx_factory):
        dns.record("198.51.100.8", "crawl-x.googlebot.com", forward=["198.51.100.99"])
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.8", ua=GOOGLEBOT))[:2] == (403, "failed")
        assert "does not resolve to the client address" in n.error_log()

    def test_any_forward_address_may_match(self, dns, nginx_factory):
        dns.record("198.51.100.8", "crawl-x.googlebot.com",
                   forward=["198.51.100.1", "198.51.100.8", "2001:db8::8"])
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.8", ua=GOOGLEBOT))[:2] == (200, "verified")

    def test_hostname_that_does_not_resolve(self, dns, nginx_factory):
        dns.ptr["198.51.100.9"] = "gone.googlebot.com"
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.9", ua=GOOGLEBOT))[:2] == (403, "failed")

    def test_ipv6_crawler(self, dns, nginx_factory):
        dns.record("2001:4860:4801:10::1", "crawl-2001-4860-4801-10--1.googlebot.com")
        n = nginx_factory()
        assert verdict(n.get(ip="2001:4860:4801:10::1", ua=GOOGLEBOT)) == (200, "verified", "google")
        assert verdict(n.get(ip="2001:db8::bad", ua=GOOGLEBOT))[:2] == (403, "failed")

    @pytest.mark.parametrize("ua,host,provider", [
        (BINGBOT, "msnbot-157-55-39-1.search.msn.com", "bing"),
        ("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
         "baiduspider-123-125-71-1.crawl.baidu.com", "baidu"),
        ("Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
         "b1.crawl.yahoo.net", "yahoo"),
        ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "1-2-3-4.spider.yandex.com",
         "yandex"),
        ("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15 "
         "(Applebot/0.1; +http://www.apple.com/go/applebot)", "17-58-1-1.applebot.apple.com", "apple"),
    ])
    def test_builtin_providers(self, dns, nginx_factory, ua, host, provider):
        dns.record("192.0.2.10", host)
        n = nginx_factory()
        assert verdict(n.get(ip="192.0.2.10", ua=ua)) == (200, "verified", provider)

    def test_verified_as_one_crawler_fails_as_another(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory()
        assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        queries = len(dns.queries)
        assert verdict(n.get(ip=GOOGLE_IP, ua=BINGBOT)) == (403, "failed", "bing")
        assert len(dns.queries) == queries


class TestDnsErrors:
    def test_servfail_is_unknown_and_allowed(self, dns, nginx_factory):
        dns.servfail.add(dns.reverse_name("198.51.100.20"))
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.20", ua=GOOGLEBOT))[:2] == (200, "unknown")
        assert "could not be verified" in n.error_log()

    def test_timeout_is_unknown_and_allowed(self, dns, nginx_factory):
        dns.silent.add(dns.reverse_name("198.51.100.21"))
        n = nginx_factory(location="bot_verifier on; bot_verifier_timeout 300ms;")
        assert verdict(n.get(ip="198.51.100.21", ua=GOOGLEBOT))[:2] == (200, "unknown")

    def test_forward_servfail_is_unknown(self, dns, nginx_factory):
        dns.record("198.51.100.22", "crawl-22.googlebot.com")
        dns.servfail.add("crawl-22.googlebot.com.")
        n = nginx_factory()
        assert verdict(n.get(ip="198.51.100.22", ua=GOOGLEBOT))[:2] == (200, "unknown")


class TestCaching:
    def test_result_is_cached(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory()
        for _ in range(3):
            assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
            assert n.get(ip="203.0.113.50", ua=GOOGLEBOT).status_code == 403
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1
        assert len(dns.reverse_queries("203.0.113.50")) == 1
        m = metrics(n)
        assert m['bot_verifier_answers_total{source="zone"}'] == 4
        assert m['bot_verifier_answers_total{source="dns"}'] == 2

    def test_cache_shared_between_workers(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(workers=4)
        for _ in range(20):
            assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_ttls(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory(http="bot_verifier_ttl 1s 1s 1s;")
        n.get(ip=GOOGLE_IP, ua=GOOGLEBOT)
        wait_for(lambda: n.get(ip=GOOGLE_IP, ua=GOOGLEBOT) and len(dns.reverse_queries(GOOGLE_IP)) == 2,
                 timeout=4, interval=0.3, message="cache expiry")

    def test_concurrent_requests_share_one_lookup(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.3
        n = nginx_factory()
        results = []

        def go():
            results.append(n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code)

        threads = [threading.Thread(target=go) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [200] * 10
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_requests_do_not_block_the_worker(self, dns, nginx_factory):
        """A slow DNS answer must not stall other requests on the same worker."""
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 1.0
        n = nginx_factory(workers=1)
        slow = threading.Thread(target=lambda: n.get(ip=GOOGLE_IP, ua=GOOGLEBOT))
        slow.start()
        wait_for(lambda: dns.reverse_queries(GOOGLE_IP), message="lookup started")
        import time
        start = time.monotonic()
        assert n.get(ip="203.0.113.1", ua=BROWSER).status_code == 200
        assert time.monotonic() - start < 0.5
        slow.join()

    def test_client_going_away_mid_lookup(self, dns, nginx_factory):
        import socket
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        dns.delay = 0.5
        n = nginx_factory()
        s = socket.create_connection(("127.0.0.1", n.port))
        s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nX-Real-IP: {GOOGLE_IP}\r\nUser-Agent: {GOOGLEBOT}\r\n\r\n".encode())
        wait_for(lambda: dns.reverse_queries(GOOGLE_IP), message="lookup started")
        s.close()
        # The lookup still completes and is cached for the next request.
        wait_for(lambda: len(dns.queries_for("crawl-66-249-66-1.googlebot.com")) >= 1, timeout=3,
                 message="forward lookup")
        dns.delay = 0
        assert verdict(n.get(ip=GOOGLE_IP, ua=GOOGLEBOT))[:2] == (200, "verified")
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1

    def test_reload_keeps_cache(self, dns, nginx_factory):
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        n = nginx_factory()
        n.get(ip=GOOGLE_IP, ua=GOOGLEBOT)
        n.reload()
        import time
        time.sleep(1)
        assert n.get(ip=GOOGLE_IP, ua=GOOGLEBOT).status_code == 200
        assert len(dns.reverse_queries(GOOGLE_IP)) == 1


class TestModes:
    def test_monitor_mode_does_not_block(self, dns, nginx_factory):
        n = nginx_factory(location="bot_verifier monitor;")
        assert verdict(n.get(ip="203.0.113.9", ua=GOOGLEBOT)) == (200, "failed", "google")
        assert "would block" in n.error_log()
        m = metrics(n)
        assert m['bot_verifier_requests_total{result="failed"}'] == 1
        assert m["bot_verifier_blocked_total"] == 0

    def test_block_status(self, dns, nginx_factory):
        n = nginx_factory(location="bot_verifier on; bot_verifier_block_status 429;")
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 429

    def test_off_location(self, dns, nginx_factory):
        n = nginx_factory(http="bot_verifier on;", location="bot_verifier off;")
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 200
        assert dns.queries == []

    def test_satisfy_any_cannot_override_a_block(self, dns, nginx_factory):
        n = nginx_factory(location="bot_verifier on; satisfy any; allow all;")
        assert n.get(ip="203.0.113.9", ua=GOOGLEBOT).status_code == 403

    def test_satisfy_any_still_requires_auth_for_others(self, dns, nginx_factory, tmp_path):
        """The old module returned NGX_OK for non-crawlers, granting access under satisfy any."""
        htpasswd = tmp_path / "htpasswd"
        htpasswd.write_text("u:$apr1$x$x\n")
        n = nginx_factory(location=f"bot_verifier on; satisfy any; deny all; auth_basic x; "
                                   f"auth_basic_user_file {htpasswd};")
        assert n.get(ip="203.0.113.9", ua=BROWSER).status_code == 401

    def test_x_forwarded_for_is_not_trusted(self, dns, nginx_factory):
        """Without realip the connection address is used, whatever the headers say."""
        dns.record(GOOGLE_IP, GOOGLE_HOST)
        raw = """
            resolver {resolver};
            server {
                listen 127.0.0.1:{port};
                add_header X-Result $bot_verifier_result always;
                location / { bot_verifier on; }
                location = /__ready { return 204; }
            }
        """
        n = nginx_factory(raw=raw)
        resp = n.get(ua=GOOGLEBOT, headers={"X-Forwarded-For": GOOGLE_IP})
        assert (resp.status_code, resp.headers["X-Result"]) == (403, "failed")
        assert dns.reverse_queries("127.0.0.1")
        assert not dns.reverse_queries(GOOGLE_IP)


class TestConfig:
    def test_requires_resolver(self, nginx_factory):
        raw = """
            server {
                listen 127.0.0.1:{port};
                location / { bot_verifier on; }
            }
        """
        with pytest.raises(RuntimeError, match="needs a DNS resolver"):
            nginx_factory(raw=raw)

    def test_bad_block_status(self, nginx_factory):
        with pytest.raises(RuntimeError, match="between 400 and 599"):
            nginx_factory(location="bot_verifier on; bot_verifier_block_status 200;")

    def test_repsheet_requires_redis(self, nginx_factory):
        with pytest.raises(RuntimeError, match="requires repsheet_redis or bot_verifier_redis"):
            nginx_factory(http="bot_verifier_repsheet mark;")
