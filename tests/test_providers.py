"""Custom providers, published ranges, variables and metrics."""

import json

import pytest

from conftest import GOOGLEBOT, metrics

DDG = "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


class TestRanges:
    def test_json_ranges_verify_without_dns(self, dns, nginx_factory, tmp_path):
        f = write(tmp_path, "google.json", json.dumps({
            "creationTime": "2026-11-01T00:00:00",
            "prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"ipv6Prefix": "2001:4860:4801:10::/64"}],
        }))
        n = nginx_factory(http=f"bot_verifier_ranges google {f};")
        for ip in ("66.249.64.5", "2001:4860:4801:10::abcd"):
            resp = n.get(ip=ip, ua=GOOGLEBOT)
            assert (resp.status_code, resp.headers["X-Result"]) == (200, "verified")
        assert dns.queries == []
        assert metrics(n)['bot_verifier_answers_total{source="ranges"}'] == 2

    def test_outside_ranges_falls_back_to_dns(self, dns, nginx_factory, tmp_path):
        f = write(tmp_path, "google.txt", "66.249.64.0/27\n")
        dns.record("66.249.70.1", "crawl-66-249-70-1.googlebot.com")
        n = nginx_factory(http=f"bot_verifier_ranges google {f};")
        assert n.get(ip="66.249.70.1", ua=GOOGLEBOT).status_code == 200
        assert dns.reverse_queries("66.249.70.1")

    def test_plain_text_format(self, dns, nginx_factory, tmp_path):
        f = write(tmp_path, "ddg.txt", "# DuckDuckBot\n20.191.45.212\n  40.88.21.235/32  # comment\n\n")
        n = nginx_factory(http=f"bot_verifier_ranges duckduckgo {f};")
        assert n.get(ip="40.88.21.235", ua=DDG).status_code == 200
        resp = n.get(ip="203.0.113.5", ua=DDG)
        assert (resp.status_code, resp.headers["X-Result"]) == (403, "failed")
        assert dns.queries == []

    def test_ranges_only_provider_without_ranges_is_unknown(self, dns, nginx_factory):
        n = nginx_factory()
        resp = n.get(ip="203.0.113.5", ua=DDG)
        assert (resp.status_code, resp.headers["X-Result"]) == (200, "unknown")
        assert dns.queries == []

    @pytest.mark.parametrize("text,error", [
        ("not-an-address\n", "invalid range"),
        ("# nothing\n", "no ranges found"),
        ('{"prefixes": [{"ipv4Prefix": "300.1.1.1/8"}]}', "invalid range"),
    ])
    def test_bad_files(self, nginx_factory, tmp_path, text, error):
        f = write(tmp_path, "bad.txt", text)
        with pytest.raises(RuntimeError, match=error):
            nginx_factory(http=f"bot_verifier_ranges google {f};")

    def test_missing_file(self, nginx_factory, tmp_path):
        with pytest.raises(RuntimeError, match="cannot open ranges file"):
            nginx_factory(http=f"bot_verifier_ranges google {tmp_path}/nope.json;")

    def test_unknown_provider(self, nginx_factory, tmp_path):
        f = write(tmp_path, "r.txt", "10.0.0.0/8\n")
        with pytest.raises(RuntimeError, match="unknown provider"):
            nginx_factory(http=f"bot_verifier_ranges nosuch {f};")


class TestCustomProviders:
    def test_new_provider(self, dns, nginx_factory):
        dns.record("192.0.2.30", "bot-1.crawler.example.org")
        n = nginx_factory(http="""
            bot_verifier_provider examplebot {
                user_agent "ExampleBot/\\d";
                domain crawler.example.org;
            }""")
        resp = n.get(ip="192.0.2.30", ua="Mozilla/5.0 (compatible; ExampleBot/1.0)")
        assert (resp.status_code, resp.headers["X-Result"], resp.headers["X-Provider"]) == \
            (200, "verified", "examplebot")
        assert n.get(ip="192.0.2.31", ua="ExampleBot/2").status_code == 403
        assert n.get(ip="192.0.2.31", ua="ExampleBot").status_code == 200  # regex does not match

    def test_redefining_a_builtin_replaces_it(self, dns, nginx_factory):
        dns.record("192.0.2.40", "crawl-1.googlebot.com")
        n = nginx_factory(http="""
            bot_verifier_provider google {
                user_agent "googlebot";
                domain my-google-proxy.example.net;
            }""")
        assert n.get(ip="192.0.2.40", ua=GOOGLEBOT).status_code == 403

    @pytest.mark.parametrize("block,error", [
        ("domain x.example;", "requires \"user_agent\""),
        ("user_agent x;", "requires \"domain\" or \"ranges\""),
        ("user_agent \"(\"; domain x.example;", "invalid user_agent"),
        ("user_agent x; bogus y;", "expected"),
    ])
    def test_invalid(self, nginx_factory, block, error):
        with pytest.raises(RuntimeError, match=error):
            nginx_factory(http=f"bot_verifier_provider p {{ {block} }}")


class TestMetrics:
    def test_counters(self, dns, nginx_factory):
        dns.record("66.249.66.1", "crawl-66-249-66-1.googlebot.com")
        n = nginx_factory()
        n.get(ip="66.249.66.1", ua=GOOGLEBOT)
        n.get(ip="66.249.66.1", ua=GOOGLEBOT)
        n.get(ip="203.0.113.9", ua=GOOGLEBOT)
        n.get(ip="203.0.113.9", ua="curl/8")
        m = metrics(n)
        assert m['bot_verifier_requests_total{result="verified"}'] == 2
        assert m['bot_verifier_requests_total{result="failed"}'] == 1
        assert m["bot_verifier_blocked_total"] == 1
        assert m["bot_verifier_dns_queries_total"] == 3   # 2 reverse + 1 forward
        assert m["bot_verifier_cache_entries"] == 2
        assert m["bot_verifier_zone_size_bytes"] == 16 * 1024 * 1024
        assert 0 < m["bot_verifier_zone_free_bytes"] < 16 * 1024 * 1024
