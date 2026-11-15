import time

import pytest
import requests

from conftest import Server, free_port, metrics, nginx_binary, wait_for

BASE = """
    repsheet_redis {redis};
    repsheet_sync_interval 100ms;
    repsheet_redis_timeout 500ms;
    repsheet on;
%s
    server {
        listen 127.0.0.1:{port};
        location / { }
        location = /vars {
            return 200 "$repsheet_status|$repsheet_reason|$repsheet_actor";
        }
        location = /metrics {
            repsheet off;
            repsheet_metrics;
        }
%s
    }
"""


def conf(http="", locations=""):
    return BASE % (http, locations)


def status_is(n, code, path="/", **kw):
    return lambda: n.get(path, **kw).status_code == code


def wait_status(n, code, path="/", **kw):
    wait_for(status_is(n, code, path, **kw), message=f"{path} to return {code}")


def synced(n):
    wait_for(lambda: metrics(n).get("repsheet_sync_up") == 1, message="sync")


@pytest.fixture
def nginx(nginx_factory, r):
    n = nginx_factory(conf())
    synced(n)
    return n


class TestEnforcement:
    def test_unknown_client_passes(self, nginx):
        assert nginx.get().status_code == 200
        assert nginx.get("/vars").text == "||"

    def test_block_ip(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1", "REASON", "scanner")
        wait_status(nginx, 403)

    def test_block_network(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.0/8")
        wait_status(nginx, 403)

    def test_unrelated_network_not_blocked(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "10.0.0.0/8")
        r.execute_command("REPSHEET.MARK", "127.0.0.1")  # sync barrier
        wait_for(lambda: nginx.get("/vars").text.startswith("mark"))
        assert nginx.get().status_code == 200

    def test_allow_overrides_block(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.0/8")
        r.execute_command("REPSHEET.ALLOW", "127.0.0.1", "REASON", "monitoring")
        wait_for(lambda: nginx.get("/vars").text == "allow|monitoring|ip:127.0.0.1")
        assert nginx.get().status_code == 200

    def test_mark_passes_with_variables(self, nginx, r):
        r.execute_command("REPSHEET.MARK", "127.0.0.1", "REASON", "credential stuffing")
        wait_for(lambda: nginx.get("/vars").text == "mark|credential stuffing|ip:127.0.0.1")
        assert nginx.get().status_code == 200

    def test_clear_unblocks(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(nginx, 403)
        r.execute_command("REPSHEET.CLEAR", "127.0.0.1")
        wait_status(nginx, 200)

    def test_ttl_expires_locally(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1", "TTL", "1")
        wait_status(nginx, 403)
        time.sleep(1.1)
        assert nginx.get().status_code == 200

    def test_most_specific_reason_wins(self, nginx, r):
        r.execute_command("REPSHEET.MARK", "127.0.0.0/8", "REASON", "wide")
        r.execute_command("REPSHEET.MARK", "127.0.0.0/24", "REASON", "narrow")
        wait_for(lambda: nginx.get("/vars").text == "mark|narrow|ip:127.0.0.0/24")


class TestPrefixLengths:
    """Every prefix length in use is checked; the per-length filters may only skip misses."""

    def vars(self, n, ip):
        return n.get("/vars", headers={"X-Real-IP": ip}).text

    @pytest.fixture
    def realip(self, nginx_factory, r):
        n = nginx_factory(conf(http="set_real_ip_from 127.0.0.1;\n    real_ip_header X-Real-IP;"))
        synced(n)
        return n

    def test_most_specific_match_at_every_length(self, realip, r):
        pipe = r.pipeline(transaction=False)
        for length in range(8, 33):
            pipe.execute_command("REPSHEET.MARK", f"10.20.30.40/{length}", "REASON", f"v4/{length}")
        for length in range(16, 129, 8):
            pipe.execute_command("REPSHEET.MARK", f"2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff/{length}",
                                 "REASON", f"v6/{length}")
        pipe.execute()
        wait_for(lambda: metrics(realip)["repsheet_decisions"] == 25 + 15, message="sync")
        assert self.vars(realip, "10.20.30.40") == "mark|v4/32|ip:10.20.30.40"
        assert self.vars(realip, "10.20.30.41").split("|")[1] == "v4/31"
        assert self.vars(realip, "10.20.31.1").split("|")[1] == "v4/23"
        assert self.vars(realip, "10.200.0.1").split("|")[1] == "v4/8"
        assert self.vars(realip, "11.0.0.1") == "||"
        assert self.vars(realip, "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff").split("|")[1] == "v6/128"
        assert self.vars(realip, "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0").split("|")[1] == "v6/112"
        assert self.vars(realip, "2001:db8:aaaa::1").split("|")[1] == "v6/48"
        assert self.vars(realip, "2a00::1") == "||"

    def test_cleared_networks_fall_back(self, realip, r):
        r.execute_command("REPSHEET.BLOCK", "10.1.2.0/24", "REASON", "narrow")
        r.execute_command("REPSHEET.MARK", "10.1.0.0/16", "REASON", "wide")
        wait_status(realip, 403, headers={"X-Real-IP": "10.1.2.3"})
        r.execute_command("REPSHEET.CLEAR", "10.1.2.0/24")   # its filter bit stays set
        wait_for(lambda: self.vars(realip, "10.1.2.3") == "mark|wide|ip:10.1.0.0/16", message="fallback")

    def test_correct_after_filters_are_rebuilt(self, realip, r):
        """Remove enough networks to trigger a rebuild in the expiry sweep."""
        pipe = r.pipeline(transaction=False)
        for i in range(3000):
            pipe.execute_command("REPSHEET.MARK", f"172.16.{i // 256}.{i % 256}/32", "TTL", "1")
        pipe.execute_command("REPSHEET.BLOCK", "192.0.2.0/24")
        pipe.execute()
        wait_for(lambda: metrics(realip)["repsheet_decisions"] == 3001, message="sync")
        wait_for(lambda: metrics(realip)["repsheet_decisions"] == 1, timeout=20, message="expiry sweep")
        assert self.vars(realip, "192.0.2.9").startswith("block|")
        assert self.vars(realip, "172.16.0.1") == "||"


class TestConfiguration:
    def test_block_status(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_block_status 429;"))
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(n, 429)

    def test_off_location_is_not_enforced(self, nginx_factory, r):
        n = nginx_factory(conf(locations="location /open { repsheet off; return 200 $repsheet_status; }"))
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(n, 403)
        res = n.get("/open")
        assert res.status_code == 200 and res.text == "block"

    def test_monitor_mode(self, nginx_factory, r):
        n = nginx_factory(conf(locations="location /m { repsheet monitor; try_files /index.html =404; }"))
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1", "REASON", "watch")
        wait_status(n, 403)
        before = metrics(n)
        assert n.get("/m").status_code == 200
        after = metrics(n)
        assert after['repsheet_requests_total{decision="block"}'] == before['repsheet_requests_total{decision="block"}'] + 1
        assert after["repsheet_blocked_total"] == before["repsheet_blocked_total"]
        assert "would block request" in n.error_log()

    def test_invalid_actor_type_rejected(self, tmp_path):
        from conftest import Nginx
        with pytest.raises(RuntimeError, match="invalid actor type"):
            Nginx(tmp_path, 1, conf("    repsheet_actor 'bad type' $cookie_x;"))

    def test_block_status_bounds(self, tmp_path):
        from conftest import Nginx
        with pytest.raises(RuntimeError, match="between 400 and 599"):
            Nginx(tmp_path, 1, conf("    repsheet_block_status 200;"))

    def test_without_redis_module_is_inert(self, nginx_factory, server):
        http = "    repsheet on;\n    server { listen 127.0.0.1:{port}; location / { } }"
        n = nginx_factory(http)
        assert n.get().status_code == 200


class TestActors:
    def test_cookie_actor(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor session $cookie_sid;"))
        r.execute_command("REPSHEET.BLOCK", "session:stolen-token", "REASON", "ato")
        wait_status(n, 403, cookies={"sid": "stolen-token"})
        assert n.get(cookies={"sid": "other"}).status_code == 200
        assert n.get().status_code == 200

    def test_actor_type_is_case_insensitive(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor API_Key $http_x_api_key;"))
        r.execute_command("REPSHEET.BLOCK", "api_key:k1")
        wait_status(n, 403, headers={"X-API-Key": "k1"})

    def test_actor_values_are_case_sensitive(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor session $cookie_sid;"))
        r.execute_command("REPSHEET.BLOCK", "session:ABC")
        r.execute_command("REPSHEET.MARK", "127.0.0.1")
        wait_for(lambda: n.get("/vars").text.startswith("mark"))
        assert n.get(cookies={"sid": "abc"}).status_code == 200

    def test_allow_on_ip_overrides_actor_block(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor session $cookie_sid;"))
        r.execute_command("REPSHEET.BLOCK", "session:s1")
        r.execute_command("REPSHEET.ALLOW", "127.0.0.1")
        wait_for(lambda: n.get("/vars", cookies={"sid": "s1"}).text.startswith("allow"))
        assert n.get(cookies={"sid": "s1"}).status_code == 200

    def test_ip_actor_from_header(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor ip $http_x_client_ip;"))
        r.execute_command("REPSHEET.BLOCK", "2001:db8::/32")
        wait_status(n, 403, headers={"X-Client-IP": "2001:db8:1::5"})
        assert n.get(headers={"X-Client-IP": "2001:db9::5"}).status_code == 200
        assert n.get(headers={"X-Client-IP": "garbage"}).status_code == 200

    def test_ip_actor_from_header_rejects_networks(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_actor ip $http_x_client_ip;"))
        r.execute_command("REPSHEET.BLOCK", "198.51.100.0/24")
        wait_status(n, 403, headers={"X-Client-IP": "198.51.100.7"})
        # Network notation from a request is ignored rather than matched.
        assert n.get("/vars", headers={"X-Client-IP": "198.51.100.0/24"}).text == "||"

    def test_location_actors_override_inherited(self, nginx_factory, r):
        n = nginx_factory(conf(
            "    repsheet_actor session $cookie_sid;",
            "location /api { repsheet_actor api_key $http_x_api_key; try_files /index.html =404; }",
        ))
        r.execute_command("REPSHEET.BLOCK", "session:s1")
        wait_status(n, 403, cookies={"sid": "s1"})
        assert n.get("/api", cookies={"sid": "s1"}).status_code == 200


class TestProxies:
    def test_forwarded_for_is_not_trusted_by_default(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        r.execute_command("REPSHEET.ALLOW", "9.9.9.9")
        wait_status(nginx, 403)
        # A client cannot launder itself through a whitelisted address.
        assert nginx.get(headers={"X-Forwarded-For": "9.9.9.9"}).status_code == 403

    def test_realip_from_trusted_proxy(self, nginx_factory, r):
        n = nginx_factory(conf(
            "    set_real_ip_from 127.0.0.1;\n"
            "    real_ip_header X-Forwarded-For;\n"
            "    real_ip_recursive on;"
        ))
        r.execute_command("REPSHEET.BLOCK", "2001:db8::/32")
        wait_status(n, 403, headers={"X-Forwarded-For": "2001:db8::1"})
        assert n.get(headers={"X-Forwarded-For": "198.51.100.1"}).status_code == 200
        # Left-most spoofed entries are ignored; the last untrusted hop is used.
        assert n.get(headers={"X-Forwarded-For": "2001:db8::1, 198.51.100.1"}).status_code == 200


    def test_realip_in_location(self, nginx_factory, r):
        n = nginx_factory(conf(locations=(
            "location /behind-proxy {\n"
            "    set_real_ip_from 127.0.0.1;\n"
            "    real_ip_header X-Real-IP;\n"
            "    try_files /index.html =404;\n"
            "}"
        )))
        r.execute_command("REPSHEET.BLOCK", "203.0.113.9")
        r.execute_command("REPSHEET.MARK", "127.0.0.1")
        wait_for(lambda: n.get("/vars").text.startswith("mark"))
        assert n.get("/behind-proxy", headers={"X-Real-IP": "203.0.113.9"}).status_code == 403
        assert n.get("/behind-proxy", headers={"X-Real-IP": "203.0.113.10"}).status_code == 200


class TestSync:
    def test_snapshot_on_startup(self, nginx_factory, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        for i in range(500):
            r.execute_command("REPSHEET.MARK", f"10.0.{i // 256}.{i % 256}")
        n = nginx_factory(conf())
        wait_status(n, 403)
        m = metrics(n)
        assert m["repsheet_decisions"] == 501
        assert m["repsheet_sync_snapshots_total"] == 1

    def test_snapshot_is_loaded_in_pages(self, nginx_factory, r):
        pipe = r.pipeline(transaction=False)
        for i in range(5000):
            pipe.execute_command("REPSHEET.MARK", f"10.1.{i // 256}.{i % 256}")
        pipe.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        pipe.execute()
        n = nginx_factory(conf())
        wait_status(n, 403)
        wait_for(lambda: metrics(n)["repsheet_decisions"] == 5001, message="all pages")
        assert metrics(n)["repsheet_sync_snapshots_total"] == 1
        assert "loaded snapshot with 5001 decisions" in n.error_log()

    def test_changes_during_paging_are_not_lost(self, nginx_factory, r):
        """Decisions added and cleared while nginx pages through the snapshot
        are repaired by replaying the change log from the first page."""
        import threading

        pipe = r.pipeline(transaction=False)
        for i in range(20000):
            pipe.execute_command("REPSHEET.MARK", f"10.2.{i // 256}.{i % 256}")
        pipe.execute()

        stop = threading.Event()

        def churn():
            k = 0
            while not stop.is_set():
                r.execute_command("REPSHEET.MARK", f"10.3.{k // 256 % 256}.{k % 256}")
                r.execute_command("REPSHEET.CLEAR", f"10.2.{k // 256 % 78}.{k % 256}")
                k += 1

        t = threading.Thread(target=churn)
        t.start()
        try:
            n = nginx_factory(conf())
            synced(n)
            time.sleep(0.3)
        finally:
            stop.set()
            t.join()

        expected = r.scard("{repsheet}:index")
        wait_for(lambda: metrics(n)["repsheet_decisions"] == expected, timeout=10,
                 message=f"nginx to hold exactly the {expected} decisions in valkey")

    def test_large_burst_pages_through_changes(self, nginx, r):
        pipe = r.pipeline(transaction=False)
        for i in range(2500):
            pipe.execute_command("REPSHEET.MARK", f"session:{i}")
        pipe.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        pipe.execute()
        wait_status(nginx, 403)
        m = metrics(nginx)
        assert m["repsheet_decisions"] == 2501
        assert m["repsheet_sync_snapshots_total"] == 1
        assert m["repsheet_sync_changes_total"] == 2501

    def test_flush_triggers_resync(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(nginx, 403)
        r.flushall()
        r.execute_command("REPSHEET.MARK", "127.0.0.1", "REASON", "after flush")
        wait_for(lambda: nginx.get("/vars").text == "mark|after flush|ip:127.0.0.1")
        assert metrics(nginx)["repsheet_decisions"] == 1
        assert metrics(nginx)["repsheet_sync_snapshots_total"] == 2

    def test_reload_keeps_state_without_new_snapshot(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(nginx, 403)
        nginx.reload()
        time.sleep(0.5)
        assert nginx.get().status_code == 403
        r.execute_command("REPSHEET.CLEAR", "127.0.0.1")
        wait_status(nginx, 200)
        assert metrics(nginx)["repsheet_sync_snapshots_total"] == 1

    def test_zone_full_is_reported(self, nginx_factory, r):
        n = nginx_factory(conf("    repsheet_zone_size 64k;"))
        synced(n)
        pipe = r.pipeline(transaction=False)
        for i in range(3000):
            pipe.execute_command("REPSHEET.MARK", f"session:{i:08d}", "REASON", "x" * 64)
        pipe.execute()
        wait_for(lambda: metrics(n)["repsheet_zone_alloc_failures_total"] > 0)
        assert n.get().status_code == 200
        assert "repsheet_zone_size" in n.error_log()


class TestResilience:
    def test_survives_redis_outage_and_reconnects(self, nginx_factory, tmp_path):
        port = free_port()
        s = Server(tmp_path, port=port)
        n = nginx_factory(conf(), redis_port=port)
        synced(n)
        s.client.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(n, 403)

        s.stop()
        # Decisions keep being enforced while the store is down.
        wait_for(lambda: "redis connection lost" in n.error_log())
        for _ in range(5):
            assert n.get().status_code == 403
            time.sleep(0.1)

        # A new, empty server: different epoch, so nginx resyncs and drops the block.
        s = Server(tmp_path, port=port)
        try:
            s.client.execute_command("REPSHEET.MARK", "127.0.0.1")
            wait_for(lambda: n.get("/vars").text.startswith("mark"), timeout=40)
            assert n.get().status_code == 200
        finally:
            s.stop()

    def test_starts_without_redis(self, nginx_factory, tmp_path):
        port = free_port()
        n = nginx_factory(conf(), redis_port=port)
        assert n.get().status_code == 200
        assert metrics(n)["repsheet_sync_up"] == 0
        s = Server(tmp_path, port=port)
        try:
            s.client.execute_command("REPSHEET.BLOCK", "127.0.0.1")
            wait_status(n, 403)
        finally:
            s.stop()

    def test_server_without_module(self, nginx_factory, tmp_path):
        s = Server(tmp_path, module=False)
        try:
            n = nginx_factory(conf(), redis_port=s.port)
            wait_for(lambda: metrics(n)["repsheet_sync_errors_total"] > 0)
            assert n.get().status_code == 200
            assert "is the repsheet module loaded" in n.error_log()
        finally:
            s.stop()

    def test_auth(self, nginx_factory, tmp_path):
        s = Server(tmp_path, password="s3cret")
        try:
            n = nginx_factory(conf("    repsheet_redis_auth s3cret;"), redis_port=s.port)
            s.client.execute_command("REPSHEET.BLOCK", "127.0.0.1")
            wait_status(n, 403)
        finally:
            s.stop()

    def test_bad_auth_is_logged(self, nginx_factory, tmp_path):
        s = Server(tmp_path, password="s3cret")
        try:
            n = nginx_factory(conf("    repsheet_redis_auth wrong;"), redis_port=s.port)
            wait_for(lambda: "AUTH failed" in n.error_log())
            assert n.get().status_code == 200
        finally:
            s.stop()

    def test_slow_redis_does_not_block_requests(self, nginx_factory, tmp_path):
        s = Server(tmp_path)
        try:
            n = nginx_factory(conf(), redis_port=s.port)
            synced(n)
            s.proc.send_signal(19)  # SIGSTOP: connections stay open, nothing answers
            try:
                start = time.monotonic()
                for _ in range(20):
                    assert n.get().status_code == 200
                assert time.monotonic() - start < 2
                wait_for(lambda: "did not answer" in n.error_log(), timeout=5)
            finally:
                s.proc.send_signal(18)  # SIGCONT
        finally:
            s.stop()


class TestMetrics:
    def test_counts(self, nginx, r):
        r.execute_command("REPSHEET.BLOCK", "127.0.0.1")
        wait_status(nginx, 403)
        before = metrics(nginx)
        for _ in range(3):
            nginx.get()
        after = metrics(nginx)
        assert after["repsheet_blocked_total"] - before["repsheet_blocked_total"] == 3
        assert after["repsheet_decisions"] == 1
        assert after["repsheet_zone_size_bytes"] == 32 * 1024 * 1024
        assert 0 < after["repsheet_zone_free_bytes"] < after["repsheet_zone_size_bytes"]
        assert after["repsheet_sync_last_success_timestamp_seconds"] > time.time() - 10

    def test_content_type(self, nginx):
        res = nginx.get("/metrics")
        assert res.headers["Content-Type"].startswith("text/plain")
        assert requests.post(nginx.url + "/metrics", timeout=5).status_code == 405
