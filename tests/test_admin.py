"""repsheet-admin against a real Valkey with the module loaded."""

import html
import re

from conftest import wait_for


def decision(r, actor):
    reply = r.execute_command("REPSHEET.GET", actor)
    if isinstance(reply, list):
        reply = dict(zip(reply[::2], reply[1::2]))
    return reply


def text(resp):
    """Page text with tags removed, for loose assertions."""
    return html.unescape(re.sub(r"<[^>]+>", " ", resp.text))


class TestPages:
    def test_dashboard_counts(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "bad")
        r.execute_command("REPSHEET.BLOCK", "10.0.0.0/8")
        r.execute_command("REPSHEET.MARK", "session:abc")
        r.execute_command("REPSHEET.ALLOW", "2.2.2.2")
        page = wait_for(lambda: (p := admin.get("/")) and "2 blocked" in " ".join(text(p).split()) and p,
                        message="dashboard counts")
        t = " ".join(text(page).split())
        assert "1 marked" in t and "1 allowed" in t
        assert "session" in t and "ip" in t
        assert "Valkey" in t or "Redis" in t
        assert "6.0.0" in t

    def test_decisions_filters(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "credential stuffing")
        r.execute_command("REPSHEET.MARK", "2.2.2.2", "REASON", "scraper")
        r.execute_command("REPSHEET.BLOCK", "session:zzz")
        wait_for(lambda: "ip:2.2.2.2" in admin.get("/decisions").text, message="mirror")
        t = admin.get("/decisions?status=block").text
        assert "ip:1.1.1.1" in t and "session:zzz" in t and "ip:2.2.2.2" not in t
        t = admin.get("/decisions?type=session").text
        assert "session:zzz" in t and "ip:1.1.1.1" not in t
        t = admin.get("/decisions?q=STUFFING").text
        assert "ip:1.1.1.1" in t and "ip:2.2.2.2" not in t

    def test_pagination(self, r, admin):
        pipe = r.pipeline(transaction=False)
        for i in range(250):
            pipe.execute_command("REPSHEET.BLOCK", f"session:s{i:03d}")
        pipe.execute()
        wait_for(lambda: "250" in admin.get("/decisions").text, message="mirror")
        assert "page 1 of 3" in admin.get("/decisions").text
        last = admin.get("/decisions?page=3").text
        assert "session:s249" in last and "session:s000" not in last
        assert "page 3 of 3" in admin.get("/decisions?page=99").text

    def test_expired_decisions_hidden(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "TTL", "1")
        wait_for(lambda: "ip:1.1.1.1" in admin.get("/decisions").text, message="mirror")
        wait_for(lambda: "ip:1.1.1.1" not in admin.get("/decisions").text, timeout=4, message="expiry")

    def test_actor_shows_network_match(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "203.0.113.0/24", "REASON", "abuse", "BY", "alice")
        t = " ".join(text(admin.get("/actor", params={"q": "203.0.113.7"})).split())
        assert "ip:203.0.113.7" in t
        assert "because of ip:203.0.113.0/24 : abuse" in t
        assert "No decision is stored for exactly this actor" in t

        t = " ".join(text(admin.get("/actor", params={"q": "203.0.113.0/24"})).split())
        assert "by alice" in t and "abuse" in t

    def test_actor_invalid(self, admin):
        resp = admin.get("/actor", params={"q": "1.2.3.4/33"})
        assert resp.status_code == 200
        assert "Not a valid actor" in resp.text

    def test_actor_history(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "first", "BY", "alice")
        r.execute_command("REPSHEET.ALLOW", "1.1.1.1", "REASON", "second", "BY", "bob")
        r.execute_command("REPSHEET.CLEAR", "1.1.1.1", "BY", "carol")
        r.execute_command("REPSHEET.BLOCK", "9.9.9.9")
        t = text(admin.get("/actor", params={"q": "1.1.1.1"}))
        for s in ("first", "second", "alice", "bob", "carol", "cleared"):
            assert s in t
        assert "9.9.9.9" not in t

    def test_activity_pages(self, r, admin):
        for i in range(60):
            r.execute_command("REPSHEET.MARK", f"session:{i}", "BY", "loader")
        first = admin.get("/activity").text
        assert "session:59" in first and "session:9<" not in first
        older = re.search(r'href="/activity\?before=(\d+)"', first)
        assert older
        second = admin.get(f"/activity?before={older.group(1)}").text
        assert "session:0<" in second and "session:59" not in second

    def test_css_and_health(self, admin):
        assert admin.get("/static/app.css").headers["content-type"].startswith("text/css")
        assert admin.get("/healthz").text == "ok\n"


class TestChanges:
    def test_block_from_form(self, r, admin):
        resp = admin.post("/decisions", {"actor": "198.51.100.9/24", "status": "block",
                                         "reason": "from the UI", "ttl": "2h"})
        assert resp.status_code == 303
        assert resp.headers["location"] == "/actor?q=ip:198.51.100.0%2F24&done=set"
        d = decision(r, "198.51.100.0/24")
        assert d["status"] == "block" and d["reason"] == "from the UI" and d["by"] == "repsheet-admin"
        assert d["expires"] > 0
        page = admin.get(resp.headers["location"]).text
        assert "Decision saved." in page

    def test_change_and_clear(self, r, admin):
        admin.post("/decisions", {"actor": "session:abc", "status": "mark", "reason": "x", "ttl": ""})
        admin.post("/decisions", {"actor": "session:abc", "status": "allow", "reason": "y", "ttl": "never"})
        d = decision(r, "session:abc")
        assert d["status"] == "allow" and d["expires"] == 0
        resp = admin.post("/clear", {"actor": "session:abc"})
        assert resp.status_code == 303 and resp.headers["location"].endswith("done=cleared")
        assert decision(r, "session:abc") is None
        resp = admin.post("/clear", {"actor": "session:abc"})
        assert resp.headers["location"].endswith("done=absent")
        _, last = r.xrevrange("{repsheet}:changes", count=1)[0]
        assert last["op"] == "del" and last["by"] == "repsheet-admin"

    def test_form_errors(self, r, admin):
        cases = [
            ({"actor": "999.1.1.1", "status": "block"}, "Not a valid actor"),
            ({"actor": "1.1.1.1", "status": "none"}, "Choose block, allow or mark"),
            ({"actor": "1.1.1.1", "status": "block", "ttl": "soon"}, "is not a duration"),
            ({"actor": "1.1.1.1", "status": "block", "reason": "x" * 1025}, "longer than 1024"),
        ]
        for form, message in cases:
            resp = admin.post("/decisions", form)
            assert resp.status_code == 422, form
            assert message in html.unescape(resp.text), form
        assert r.scard("{repsheet}:index") == 0

    def test_user_header_is_author(self, r, admin_factory):
        admin = admin_factory(["--user-header", "X-Forwarded-User"])
        admin.post("/decisions", {"actor": "1.1.1.1", "status": "block"}, headers={"X-Forwarded-User": "dana"})
        assert decision(r, "1.1.1.1")["by"] == "dana"
        admin.post("/decisions", {"actor": "1.1.1.1", "status": "block"})
        assert decision(r, "1.1.1.1")["by"] == "repsheet-admin"

    def test_output_is_escaped(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "session:<script>x</script>", "REASON", "<img src=x onerror=alert(1)>",
                          "BY", "<b>eve</b>")
        for path in ("/", "/decisions", "/activity"):
            body = admin.get(path).text
            assert "<script>x" not in body and "<img src=x" not in body and "<b>eve" not in body, path
        body = admin.get("/actor", params={"q": "session:<script>x</script>"}).text
        assert "<script>x" not in body and "&#60;script&#62;x" in body


class TestSafety:
    def test_cross_origin_post_refused(self, r, admin):
        for headers in ({"Origin": "http://evil.example"}, {"Origin": "null"},
                        {"Origin": "", "Referer": "http://evil.example/"}):
            resp = admin.post("/decisions", {"actor": "1.1.1.1", "status": "block"}, headers=headers)
            assert resp.status_code == 403, headers
        resp = admin.session.post(admin.base + "/clear", data={"actor": "1.1.1.1"}, allow_redirects=False)
        assert resp.status_code == 403  # no Origin or Referer at all
        assert r.scard("{repsheet}:index") == 0

    def test_referer_accepted_without_origin(self, r, admin):
        resp = admin.session.post(admin.base + "/decisions", data={"actor": "1.1.1.1", "status": "block"},
                                  headers={"Referer": admin.base + "/new"}, allow_redirects=False)
        assert resp.status_code == 303

    def test_unknown_host_refused(self, admin):
        assert admin.get("/", headers={"Host": "rebind.evil.example"}).status_code == 421
        assert admin.get("/", headers={"Host": f"localhost:{admin.port}"}).status_code == 200

    def test_allowed_host(self, admin_factory):
        admin = admin_factory(["--allowed-host", "admin.example.com"])
        assert admin.get("/", headers={"Host": "admin.example.com"}).status_code == 200
        assert admin.get("/", headers={"Host": "other.example.com"}).status_code == 421

    def test_behind_https_proxy(self, r, admin_factory):
        admin = admin_factory(["--allowed-host", "admin.example.com", "--user-header", "X-Forwarded-User"])
        headers = {"Host": "admin.example.com", "Origin": "https://admin.example.com", "X-Forwarded-User": "erin"}
        resp = admin.post("/decisions", {"actor": "1.1.1.1", "status": "block"}, headers=headers)
        assert resp.status_code == 303
        assert decision(r, "1.1.1.1")["by"] == "erin"
        headers["Origin"] = "https://evil.example.com"
        assert admin.post("/clear", {"actor": "1.1.1.1"}, headers=headers).status_code == 403

    def test_security_headers(self, admin):
        h = admin.get("/").headers
        assert "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"

    def test_read_only(self, r, admin_factory):
        admin = admin_factory(["--read-only"])
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        assert admin.post("/decisions", {"actor": "2.2.2.2", "status": "block"}).status_code == 403
        assert admin.post("/clear", {"actor": "1.1.1.1"}).status_code == 403
        page = admin.get("/actor", params={"q": "1.1.1.1"}).text
        assert "Clear decision" not in page and 'action="/decisions"' not in page
        assert "read-only" in page
        assert decision(r, "1.1.1.1") is not None


class TestMirror:
    def test_follows_changes_and_resyncs_after_flush(self, r, admin):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        wait_for(lambda: "ip:1.1.1.1" in admin.get("/decisions").text, message="first change")
        r.flushall()
        r.execute_command("REPSHEET.BLOCK", "2.2.2.2")
        wait_for(lambda: (t := admin.get("/decisions").text) and "ip:2.2.2.2" in t and "ip:1.1.1.1" not in t,
                 message="resync after flush")

    def test_survives_server_restart(self, server, r, tmp_path):
        from conftest import Admin, Server

        s = Server(tmp_path)
        a = Admin(tmp_path, s.port)
        try:
            s.client.execute_command("REPSHEET.BLOCK", "1.1.1.1")
            wait_for(lambda: "ip:1.1.1.1" in a.get("/decisions").text, message="mirror")
            port = s.port
            s.stop()
            wait_for(lambda: a.get("/healthz").status_code == 503, message="unhealthy while down")
            assert "ip:1.1.1.1" in a.get("/decisions").text  # last known state still shown
            s = Server(tmp_path, port=port)
            s.client.execute_command("REPSHEET.BLOCK", "2.2.2.2")
            wait_for(lambda: "ip:2.2.2.2" in a.get("/decisions").text, timeout=15, message="reconnect")
            assert a.get("/healthz").status_code == 200
        finally:
            a.stop()
            s.stop()
