import time

import pytest
import redis


def get(r, actor):
    reply = r.execute_command("REPSHEET.GET", actor)
    if reply is None:
        return None
    if isinstance(reply, list):  # RESP2 flattens maps
        reply = dict(zip(reply[::2], reply[1::2]))
    return reply


def test_version(r):
    assert r.execute_command("REPSHEET.VERSION") == "6.0.0"


@pytest.mark.parametrize("command,status", [
    ("REPSHEET.ALLOW", "allow"),
    ("REPSHEET.BLOCK", "block"),
    ("REPSHEET.MARK", "mark"),
])
def test_set_and_get(r, command, status):
    assert r.execute_command(command, "1.1.1.1", "REASON", "test") == "OK"
    d = get(r, "1.1.1.1")
    assert d["actor"] == "ip:1.1.1.1"
    assert d["status"] == status
    assert d["reason"] == "test"
    assert d["expires"] == 0
    assert d["created"] > 0


def test_latest_decision_replaces_previous(r):
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "bad")
    r.execute_command("REPSHEET.ALLOW", "1.1.1.1", "REASON", "good")
    assert get(r, "1.1.1.1")["status"] == "allow"
    assert r.smembers("{repsheet}:index") == {"ip:1.1.1.1"}


@pytest.mark.parametrize("given,canonical", [
    ("1.2.3.4", "ip:1.2.3.4"),
    ("ip:1.2.3.4", "ip:1.2.3.4"),
    ("IP:1.2.3.4", "ip:1.2.3.4"),
    ("1.2.3.4/32", "ip:1.2.3.4"),
    ("10.1.2.3/8", "ip:10.0.0.0/8"),
    ("::ffff:1.2.3.4", "ip:1.2.3.4"),
    ("::ffff:10.0.0.0/104", "ip:10.0.0.0/8"),
    ("2001:DB8:0:0::1", "ip:2001:db8::1"),
    ("2001:db8:aa:bb:cc::1/64", "ip:2001:db8:aa:bb::/64"),
    ("Session:AbC", "session:AbC"),
    ("api_key:k-1:with:colons", "api_key:k-1:with:colons"),
])
def test_actor_canonicalization(r, given, canonical):
    r.execute_command("REPSHEET.BLOCK", given)
    assert get(r, given)["actor"] == canonical
    assert r.exists("{repsheet}:actor:" + canonical)


@pytest.mark.parametrize("bad", [
    "nonsense", "1.2.3.4/33", "ip:not-an-ip", "2001:db8::/129", ":value", "type:",
    "bad type:x", "fe80::1/129", "1:2:3", "x" * 40 + ":v", "t:" + "v" * 600, "t:a\x01b",
])
def test_invalid_actor(r, bad):
    with pytest.raises(redis.ResponseError, match="invalid actor"):
        r.execute_command("REPSHEET.BLOCK", bad)


def test_reason_length_limit(r):
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "x" * 1024)
    with pytest.raises(redis.ResponseError, match="reason exceeds"):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "x" * 1025)


@pytest.mark.parametrize("args", [
    ["TTL", "abc"], ["TTL", "0"], ["TTL", "-5"], ["TTL", "999999999999"],
    ["BOGUS", "x"], ["REASON"],
])
def test_bad_options(r, args):
    with pytest.raises(redis.ResponseError):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", *args)


def test_ttl_expires_and_cleans_index(r):
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "TTL", "1")
    d = get(r, "1.1.1.1")
    assert d["expires"] > time.time() * 1000
    assert 0 < r.pttl("{repsheet}:actor:ip:1.1.1.1") <= 1000
    time.sleep(1.2)
    assert get(r, "1.1.1.1") is None
    # Active expiry fires the keyspace event that cleans the index.
    for _ in range(50):
        if not r.sismember("{repsheet}:index", "ip:1.1.1.1"):
            break
        time.sleep(0.1)
    assert not r.sismember("{repsheet}:index", "ip:1.1.1.1")


def test_ttl_cleared_when_replaced_without_ttl(r):
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "TTL", "100")
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
    assert r.pttl("{repsheet}:actor:ip:1.1.1.1") == -1


def test_clear(r):
    r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
    assert r.execute_command("REPSHEET.CLEAR", "1.1.1.1") == 1
    assert r.execute_command("REPSHEET.CLEAR", "1.1.1.1") == 0
    assert get(r, "1.1.1.1") is None
    assert r.scard("{repsheet}:index") == 0


class TestCheck:
    def check(self, r, *actors):
        return r.execute_command("REPSHEET.CHECK", *actors)

    def test_none(self, r):
        assert self.check(r, "1.1.1.1") == ["none", None, None]

    def test_exact(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "exact")
        assert self.check(r, "1.1.1.1") == ["block", "exact", "ip:1.1.1.1"]

    def test_network_match(self, r):
        r.execute_command("REPSHEET.BLOCK", "10.0.0.0/8", "REASON", "net")
        assert self.check(r, "10.20.30.40") == ["block", "net", "ip:10.0.0.0/8"]
        assert self.check(r, "11.0.0.1")[0] == "none"

    def test_ipv6_network(self, r):
        r.execute_command("REPSHEET.BLOCK", "2001:db8:1:2::/64")
        assert self.check(r, "2001:db8:1:2:dead:beef::1")[0] == "block"
        assert self.check(r, "2001:db8:1:3::1")[0] == "none"

    def test_allow_overrides_block(self, r):
        r.execute_command("REPSHEET.BLOCK", "10.0.0.0/8", "REASON", "net")
        r.execute_command("REPSHEET.ALLOW", "10.1.1.1", "REASON", "partner")
        assert self.check(r, "10.1.1.1") == ["allow", "partner", "ip:10.1.1.1"]
        assert self.check(r, "10.1.1.2")[0] == "block"

    def test_block_overrides_mark(self, r):
        r.execute_command("REPSHEET.MARK", "1.1.1.1")
        r.execute_command("REPSHEET.BLOCK", "1.0.0.0/8")
        assert self.check(r, "1.1.1.1")[0] == "block"

    def test_most_specific_wins_tie(self, r):
        r.execute_command("REPSHEET.MARK", "1.0.0.0/8", "REASON", "wide")
        r.execute_command("REPSHEET.MARK", "1.1.0.0/16", "REASON", "narrow")
        assert self.check(r, "1.1.1.1")[1] == "narrow"

    def test_multiple_actors(self, r):
        r.execute_command("REPSHEET.BLOCK", "session:abc", "REASON", "stolen")
        assert self.check(r, "1.1.1.1", "session:abc") == ["block", "stolen", "session:abc"]
        r.execute_command("REPSHEET.ALLOW", "1.1.1.1")
        assert self.check(r, "1.1.1.1", "session:abc")[0] == "allow"


class TestSync:
    def snapshot(self, r):
        epoch, seq, entries = r.execute_command("REPSHEET.SNAPSHOT")
        return epoch, seq, {e[0]: e[1:] for e in entries}

    def changes(self, r, epoch, seq, count=None):
        args = ["COUNT", count] if count else []
        return r.execute_command("REPSHEET.CHANGES", epoch, seq, *args)

    def test_empty_dataset(self, r):
        epoch, seq, entries = self.snapshot(r)
        assert (epoch, seq, entries) == ("", 0, {})
        assert self.changes(r, "", 0) == ["OK", "", 0, []]

    def test_follows_log_from_empty_dataset(self, r):
        self.snapshot(r)
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch = self.snapshot(r)[0]
        ok, got_epoch, cursor, changes = self.changes(r, "", 0)
        assert (ok, got_epoch, cursor) == ("OK", epoch, 1)
        assert changes[0][:3] == [1, "set", "ip:1.1.1.1"]

    def test_empty_epoch_resyncs_once_log_is_incomplete(self, tmp_path):
        from conftest import Server
        s = Server(tmp_path, module_args=["changelog-max", "1"])
        try:
            s.client.execute_command("REPSHEET.BLOCK", "1.1.1.1")
            s.client.execute_command("REPSHEET.BLOCK", "2.2.2.2")
            assert s.client.execute_command("REPSHEET.CHANGES", "", 0) == ["RESYNC"]
            assert s.client.execute_command("REPSHEET.CHANGES", "", 1) == ["RESYNC"]
        finally:
            s.stop()

    def test_snapshot(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "a")
        r.execute_command("REPSHEET.MARK", "session:x", "REASON", "b", "TTL", "100")
        epoch, seq, entries = self.snapshot(r)
        assert len(epoch) == 16
        assert seq == 2
        assert entries["ip:1.1.1.1"] == ["block", "a", 0]
        assert entries["session:x"][:2] == ["mark", "b"]
        assert entries["session:x"][2] > 0

    def test_incremental_changes(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch, seq, _ = self.snapshot(r)
        assert self.changes(r, epoch, seq) == ["OK", epoch, seq, []]

        r.execute_command("REPSHEET.MARK", "2.2.2.2", "REASON", "r", "TTL", "60")
        r.execute_command("REPSHEET.CLEAR", "1.1.1.1")
        ok, _, cursor, changes = self.changes(r, epoch, seq)
        assert ok == "OK" and cursor == seq + 2
        assert changes[0][:5] == [seq + 1, "set", "ip:2.2.2.2", "mark", "r"]
        assert int(changes[0][5]) > 0
        assert changes[1][:3] == [seq + 2, "del", "ip:1.1.1.1"]

    def test_count_pages_through_changes(self, r):
        epoch, seq, _ = self.snapshot(r)
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch = self.snapshot(r)[0]
        for i in range(5):
            r.execute_command("REPSHEET.BLOCK", f"2.2.2.{i}")
        ok, _, cursor, changes = self.changes(r, epoch, 1, count=2)
        assert [c[0] for c in changes] == [2, 3] and cursor == 3
        ok, _, cursor, changes = self.changes(r, epoch, cursor, count=10)
        assert [c[0] for c in changes] == [4, 5, 6]

    def test_wrong_epoch_resyncs(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        assert self.changes(r, "0" * 16, 0) == ["RESYNC"]

    def test_flush_resyncs(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch, seq, _ = self.snapshot(r)
        r.flushall()
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        assert self.changes(r, epoch, seq) == ["RESYNC"]

    def test_cursor_ahead_resyncs(self, r):
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch, seq, _ = self.snapshot(r)
        assert self.changes(r, epoch, seq + 10) == ["RESYNC"]

    def test_bad_arguments(self, r):
        with pytest.raises(redis.ResponseError):
            r.execute_command("REPSHEET.CHANGES", "e", "-1")
        with pytest.raises(redis.ResponseError):
            r.execute_command("REPSHEET.CHANGES", "e", "0", "COUNT", "0")

    def test_notify(self, r):
        p = r.pubsub()
        p.subscribe("{repsheet}:notify")
        p.get_message(timeout=1)
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        msg = p.get_message(timeout=1)
        epoch = self.snapshot(r)[0]
        assert msg["data"] == f"{epoch}:1"
        p.close()


def test_trimmed_changelog_resyncs(tmp_path):
    from conftest import Server

    s = Server(tmp_path, module_args=["changelog-max", "3"])
    try:
        r = s.client
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1")
        epoch, seq, _ = r.execute_command("REPSHEET.SNAPSHOT")
        for i in range(5):
            r.execute_command("REPSHEET.BLOCK", f"2.2.2.{i}")
        assert r.xlen("{repsheet}:changes") == 3
        assert r.execute_command("REPSHEET.CHANGES", epoch, seq) == ["RESYNC"]
        assert r.execute_command("REPSHEET.CHANGES", epoch, 3)[0] == "OK"
    finally:
        s.stop()


def test_replicates_to_replica(server, r, tmp_path):
    from conftest import Server

    replica = Server(tmp_path)
    try:
        replica.client.replicaof("127.0.0.1", server.port)
        r.execute_command("REPSHEET.BLOCK", "1.1.1.1", "REASON", "repl", "TTL", "100")
        from conftest import wait_for
        wait_for(lambda: replica.client.execute_command("REPSHEET.GET", "1.1.1.1"), message="replication")
        assert replica.client.execute_command("REPSHEET.SNAPSHOT") == r.execute_command("REPSHEET.SNAPSHOT")
        with pytest.raises(redis.ReadOnlyError):
            replica.client.execute_command("REPSHEET.BLOCK", "2.2.2.2")
    finally:
        replica.stop()
