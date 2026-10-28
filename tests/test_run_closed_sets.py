"""Review of fix 1: null probe, closed identifier sets and packet structure."""
import json
import sys
from pathlib import Path

import pytest

from tools.checks import bundle as B

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pktgen as G  # noqa: E402

FIX = HERE / "fixtures" / "runs"


def load(name):
    return json.loads((FIX / name).read_text())


def test_null_probe_with_empty_flags_passes():
    assert B.check_run(load("pass-null-probe.json")) == []


def test_icmp_id_and_seq_not_required():
    r = load("pass-run.json")
    for e in r["exchanges"]:
        for k in ("sent_parsed", "reply_parsed"):
            if e.get(k):
                assert "icmp_id" not in e[k] and "icmp_seq" not in e[k]
    assert B.check_run(r) == []


def test_every_listed_name_kind_and_option_is_accepted():
    for n in ("SEQ1", "SEQ2", "SEQ3", "SEQ4", "SEQ5", "SEQ6", "ECN", "IE1", "IE2",
              "T2", "T3", "T4", "T5", "T6", "T7", "U1"):
        assert n in B.EXCHANGE_NAMES
    assert B.EXCHANGE_KINDS == {"ecn", "icmp", "syn_seq", "tcp_unusual", "udp"}
    assert B.OPTION_NAMES == {"EOL", "MSS", "NOP", "SAckOK", "Timestamp", "WScale"}
    assert B.TOOL_NAME == "probe"


def first(r):
    return r["exchanges"][0]


def bad_packet(b):
    return lambda r: first(r).__setitem__("sent", {"hex": b.hex(), "len": len(b)})


A, T = "192.0.2.10", "192.0.2.1"
GOOD_SENT = G.ip(A, T, 6, G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=100)


@pytest.mark.parametrize("label,fn,reason", [
    ("name example.com", lambda r: first(r).__setitem__("name", "example.com"), "name"),
    ("name jdoe-laptop", lambda r: first(r).__setitem__("name", "jdoe-laptop"), "name"),
    ("tool dc01.corp", lambda r: r.__setitem__("tool", "dc01.corp"), "tool"),
    ("flags jdoe-laptop", lambda r: first(r)["reply_parsed"].__setitem__("flags", "jdoe-laptop"), "flags"),
    ("unknown kind", lambda r: first(r).__setitem__("kind", "custom"), "kind"),
    ("unknown option name", lambda r: first(r)["sent_parsed"].__setitem__("options_raw", [["Note", 1]]), "options_raw"),
    ("non-IPv4 hex", bad_packet(b"\x00" * 300), "sent.hex"),
    ("trailer after a valid packet", bad_packet(GOOD_SENT + b"\x00" * 6), "sent.hex"),
    ("3000-byte packet", bad_packet(G.ip(A, T, 17, G.udp(40001, 1, b"C" * 2972))), "sent.hex"),
    ("protocol not tcp, udp or icmp", bad_packet(G.ip(A, T, 47, b"\x00" * 20)), "sent.hex"),
    ("hex ttl differs from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=100, ttl=63)), "ip_ttl"),
    ("hex seq differs from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 22, seq=1001, flags="S", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=100)), "seq"),
    ("hex ip_id differs from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=101)), "ip_id"),
    ("hex flags differ from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 22, seq=1000, flags="SA", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=100)), "flags"),
    ("hex window differs from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 22, seq=1000, flags="S", window=1025, options=b"\x02\x04\x05\xb4"), ip_id=100)), "window"),
    ("hex port differs from parsed", bad_packet(G.ip(A, T, 6, G.tcp(40000, 23, seq=1000, flags="S", window=1024, options=b"\x02\x04\x05\xb4"), ip_id=100)), "dport"),
])
def test_closed_sets_and_packet_fail(label, fn, reason):
    r = load("pass-run.json")
    fn(r)
    errs = B.check_run(r)
    assert errs, label
    assert any(reason in e for e in errs), (label, errs)


def test_good_sent_matches_fixture():
    assert first(load("pass-run.json"))["sent"]["hex"] == GOOD_SENT.hex()
