"""Fix 1: per-field type and pattern checks inside run JSON."""
import copy, json
from pathlib import Path
import pytest
from tools.checks import bundle as B

FIX = Path(__file__).resolve().parent / "fixtures" / "runs"


def good():
    return json.loads((FIX / "pass-run.json").read_text())


def test_pass_fixture_is_valid():
    assert B.check_run(good()) == []


def mutate(fn):
    r = good()
    fn(r)
    return B.check_run(r)


@pytest.mark.parametrize("label,fn,reason", [
    ("hostname in name", lambda r: r["exchanges"][0].__setitem__("name", "probe.example.invalid"), "name"),
    ("string port", lambda r: r["ports"].__setitem__("open_tcp", "22"), "ports.open_tcp"),
    ("port out of range", lambda r: r["ports"].__setitem__("closed_tcp", 70000), "ports.closed_tcp"),
    ("bool port", lambda r: r["ports"].__setitem__("closed_udp", True), "ports.closed_udp"),
    ("non-UUID run_id", lambda r: r.__setitem__("run_id", "fake-run-1"), "run_id"),
    ("upper-case UUID", lambda r: r.__setitem__("run_id", "0B5E7C1A-3F2D-4E8B-9A6C-1D2E3F405162"), "run_id"),
    ("non-hex packet bytes", lambda r: r["exchanges"][0]["sent"].__setitem__("hex", "zz" * 20), "sent.hex"),
    ("odd-length hex", lambda r: r["exchanges"][0]["sent"].__setitem__("hex", "abc"), "sent.hex"),
    ("len mismatch", lambda r: r["exchanges"][0]["sent"].__setitem__("len", 41), "sent.len"),
    ("path-like kind", lambda r: r["exchanges"][0].__setitem__("kind", "a/b/c"), "kind"),
    ("path-like flags", lambda r: r["exchanges"][0]["reply_parsed"].__setitem__("flags", "../x"), "flags"),
    ("long name", lambda r: r["exchanges"][0].__setitem__("name", "A" * 33), "name"),
    ("ip outside doc range", lambda r: r["exchanges"][0]["reply_parsed"].__setitem__("ip_src", "203.0.113.5"), "ip_src"),
    ("target not 192.0.2.1", lambda r: r.__setitem__("target", "192.0.2.2"), "target"),
    ("hex address outside documentation ranges", lambda r: r["exchanges"][0]["sent"].__setitem__("hex", "4500002800014000400600000a000001c0000201" + "00" * 20), "sent.hex"),
    ("string ttl", lambda r: r["exchanges"][0]["reply_parsed"].__setitem__("ip_ttl", "64"), "ip_ttl"),
    ("too many exchanges", lambda r: r.__setitem__("exchanges", r["exchanges"] * 300), "exchanges"),
    ("bool timeout as string", lambda r: r["exchanges"][0].__setitem__("timeout", "no"), "timeout"),
    ("batch key not in plan", lambda r: r["exchanges"][0].__setitem__("batch", "x"), "batch"),
])
def test_value_fail(label, fn, reason):
    errs = mutate(fn)
    assert errs, label
    assert any(reason in e for e in errs), (label, errs)
