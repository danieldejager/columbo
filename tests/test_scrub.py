"""tools/scrub.py: a raw probe bundle in, a clean bundle out that passes the
bundle checks. Every fixture here is synthetic: packets come from pktgen with
documentation addresses, and every name is made up."""
import copy
import json
import struct
import sys
from pathlib import Path

import pytest

from tools.checks import bundle as B

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import pktgen as G  # noqa: E402

PROBE, TARGET = "203.0.113.5", "198.51.100.7"
LABEL = "fake-os-fwon"
DROP_TOP = ("timestamp", "cmdline", "dry_run", "probe_plan", "probe_method_doc", "extra_key")
SYN_OPTS = [["WScale", 10], ["NOP"], ["MSS", 1460], ["Timestamp", [4294967295, 0]], ["SAckOK"]]


def scrub():
    import tools.scrub as S
    return S


def reply_opts(ts):
    return [["MSS", 1460], ["NOP"], ["WScale", 8], ["SAckOK"], ["Timestamp", [ts, 4294967295]]]


def enc(opts):
    b = B.encode_options(opts)
    return b + b"\x00" * (-len(b) % 4)


def packet(p, trailer=b""):
    p = p + trailer
    return {"hex": p.hex(), "len": len(p), "summary": "IP / fake summary"}


def parsed(p, **extra):
    d = B.decode_ipv4(p)
    d.update(extra)
    return d


def tcp_ex(name, kind, i, t, sflags, sopts, reply_flags=None, ropts=None, seq=0, ip_id=0, trailer=b"", urg=0, res=0):
    seg = bytearray(G.tcp(40000 + i, 22, seq=1000 + i, flags=sflags, window=1024, options=enc(sopts), urgptr=urg))
    seg[12] |= res << 1
    s = G.fix_checksums(G.ip(PROBE, TARGET, 6, bytes(seg), ip_id=100 + i, ttl=50))
    ex = {"name": name, "kind": kind, "gap_before_sec": 0.1, "sent_at_offset_sec": t, "note": "extra",
          "sent": packet(s), "sent_parsed": parsed(s, options_raw=sopts, options="", reserved=res, urgptr=urg)}
    if reply_flags is None:
        ex.update(reply=None, reply_parsed=None, timeout=True)
        return ex
    ack = 1001 + i if "A" in reply_flags or "R" in reply_flags else 0
    r = G.ip(TARGET, PROBE, 6, G.tcp(22, 40000 + i, seq=seq, ack=ack, flags=reply_flags, window=65535 if ropts else 0,
                                     options=enc(ropts or [])), ip_id=ip_id, ttl=128)
    ex.update(reply=packet(r, trailer), timeout=False,
              reply_parsed=parsed(r, options_raw=ropts or [], options="M5B4NW8ST11" if ropts else "", reserved=0, urgptr=0))
    return ex


def echo_ex(name, i, code, pad, t, ip_id, tos=0):
    rest = struct.pack("!HH", 0x1234 + i, 0x0100 + i)
    s = G.ip(PROBE, TARGET, 1, G.icmp(8, code, rest, b"\x00" * pad), ip_id=200 + i, ttl=50, tos=tos)
    r = G.ip(TARGET, PROBE, 1, G.icmp(0, 0, rest, b"\x00" * pad), ip_id=ip_id, ttl=128, df=False)
    u = int.from_bytes(rest, "big")
    dirty = {"icmp_unused": u, "icmp_id": 0x1234 + i, "icmp_seq": 0x0100 + i}
    return {"name": name, "kind": "icmp", "gap_before_sec": 0.1, "sent_at_offset_sec": t,
            "sent": packet(s), "sent_parsed": parsed(s, **dirty),
            "reply": packet(r), "reply_parsed": parsed(r, **dirty), "timeout": False}


def u1_ex(t, ip_id):
    s = G.ip(PROBE, TARGET, 17, G.udp(40100, 33000, b"C" * 300), ip_id=0x1042, ttl=64, df=False)
    r = G.ip(TARGET, PROBE, 1, G.icmp(3, 3, b"\x00" * 4, s), ip_id=ip_id, ttl=128, df=False)
    emb = {"icmp_unused": 0, "embedded_ip_ttl": 64, "embedded_ip_id": 0x1042, "embedded_ip_len": len(s),
           "embedded_ip_sum": int.from_bytes(s[10:12], "big"), "embedded_ip_sum_ok": True,
           "embedded_udp_sum": int.from_bytes(s[26:28], "big"), "embedded_udp_data_hex": ("43" * 300)}
    return {"name": "U1", "kind": "udp", "gap_before_sec": 0.1, "sent_at_offset_sec": t,
            "sent": packet(s), "sent_parsed": parsed(s),
            "reply": packet(r), "reply_parsed": parsed(r, **emb), "timeout": False}


def raw_run(n):
    ex = []
    isn = (0x1A2B3C4D * (n + 3)) & 0xFFFFFFFF
    ipid = 3000 + 40 * n
    for i in range(6):
        ex.append(tcp_ex("SEQ%d" % (i + 1), "syn_seq", i, round(0.1 * i, 3), "S", SYN_OPTS, "SA", reply_opts(5000 + 10 * i),
                         seq=(isn + 250000 * i) & 0xFFFFFFFF, ip_id=ipid + i))
    ex.append(echo_ex("IE1", 6, 9, 120, 0.7, ipid + 6))
    ex.append(echo_ex("IE2", 7, 0, 150, 0.8, ipid + 7, tos=4))
    ex.append(u1_ex(0.9, ipid + 8))
    ex.append(tcp_ex("ECN", "ecn", 9, 1.0, "SEC", SYN_OPTS, "SAE", reply_opts(6000), seq=isn ^ 0xFFFF, ip_id=ipid + 9,
                     urg=63477, res=4))
    ex.append(tcp_ex("T2", "tcp_unusual", 10, 1.1, "", SYN_OPTS))
    ex.append(tcp_ex("T3", "tcp_unusual", 11, 1.2, "SFUP", SYN_OPTS))
    ex.append(tcp_ex("T4", "tcp_unusual", 12, 1.3, "A", SYN_OPTS, "R", ip_id=ipid + 12))
    ex.append(tcp_ex("T5", "tcp_unusual", 13, 1.4, "S", SYN_OPTS, "RA", ip_id=ipid + 13, trailer=b"\x00" * 6))
    ex.append(tcp_ex("T6", "tcp_unusual", 14, 1.5, "A", SYN_OPTS, "R", ip_id=ipid + 14))
    ex.append(tcp_ex("T7", "tcp_unusual", 15, 1.6, "FPU", SYN_OPTS, "RA", ip_id=ipid + 15))
    if n == 0:  # a reply with a wrong IP header checksum
        b = bytearray.fromhex(ex[2]["reply"]["hex"])
        b[10] ^= 0x5A
        ex[2]["reply"]["hex"] = b.hex()
    if n == 1:  # an earlier address rewrite left stale sums in the probe and its quote
        u1 = ex[8]
        s, r = bytearray.fromhex(u1["sent"]["hex"]), bytearray.fromhex(u1["reply"]["hex"])
        s[15] = r[28 + 15] = 9
        r[22:24] = b"\x00\x00"
        r[22:24] = struct.pack("!H", G.csum(bytes(r[20:])))
        r[10:12] = b"\x00\x00"
        r[10:12] = struct.pack("!H", G.csum(bytes(r[:20])))
        u1["sent"]["hex"], u1["reply"]["hex"] = s.hex(), r.hex()
        u1["sent_parsed"]["ip_src"] = "203.0.113.9"
    return {"run_id": "fake-run-%d" % n, "run_index": n, "tool": "probe.py", "tool_version": "0.3.2",
            "target": TARGET, "ports": {"open_tcp": 22, "closed_tcp": 1, "closed_udp": 33000},
            "timestamp": "2000-01-01T00:00:00Z",
            "cmdline": "/home/exampleuser/probe.py --target %s C:\\Users\\exampleuser\\out" % TARGET,
            "dry_run": False, "probe_plan": ["SEQ1"], "extra_key": 1,
            "probe_method_doc": "see /Users/exampleuser/doc; vendor M=0A1B2C", "exchanges": ex}


@pytest.fixture
def raw_dir(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    for n in range(6):
        (d / ("run-%d.json" % n)).write_text(json.dumps(raw_run(n)))
    for other in ("nmap.txt", "nmap.xml", "p0f.log", "p0f.txt", "probe.log", "tool-versions.txt"):
        (d / other).write_text("fake other file\n")
    return d


@pytest.fixture
def cleaned(raw_dir, tmp_path):
    out = tmp_path / "clean" / LABEL
    report = scrub().scrub_bundle(raw_dir, out, label=LABEL, firewall="on", restart="0")
    return out, report


def files_of(d):
    return {p.name: p.read_bytes() for p in sorted(d.iterdir())}


def runs_of(d):
    return [json.loads(p.read_text()) for p in sorted(d.glob("run-*.json"))]


def walk_keys(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from walk_keys(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk_keys(v)


def test_raw_fixture_fails_the_checks(raw_dir):
    errs = B.check_bundle_dir(LABEL, files_of(raw_dir))
    assert errs


def test_clean_output_passes_the_bundle_checks(cleaned):
    out, report = cleaned
    assert B.check_bundle_dir(LABEL, files_of(out)) == []
    assert report["runs_in"] == report["runs_out"] == 6


def test_only_manifest_and_run_files_are_written(cleaned):
    out, report = cleaned
    names = sorted(files_of(out))
    assert "manifest.txt" in names and len(names) == 7
    assert all(B.RUN_FILE_RE.match(n) for n in names if n != "manifest.txt")
    assert report["files_ignored"] == 6


@pytest.mark.parametrize("key", DROP_TOP + ("summary", "icmp_id", "icmp_seq", "note"))
def test_each_key_is_dropped(cleaned, key):
    out, report = cleaned
    for r in runs_of(out):
        assert key not in set(walk_keys(r))
    assert report["dropped"][key] > 0


def test_tool_target_and_run_id(cleaned):
    out, _ = cleaned
    seen = set()
    for p in sorted(out.glob("run-*.json")):
        r = json.loads(p.read_text())
        assert r["tool"] == "probe" and r["target"] == "192.0.2.1"
        assert B.UUID_RE.match(r["run_id"]) and p.name == "run-%s.json" % r["run_id"]
        seen.add(r["run_id"])
    assert len(seen) == 6


def test_run_ids_are_deterministic(raw_dir, tmp_path):
    S = scrub()
    a, b = tmp_path / "a" / LABEL, tmp_path / "b" / LABEL
    S.scrub_bundle(raw_dir, a, label=LABEL, firewall="on")
    S.scrub_bundle(raw_dir, b, label=LABEL, firewall="on")
    assert files_of(a) == files_of(b)


def test_manifest_has_allowed_keys_only(cleaned):
    out, _ = cleaned
    errs = []
    m = B.parse_manifest((out / "manifest.txt").read_bytes(), "m", errs)
    assert errs == []
    assert m["label"] == LABEL and m["firewall"] == "on" and m["runs"] == "6"
    assert m["probe_version"] == "0.3.2" and B.SEMVER_RE.match(m["derive_version"])


def _all_packets(runs):
    for r in runs:
        for e in r["exchanges"]:
            for side in ("sent", "reply"):
                if e.get(side):
                    yield e, side, bytes.fromhex(e[side]["hex"])


def test_checksums_are_recomputed(cleaned):
    out, report = cleaned
    for e, side, b in _all_packets(runs_of(out)):
        assert B.csum(b[:20]) == 0
        l4 = b[20:]
        if b[9] == 1:
            assert B.csum(l4) == 0
        else:
            assert B.csum(B._pseudo(b[12:16], b[16:20], b[9], len(l4)) + l4) == 0
    assert report["checksums_invalid_in"] == 2
    assert report["packets_rewritten"] > 0


def test_trailer_is_stripped(cleaned):
    out, report = cleaned
    for e, side, b in _all_packets(runs_of(out)):
        assert len(b) == int.from_bytes(b[2:4], "big") == e[side]["len"]
    assert report["trailers_stripped"] == 6


def test_addresses_are_192_0_2(cleaned):
    out, _ = cleaned
    for e, side, b in _all_packets(runs_of(out)):
        assert b[12:15] == b[16:19] == bytes([192, 0, 2])
        p = e[side + "_parsed"]
        assert p["ip_src"].startswith("192.0.2.") and p["ip_dst"].startswith("192.0.2.")


def test_icmp_echo_id_and_sequence_are_zeroed(cleaned):
    out, _ = cleaned
    n = 0
    for e, side, b in _all_packets(runs_of(out)):
        if b[9] == 1 and b[20] in (0, 8):
            assert b[24:28] == b"\x00" * 4
            assert e[side + "_parsed"]["icmp_unused"] == 0
            n += 1
    assert n == 24


def test_quoted_probe_still_matches_the_sent_probe(cleaned):
    out, _ = cleaned
    for r in runs_of(out):
        u1 = [e for e in r["exchanges"] if e["name"] == "U1"][0]
        s, q = bytes.fromhex(u1["sent"]["hex"]), bytes.fromhex(u1["reply"]["hex"])[28:]
        assert q == s
        assert u1["reply_parsed"]["embedded_ip_sum"] == int.from_bytes(s[10:12], "big")
        assert u1["reply_parsed"]["embedded_udp_sum"] == int.from_bytes(s[26:28], "big")


def test_user_paths_and_mac_prefixes(cleaned):
    S = scrub()
    text, users, macs = S.scrub_text("x /home/exampleuser/a C:\\Users\\exampleuser\\b /Users/exampleuser/c M=0A1B2C y")
    assert "exampleuser" not in text and "0A1B2C" not in text
    assert users == 3 and macs == 1
    assert "/home/" + S.USER_PLACEHOLDER in text
    out, report = cleaned
    blob = b"".join(files_of(out).values())
    assert b"exampleuser" not in blob and b"0A1B2C" not in blob
    assert report["user_path_hits"] == 6 * 3 and report["mac_prefix_hits"] == 6


def test_derive_output_identical_before_and_after_scrub(raw_dir, cleaned):
    S = scrub()
    out, _ = cleaned
    before = S.derive_text([json.loads(p.read_text()) for p in sorted(raw_dir.glob("run-*.json"))])
    after = S.derive_text(runs_of(out))
    assert "SEQ(" in before and "U1(" in before and "IE(" in before
    assert before == after


def test_derive_does_not_read_icmp_id_or_sequence(raw_dir):
    S = scrub()
    runs = [json.loads(p.read_text()) for p in sorted(raw_dir.glob("run-*.json"))]
    other = copy.deepcopy(runs)
    for r in other:
        for e in r["exchanges"]:
            for k in ("sent_parsed", "reply_parsed"):
                p = e.get(k) or {}
                if "icmp_id" in p:
                    p["icmp_id"], p["icmp_seq"] = 0xBEEF, 0xBEEF
    assert S.derive_text(runs) == S.derive_text(other)


def test_vendored_files_are_listed_with_their_sha256():
    import hashlib
    text = (ROOT / "tools" / "VENDORED.md").read_text()
    for p in sorted((ROOT / "tools" / "derive").glob("*.py")):
        assert p.name in text and hashlib.sha256(p.read_bytes()).hexdigest() in text
