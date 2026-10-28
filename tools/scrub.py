"""Turn a raw probe bundle directory into a clean bundle directory that the
bundle checks accept.

Reads only run-*.json from the raw directory. Writes manifest.txt and one
run-<uuid>.json per run. Nothing else is ever copied. Standard library only.

    python3 tools/scrub.py RAW_DIR OUT_DIR --label LABEL --firewall on|off [--restart 0|1] [--report FILE]

OUT_DIR must not exist yet; its last path part should equal LABEL.
"""
import argparse
import hashlib
import json
import re
import sys
import uuid
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.checks import bundle as B  # noqa: E402

DERIVE_DIR = ROOT / "tools" / "derive"
TARGET = "192.0.2.1"
USER_PLACEHOLDER = "user"
USER_RES = (
    re.compile(r"(/home/)[^/\s\"']+"),
    re.compile(r"(/Users/)[^/\s\"']+"),
    re.compile(r"([A-Za-z]:\\+Users\\+)[^\\\s\"']+", re.I),
)
MAC_RE = re.compile(r"\bM=[0-9A-Fa-f]{6}\b")


def scrub_text(s):
    """Replace user names in home paths and drop M= MAC vendor prefixes.
    Returns (text, user hits, MAC prefix hits)."""
    users = 0
    for rx in USER_RES:
        s, n = rx.subn(lambda m: m.group(1) + USER_PLACEHOLDER, s)
        users += n
    s, macs = MAC_RE.subn("", s)
    return s, users, macs


def _count_text(o, acc):
    if isinstance(o, str):
        _, u, m = scrub_text(o)
        acc[0] += u
        acc[1] += m
    elif isinstance(o, dict):
        for v in o.values():
            _count_text(v, acc)
    elif isinstance(o, list):
        for v in o:
            _count_text(v, acc)


def _scrub_strings(o):
    if isinstance(o, str):
        return scrub_text(o)[0]
    if isinstance(o, dict):
        return {k: _scrub_strings(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_scrub_strings(v) for v in o]
    return o


def _inc_sum(old_sum, old, new):
    """RFC 1624 incremental update of a ones' complement checksum when the
    covered bytes change from old to new (equal length, even)."""
    s = ~old_sum & 0xFFFF
    for i in range(0, len(old), 2):
        s += (~int.from_bytes(old[i:i + 2], "big") & 0xFFFF) + int.from_bytes(new[i:i + 2], "big")
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _follow_sum(quoted, sent_old, sent_new):
    """Move a quoted checksum by the same ones' complement step as the sent
    probe's checksum moved, so equal stays equal and a given offset stays."""
    s = (~quoted & 0xFFFF) + (~sent_new & 0xFFFF) + sent_old
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _sums_valid(b):
    if len(b) < 20 or B.csum(b[:20]) != 0:
        return False
    l4 = b[20:]
    if b[9] == 1:
        return B.csum(l4) == 0
    if b[9] in (6, 17):
        if b[9] == 17 and l4[6:8] == b"\x00\x00":
            return True
        return B.csum(B._pseudo(b[12:16], b[16:20], b[9], len(l4)) + l4) == 0
    return True


class Scrubber:
    def __init__(self, target):
        self.amap = {target: TARGET} if target else {}
        self.stats = Counter()
        self.dropped = Counter()

    def addr(self, raw4):
        a = ".".join(map(str, raw4))
        if a not in self.amap:
            self.amap[a] = "192.0.2.%d" % (len(self.amap) + 2 - (TARGET in self.amap.values()))
        return bytes(int(x) for x in self.amap[a].split("."))

    def packet(self, pkt, parsed, sent=None):
        """Returns (clean packet dict, clean parsed dict)."""
        for k in pkt:
            if k not in B.PACKET_KEYS:
                self.dropped[k] += 1
        b = bytes.fromhex(pkt.get("hex", ""))
        n = int.from_bytes(b[2:4], "big") if len(b) >= 20 else len(b)
        if not _sums_valid(b[:n]):
            self.stats["checksums_invalid_in"] += 1
        orig = b
        if len(b) >= 20 and b[0] == 0x45:
            n = int.from_bytes(b[2:4], "big")
            if len(b) > n >= 20:
                b = b[:n]
                self.stats["trailers_stripped"] += 1
            b = bytearray(b)
            b[12:16], b[16:20] = self.addr(b[12:16]), self.addr(b[16:20])
            l4 = b[20:]
            if b[9] == 1 and len(l4) >= 8:
                if l4[0] in (0, 8):
                    l4[4:8] = b"\x00\x00\x00\x00"
                elif l4[0] == 3 and len(l4) >= 28 and l4[8] == 0x45:
                    q = l4[8:]
                    old = bytes(q[12:20])
                    new = self.addr(q[12:16]) + self.addr(q[16:20])
                    q[12:20] = new
                    so, sn = sent or (None, None)
                    pairs = [(10, 20)] + ([(26, 28)] if len(q) >= 28 and q[9] == 17 else [])
                    for at, need in pairs:
                        qs = int.from_bytes(q[at:at + 2], "big")
                        if not qs:
                            continue  # a zero sum stays zero
                        if so is not None and len(so) >= need and len(sn) >= need:
                            q[at:at + 2] = _follow_sum(qs, int.from_bytes(so[at:at + 2], "big"),
                                                       int.from_bytes(sn[at:at + 2], "big")).to_bytes(2, "big")
                        else:
                            q[at:at + 2] = _inc_sum(qs, old, new).to_bytes(2, "big")
                    l4[8:] = q
                l4[2:4] = b"\x00\x00"
                l4[2:4] = B.csum(bytes(l4)).to_bytes(2, "big")
            elif b[9] in (6, 17) and len(l4) >= (20 if b[9] == 6 else 8):
                at = 16 if b[9] == 6 else 6
                l4[at:at + 2] = b"\x00\x00"
                c = B.csum(B._pseudo(bytes(b[12:16]), bytes(b[16:20]), b[9], len(l4)) + bytes(l4))
                l4[at:at + 2] = (c or (0xFFFF if b[9] == 17 else 0)).to_bytes(2, "big")
            b[20:] = l4
            b[10:12] = b"\x00\x00"
            b[10:12] = B.csum(bytes(b[:20])).to_bytes(2, "big")
            b = bytes(b)
        if b != orig:
            self.stats["packets_rewritten"] += 1
        return {"hex": b.hex(), "len": len(b)}, self.parsed(parsed, b)

    def parsed(self, p, b):
        if not isinstance(p, dict):
            return p
        out = {}
        for k, v in p.items():
            if k in B.PARSED_KEYS:
                out[k] = v
            else:
                self.dropped[k] += 1
        if len(b) >= 20 and b[0] == 0x45:
            dec = B.decode_ipv4(b)
            out["ip_src"], out["ip_dst"] = dec["ip_src"], dec["ip_dst"]
            # The rebuild needs these; a null one is filled from the header bytes.
            for k in B.REQUIRED_PARSED + B.REQUIRED_L4.get(dec["l4"], ()):
                if out.get(k) is None and k in dec:
                    out[k] = dec[k]
                    self.stats["parsed_filled." + k] += 1
            l4 = b[20:]
            if b[9] == 1 and len(l4) >= 8:
                if l4[0] in (0, 8):
                    out["icmp_unused"] = 0
                elif l4[0] == 3 and len(l4) >= 28:
                    q = l4[8:]
                    if out.get("embedded_ip_sum") is not None:
                        out["embedded_ip_sum"] = int.from_bytes(q[10:12], "big")
                    if out.get("embedded_udp_sum") is not None and len(q) >= 28:
                        out["embedded_udp_sum"] = int.from_bytes(q[26:28], "big")
        return out

    def run(self, doc):
        for k in doc:
            if k not in B.RUN_KEYS or k == "run_id":
                if k != "run_id":
                    self.dropped[k] += 1
        out = {k: doc[k] for k in ("run_index", "tool_version") if k in doc}
        out["tool"] = B.TOOL_NAME
        out["target"] = TARGET
        if isinstance(doc.get("ports"), dict):
            out["ports"] = {k: v for k, v in doc["ports"].items() if k in B.PORTS_KEYS}
            for k in doc["ports"]:
                if k not in B.PORTS_KEYS:
                    self.dropped["ports." + k] += 1
        exs = []
        for e in doc.get("exchanges") or []:
            ce = {}
            sent = None
            if isinstance(e.get("sent"), dict) and "sent" in B.EXCHANGE_KEYS:
                ce["sent"], ce["sent_parsed"] = self.packet(e["sent"], e.get("sent_parsed"))
                sent = (bytes.fromhex(e["sent"].get("hex", "")), bytes.fromhex(ce["sent"]["hex"]))
            for k, v in e.items():
                if k not in B.EXCHANGE_KEYS:
                    self.dropped[k] += 1
                elif k == "sent" and isinstance(v, dict):
                    continue
                elif k == "reply" and isinstance(v, dict):
                    ce[k], ce[k + "_parsed"] = self.packet(v, e.get(k + "_parsed"), sent)
                elif k in ("sent_parsed", "reply_parsed"):
                    ce.setdefault(k, self.parsed(v, b"") if v is not None else None)
                else:
                    ce[k] = v
            exs.append(ce)
        out["exchanges"] = exs
        return _scrub_strings(out)


def run_uuid(label, run):
    body = json.dumps({k: v for k, v in run.items() if k != "run_id"}, sort_keys=True, separators=(",", ":"))
    h = bytearray(hashlib.sha256(("columbo-scrub\0%s\0%s" % (label, body)).encode()).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(h)))


def derive_version():
    text = (DERIVE_DIR / "_version.py").read_text()
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def scrub_bundle(raw_dir, out_dir, label, firewall, restart=None):
    raw_dir, out_dir = Path(raw_dir), Path(out_dir)
    if out_dir.exists():
        raise SystemExit("output directory already exists: %s" % out_dir)
    paths = sorted(raw_dir.glob("run-*.json"))
    files_ignored = sum(1 for p in raw_dir.iterdir() if p not in paths)
    docs = [json.loads(p.read_text(encoding="utf-8")) for p in paths]
    docs.sort(key=lambda d: (d.get("run_index", 0) if isinstance(d.get("run_index"), int) else 0))
    acc = [0, 0]
    _count_text(docs, acc)
    first = docs[0] if docs else {}
    target = first.get("target") if isinstance(first.get("target"), str) else None
    sc = Scrubber(target)
    runs = []
    for d in docs:
        r = sc.run(d)
        r = {"run_id": run_uuid(label, r), **r}
        runs.append(r)
    out_dir.mkdir(parents=True, mode=0o700)
    for r in runs:
        (out_dir / ("run-%s.json" % r["run_id"])).write_text(json.dumps(r, indent=1) + "\n", encoding="utf-8")
    m = [("label", label), ("firewall", firewall)]
    if restart is not None:
        m.append(("restart", str(restart)))
    m.append(("runs", str(len(runs))))
    for k in ("open_tcp", "closed_tcp", "closed_udp"):
        vals = {(r.get("ports") or {}).get(k) for r in runs}
        if len(vals) == 1 and isinstance(next(iter(vals)), int):
            m.append((k, str(vals.pop())))
    pv = {r.get("tool_version") for r in runs}
    if len(pv) == 1 and isinstance(next(iter(pv)), str):
        m.append(("probe_version", pv.pop()))
    m.append(("derive_version", derive_version()))
    (out_dir / "manifest.txt").write_text("".join("%s=%s\n" % kv for kv in m), encoding="ascii")
    return {
        "runs_in": len(docs), "runs_out": len(runs), "files_ignored": files_ignored,
        "checksums_invalid_in": sc.stats["checksums_invalid_in"],
        "packets_rewritten": sc.stats["packets_rewritten"],
        "trailers_stripped": sc.stats["trailers_stripped"],
        "parsed_filled": {k.split(".", 1)[1]: v for k, v in sorted(sc.stats.items()) if k.startswith("parsed_filled.")},
        "dropped": dict(sorted(sc.dropped.items())),
        "user_path_hits": acc[0], "mac_prefix_hits": acc[1],
    }


def _run_order(r):
    """An order that scrubbing does not change: run_index, then the send
    offsets and the reply ISNs and IP IDs (raw runs may share a run_index)."""
    key = []
    for e in r.get("exchanges") or []:
        p = e.get("reply_parsed") or {}
        key.append((str(e.get("name")), e.get("sent_at_offset_sec") or 0, p.get("seq") or 0, p.get("ip_id") or 0))
    return (r.get("run_index", 0) if isinstance(r.get("run_index"), int) else 0, key)


def derive_text(runs):
    """Vendored derive.py output for these runs, with run ids replaced by
    their position in run_index order, so raw and clean runs compare."""
    if str(DERIVE_DIR) not in sys.path:
        sys.path.insert(0, str(DERIVE_DIR))
    import derive as D
    runs = sorted(runs, key=_run_order)
    res = D.derive(runs, os_name="FAKE", os_build="0")
    text = D.render_personality(res)
    rep = json.dumps({"fields": res["fields"]}, sort_keys=True)
    for i, r in enumerate(runs):
        text = text.replace(str(r["run_id"]), "RUN%d" % i)
        rep = rep.replace(json.dumps(str(r["run_id"])), '"RUN%d"' % i)
    return text + rep


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("raw_dir", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--label", required=True)
    ap.add_argument("--firewall", required=True, choices=("on", "off"))
    ap.add_argument("--restart", choices=("0", "1"))
    ap.add_argument("--report", type=Path, help="write the counts report (JSON) here")
    a = ap.parse_args(argv)
    rep = scrub_bundle(a.raw_dir, a.out_dir, a.label, a.firewall, a.restart)
    files = {p.name: p.read_bytes() for p in a.out_dir.iterdir()}
    errs = B.check_bundle_dir(a.label, files)
    rep["check_errors"] = len(errs)
    if a.report:
        a.report.write_text(json.dumps(rep, indent=1) + "\n")
    print("runs %d in, %d out; check errors %d" % (rep["runs_in"], rep["runs_out"], len(errs)))
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
