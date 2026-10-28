"""Regenerate the synthetic entry and bundle fixtures under tests/fixtures.

Everything here is synthetic: the runs come from tests/test_scrub.py's raw_run
(pktgen packets, documentation addresses), are scrubbed with tools/scrub.py,
and the entry block is what tools/checks/link.py derives from them.

Run from the repository root: python3 tests/make_fixtures.py
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
import test_scrub as TS  # noqa: E402
import tools.scrub as S  # noqa: E402
from tools.checks import link as L  # noqa: E402

FIX = HERE / "fixtures"


def make_bundle(label, firewall, shift=0):
    tmp = Path(tempfile.mkdtemp())
    raw = tmp / "raw"
    raw.mkdir()
    for n in range(6):
        run = TS.raw_run(n + shift)
        (raw / ("run-%d.json" % n)).write_text(json.dumps(run))
    out = FIX / "bundles" / label
    if out.exists():
        shutil.rmtree(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    S.scrub_bundle(raw, out, label=label, firewall=firewall, restart="0")
    shutil.rmtree(tmp)
    return out


def entry_text(name, firewall, runs, block):
    prov = {"name": name, "firewall": firewall, "runs": runs,
            "probe_version": "0.3.2", "derive_version": L.derive_version()}
    head = "".join("#@ %s: %s\n" % (k, prov[k]) for k in ("name", "firewall", "runs", "probe_version", "derive_version"))
    return head + block, json.dumps(prov) + "\n"


def write_entry(where, name, fp, side):
    d = FIX / where
    d.mkdir(parents=True, exist_ok=True)
    (d / (name + ".fp")).write_text(fp)
    if side is not None:
        (d / (name + ".provenance.json")).write_text(side)


def main():
    out = make_bundle("win11-fwon", "on")
    runs = [p.read_text() for p in sorted(out.glob("run-*.json"))]
    block = L.derive_block("win11-fwon", runs)
    fp, side = entry_text("win11-fwon", "on", 6, block)
    write_entry("pass", "win11-fwon", fp, side)
    fail_cases(fp, side, block)


def fail_cases(fp, side, block):
    """Hand made failures, each from the passing entry by one edit. The name
    of each fixture directory says what it breaks."""
    t1 = "T1(R=Y%DF=Y%T=80%TG=80%W=FFFF%"
    cases = {
        "unknown-field": fp.replace(t1, t1 + "ZZ=1%"),
        "duplicate-field": fp.replace(t1, t1 + "W=FFFF%"),
        "out-of-range": fp.replace(t1, t1.replace("TG=80", "TG=99")),
        "bad-provenance-key": fp.replace("#@ runs: 6\n", "#@ runs: 6\n#@ build: 1\n"),
        "comment-line": fp.replace("Fingerprint ", "# derive comment\nFingerprint "),
        "missing-group": fp.replace(block.splitlines()[-1] + "\n", ""),
        "crlf": fp.replace("\n", "\r\n"),
        "runs-below-minimum": fp.replace("#@ runs: 6", "#@ runs: 5"),
    }
    for where, text in cases.items():
        s2 = side.replace('"runs": 6', '"runs": 5') if where == "runs-below-minimum" else side
        write_entry("fail/" + where, "win11-fwon", text, s2)
    write_entry("fail/no-sidecar", "win11-fwon", fp, None)
    # Against an existing entry: the same block under another name, and a
    # sibling that differs from it in one field only.
    off_fp, off_side = rename(fp, side, "win11-fwoff", "off")
    write_entry("fail/copy", "win11-fwoff", off_fp, off_side)
    write_entry("fail/sibling", "win11-fwoff", off_fp.replace("IE(R=Y%DFI=N", "IE(R=Y%DFI=S"), off_side)
    far = off_fp
    for a, b in (("DFI=N", "DFI=S"), ("CD=Z", "CD=S"), ("RUD=G", "RUD=I")):
        far = far.replace(a, b)
    write_entry("pass-far", "win11-fwoff", far, off_side)


def rename(fp, side, name, firewall):
    fp = fp.replace("win11-fwon", name).replace("#@ firewall: on", "#@ firewall: " + firewall)
    side = side.replace("win11-fwon", name).replace('"firewall": "on"', '"firewall": "%s"' % firewall)
    return fp, side


if __name__ == "__main__":
    main()
