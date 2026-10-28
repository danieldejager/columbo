"""Fix 2: bundle format per plan section 3 (directory, manifest.txt, 6 to 20 run JSONs)."""
import copy, json, subprocess, uuid
from pathlib import Path
import pytest
from tools.checks import bundle as B
from tools.checks import run_checks as R

FIX = Path(__file__).resolve().parent / "fixtures"
MANIFEST = (FIX / "bundle" / "manifest.txt").read_text()


def run_json(i, **extra):
    r = json.loads((FIX / "runs" / "pass-run.json").read_text())
    r["run_id"] = str(uuid.UUID(int=i + 1, version=4))
    r["run_index"] = i
    r.update(extra)
    return r


def bundle(n=6, manifest=None, extra_files=None, run_extra=None):
    files = {}
    for i in range(n):
        r = run_json(i, **(run_extra or {}))
        files["run-%s.json" % r["run_id"]] = (json.dumps(r, indent=2) + "\n").encode()
    m = MANIFEST if manifest is None else manifest
    files["manifest.txt"] = m.replace("runs=6", "runs=%d" % n).encode()
    files.update(extra_files or {})
    return files


def test_valid_bundle_passes():
    assert B.check_bundle_dir("fake-os-1", bundle()) == []


def test_twenty_runs_pass():
    assert B.check_bundle_dir("fake-os-1", bundle(20)) == []


@pytest.mark.parametrize("label,files,reason", [
    ("manifest with kernel", lambda: bundle(manifest=MANIFEST + "kernel=6.1.0\n"), "kernel"),
    ("manifest with target_os_build", lambda: bundle(manifest=MANIFEST + "target_os_build=1\n"), "target_os_build"),
    ("only 5 runs", lambda: bundle(5), "6 to 20"),
    ("21 runs", lambda: bundle(21), "6 to 20"),
    ("free-text line in manifest", lambda: bundle(manifest=MANIFEST + "captured on my laptop\n"), "not key=value"),
    ("tool-versions.txt with free text", lambda: bundle(extra_files={"tool-versions.txt": b"probe 1.0.0 built on a laptop\n"}), "tool-versions.txt"),
    ("unknown top-level file", lambda: bundle(extra_files={"notes.txt": b"hello\n"}), "notes.txt"),
    ("nested directory", lambda: bundle(extra_files={"sub/run.json": b"{}"}), "sub/run.json"),
    ("cmdline in a run", lambda: bundle(run_extra={"cmdline": ["probe"]}), "cmdline"),
    ("runs count mismatch", lambda: bundle(manifest=MANIFEST.replace("runs=6", "runs=7")), "runs"),
    ("label mismatch", lambda: bundle(manifest=MANIFEST.replace("label=fake-os-1", "label=fake-os-2")), "label"),
    ("host-like label", lambda: bundle(manifest=MANIFEST.replace("label=fake-os-1", "label=a.example.invalid")), "label"),
    ("bad arch", lambda: bundle(manifest=MANIFEST.replace("arch=x86_64", "arch=sparc")), "arch"),
    ("run_gap_s too low", lambda: bundle(manifest=MANIFEST.replace("run_gap_s=300", "run_gap_s=5")), "run_gap_s"),
    ("missing derive_version", lambda: bundle(manifest=MANIFEST.replace("derive_version=1.0.0\n", "")), "derive_version"),
    ("duplicate key", lambda: bundle(manifest=MANIFEST + "firewall=on\n"), "duplicate"),
    ("ports differ from runs", lambda: bundle(manifest=MANIFEST.replace("open_tcp=22", "open_tcp=80")), "open_tcp"),
    ("run file name differs from run_id", lambda: {**{("run-%s.json" % uuid.UUID(int=99, version=4) if k.startswith("run-") and i == 0 else k): v for i, (k, v) in enumerate(bundle().items())}}, "run_id"),
])
def test_bundle_fail(label, files, reason):
    errs = B.check_bundle_dir("fake-os-1", files())
    assert errs, label
    assert any(reason in e for e in errs), (label, errs)


def sh(cwd, *a):
    subprocess.run(a, cwd=cwd, check=True, capture_output=True)


def test_end_to_end_entry_with_bundle(tmp_path):
    d = tmp_path / "r"
    d.mkdir()
    sh(d, "git", "init", "-q", "-b", "main")
    sh(d, "git", "config", "user.email", "test@example.invalid")
    sh(d, "git", "config", "user.name", "Test")
    (d / "README.md").write_text("x\n")
    sh(d, "git", "add", ".")
    sh(d, "git", "commit", "-qm", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
    import entryfix
    bd = entryfix.add_valid(d)
    sh(d, "git", "add", "-A")
    sh(d, "git", "commit", "-qm", "entry")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
    res = R.run(str(d), base, head)
    errors, eligible = res[0], res[1]
    assert errors == [], errors
    assert eligible
    # A bad run in the bundle fails end to end.
    (bd / "notes.txt").write_text("hello\n")
    sh(d, "git", "add", "-A")
    sh(d, "git", "commit", "-qm", "bad")
    head2 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
    errors2 = R.run(str(d), base, head2)[0]
    assert any("notes.txt" in e for e in errors2), errors2
