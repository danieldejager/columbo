import io, json, os, shutil, subprocess, sys, tarfile
from pathlib import Path
import pytest
from tools.checks import bundle as B
from tools.checks import run_checks as R
from tools.checks import gate as G

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def sh(cwd, *a):
    subprocess.run(a, cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """A throwaway git repo whose base commit holds the passing FAKE-OS-1 entry."""
    d = tmp_path / "r"
    (d / "entries").mkdir(parents=True)
    sh(d, "git", "init", "-q", "-b", "main")
    sh(d, "git", "config", "user.email", "test@example.invalid")
    sh(d, "git", "config", "user.name", "Test")
    sh(d, "git", "config", "commit.gpgsign", "false")
    (d / "README.md").write_text("x\n")
    sh(d, "git", "add", ".")
    sh(d, "git", "commit", "-qm", "base")
    return d


def head(d):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True, check=True).stdout.strip()


def commit(d, msg="change"):
    sh(d, "git", "add", "-A")
    sh(d, "git", "commit", "-qm", msg)
    return head(d)


import entryfix as EF  # noqa: E402


def run_on(d, base):
    return R.run(str(d), base, head(d))


def with_base_entry(d):
    EF.add_valid(d)
    return commit(d, "add base entry")


# Pass case: an entry and its bundle in the same PR

def test_valid_entry_passes(repo):
    base = head(repo)
    EF.add_valid(repo)
    commit(repo)
    errors, eligible = run_on(repo, base)
    assert errors == []
    assert eligible


# Entry fail cases, each with its bundle present so only the defect fails

@pytest.mark.parametrize("case,reason", [
    ("unknown-field", "unknown field ZZ"),
    ("duplicate-field", "duplicate field W"),
    ("out-of-range", "value out of range for TG"),
    ("bad-provenance-key", "provenance key build is not allowed"),
    ("comment-line", "comments and blank lines are not allowed"),
    ("missing-group", "missing test groups: IE"),
    ("runs-below-minimum", "runs 5 is out of range"),
    ("no-sidecar", "missing sidecar"),
])
def test_entry_fail_cases(repo, case, reason):
    base = head(repo)
    EF.add_entry(repo, FIX / "fail" / case)
    EF.add_bundle(repo)
    commit(repo)
    errors, eligible = run_on(repo, base)
    assert any(reason in e for e in errors), errors
    assert not eligible


@pytest.mark.parametrize("case,reason", [
    ("copy", "duplicate fingerprint of win11-fwon"),
    ("sibling", "near-identical sibling of win11-fwon"),
])
def test_against_existing(repo, case, reason):
    base = with_base_entry(repo)
    EF.add_entry(repo, FIX / "fail" / case, "win11-fwoff")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any(reason in e for e in errors), errors


def test_far_entry_is_not_a_sibling(repo):
    base = with_base_entry(repo)
    EF.add_entry(repo, FIX / "pass-far", "win11-fwoff")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert not any("sibling" in e or "duplicate fingerprint" in e for e in errors), errors


# Bundle to entry link

def test_entry_without_bundle_fails_closed(repo):
    base = head(repo)
    EF.add_entry(repo)
    commit(repo)
    errors, eligible = run_on(repo, base)
    assert any("no bundle" in e for e in errors), errors
    assert not eligible


def test_bundle_already_in_main_is_not_enough(repo):
    EF.add_bundle(repo)
    base = commit(repo, "bundle first")
    EF.add_entry(repo)
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("no bundle" in e for e in errors), errors


def test_entry_block_must_equal_derive_output(repo):
    base = head(repo)
    EF.add_valid(repo)
    fp = repo / "entries" / "win11-fwon.fp"
    fp.write_text(fp.read_text().replace("CD=Z", "CD=S"))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("does not equal derive output" in e for e in errors), errors


def test_runs_count_must_match_bundle(repo):
    base = head(repo)
    EF.add_valid(repo)
    for name in ("win11-fwon.fp", "win11-fwon.provenance.json"):
        p = repo / "entries" / name
        p.write_text(p.read_text().replace("runs: 6", "runs: 7").replace('"runs": 6', '"runs": 7'))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("linked bundles hold 6 run files" in e for e in errors), errors


def test_restart_bundle_is_merged(repo):
    base = head(repo)
    EF.add_valid(repo)
    EF.add_bundle(repo, "win11-fwon-restart")
    commit(repo)
    errors, _ = run_on(repo, base)
    # Same runs twice: duplicate run ids are not refused by derive, but the
    # run count no longer matches, so the link fails closed.
    assert any("linked bundles hold 12 run files" in e for e in errors), errors


def test_bundle_firewall_must_match(repo):
    base = head(repo)
    EF.add_valid(repo)
    m = repo / "bundles" / "win11-fwon" / "manifest.txt"
    m.write_text(m.read_text().replace("firewall=on", "firewall=off"))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("firewall does not match" in e for e in errors), errors


# Path rule fail cases

def test_workflow_change_passes_but_not_eligible(repo):
    # Fix 3: maintainer-only change reports pass but is not eligible for auto-merge.
    base = head(repo)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "x.yml").write_text("name: x\n")
    commit(repo)
    rep = R.run_report(str(repo), base, head(repo))
    assert rep["status"] == "pass", rep
    assert rep["auto_merge_eligible"] is False
    assert rep["change_class"] == "maintainer"


def test_symlink_fails(repo):
    base = head(repo)
    os.symlink("../README.md", repo / "entries" / "FAKE-OS-2.fp")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("symlinks are not allowed" in e for e in errors), errors


def test_submodule_fails(repo):
    base = head(repo)
    blob = head(repo)
    sh(repo, "git", "update-index", "--add", "--cacheinfo", "160000,%s,entries/sub" % blob)
    (repo / ".gitmodules").write_text('[submodule "sub"]\n\tpath = entries/sub\n\turl = https://example.invalid/x\n')
    sh(repo, "git", "add", ".gitmodules")
    sh(repo, "git", "commit", "-qm", "sub")
    errors, _ = run_on(repo, base)
    assert any("submodules are not allowed" in e for e in errors), errors
    assert any("submodule configuration" in e for e in errors), errors


def test_dotdot_path_fails():
    from tools.checks import paths as P
    errs, eligible = P.check_changes([("A", "100644", "entries/../tools/x.fp")], [])
    assert errs and "traversal" in errs[0] and not eligible
    errs, _ = P.check_changes([("A", "100644", "/etc/x.fp")], [])
    assert "absolute path" in errs[0]


def test_unknown_extension_fails(repo):
    base = head(repo)
    (repo / "entries" / "FAKE-OS-2.txt").write_text("hello\n")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("unknown file type" in e for e in errors), errors


def test_binary_entry_fails(repo):
    base = head(repo)
    (repo / "entries" / "FAKE-OS-2.fp").write_bytes(b"\x00\xff\xfe")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("not ASCII" in e for e in errors), errors


# Run JSON allow-list

def load(n):
    return json.loads((FIX / "runs" / n).read_text())


def test_run_json_pass():
    assert B.check_run(load("pass-run.json")) == []


def test_run_json_cmdline_fails():
    errs = B.check_run(load("fail-cmdline.json"))
    assert any("'cmdline' is forbidden" in e for e in errs)


def test_run_json_unknown_nested_key_fails():
    errs = B.check_run(load("fail-nested-unknown.json"))
    assert any("reply_parsed: unknown key 'colour'" in e for e in errs), errs


# Fail closed

def test_gate_crash_fails(tmp_path):
    rep = tmp_path / "r.json"
    assert G.gate([sys.executable, "-c", "raise SystemExit(3)"], str(rep), 10) == 1


def test_gate_crash_with_stale_pass_report_fails(tmp_path):
    rep = tmp_path / "r.json"
    rep.write_text('{"status": "pass"}')
    assert G.gate([sys.executable, "-c", "raise RuntimeError('boom')"], str(rep), 10) == 1


def test_gate_timeout_fails(tmp_path):
    rep = tmp_path / "r.json"
    assert G.gate([sys.executable, "-c", "import time; time.sleep(5)"], str(rep), 0.5) == 1


def test_gate_missing_report_fails(tmp_path):
    assert G.gate([sys.executable, "-c", "pass"], str(tmp_path / "none.json"), 10) == 1


def test_gate_end_to_end_pass(repo, tmp_path):
    base = head(repo)
    EF.add_valid(repo)
    h = commit(repo)
    rep = tmp_path / "rep.json"
    cmd = [sys.executable, str(ROOT / "tools/checks/run_checks.py"), "--repo", str(repo),
           "--base-sha", base, "--head-sha", h, "--report", str(rep)]
    assert G.gate(cmd, str(rep), 60) == 0


# Reverse link: a changed bundle needs its entry and sidecar changed too

REV = "must change in the same pull request"


def test_bundle_changed_without_entry_fails(repo):
    EF.add_entry(repo)
    base = commit(repo, "entry first")
    EF.add_bundle(repo)
    commit(repo)
    errors, eligible = run_on(repo, base)
    assert any("bundles/win11-fwon" in e and REV in e for e in errors), errors
    assert not eligible


def test_restart_bundle_changed_without_entry_fails(repo):
    base = with_base_entry(repo)
    EF.add_bundle(repo, "win11-fwon-restart")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("bundles/win11-fwon-restart" in e and REV in e for e in errors), errors


def test_entry_sidecar_and_bundle_all_changed_passes(repo):
    base = head(repo)
    EF.add_valid(repo)
    commit(repo)
    errors, _ = run_on(repo, base)
    assert errors == []


def test_fp_changed_without_sidecar_fails(repo):
    base = with_base_entry(repo)
    EF.add_bundle(repo, "win11-fwon-restart")
    fp = repo / "entries" / "win11-fwon.fp"
    fp.write_text(fp.read_text().replace("#@ runs: 6", "#@ runs: 12"))
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("win11-fwon.provenance.json" in e and REV in e for e in errors), errors


def test_bundle_deleted_without_entry_fails(repo):
    base = with_base_entry(repo)
    sh(repo, "git", "rm", "-rq", "bundles/win11-fwon")
    commit(repo)
    errors, _ = run_on(repo, base)
    assert any("bundles/win11-fwon" in e and REV in e for e in errors), errors
