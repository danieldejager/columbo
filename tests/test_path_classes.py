"""Fix 3: maintainer-only PRs pass (not eligible), data-only PRs are checked and eligible, mixed PRs fail."""
import json, os, shutil, subprocess, sys
from pathlib import Path
import pytest
from tools.checks import run_checks as R

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def sh(cwd, *a):
    subprocess.run(a, cwd=cwd, check=True, capture_output=True)


def rev(d):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "r"
    (d / "entries").mkdir(parents=True)
    sh(d, "git", "init", "-q", "-b", "main")
    sh(d, "git", "config", "user.email", "test@example.invalid")
    sh(d, "git", "config", "user.name", "Test")
    (d / "README.md").write_text("x\n")
    sh(d, "git", "add", ".")
    sh(d, "git", "commit", "-qm", "base")
    return d


def commit(d):
    sh(d, "git", "add", "-A")
    sh(d, "git", "commit", "-qm", "c")
    return rev(d)


def add_entry(d):
    import entryfix
    entryfix.add_valid(d)


def test_maintainer_only_passes_not_eligible(repo, tmp_path, capsys):
    base = rev(repo)
    (repo / "tools").mkdir()
    (repo / "tools" / "x.py").write_text("print('x')\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("a\n")
    h = commit(repo)
    out = tmp_path / "rep.json"
    rc = R.main(["--repo", str(repo), "--base-sha", base, "--head-sha", h, "--report", str(out)])
    rep = json.loads(out.read_text())
    printed = capsys.readouterr().out
    assert rc == 0
    assert rep["status"] == "pass" and rep["auto_merge_eligible"] is False
    assert rep["change_class"] == "maintainer"
    assert "maintainer-only change: not eligible for auto-merge; code-owner review required" in printed


def test_data_only_checked_and_eligible(repo):
    base = rev(repo)
    add_entry(repo)
    h = commit(repo)
    rep = R.run_report(str(repo), base, h)
    assert rep["status"] == "pass" and rep["auto_merge_eligible"] is True
    assert rep["change_class"] == "data"


def test_data_only_bad_entry_fails(repo):
    base = rev(repo)
    import entryfix
    entryfix.add_entry(repo, FIX / "fail" / "out-of-range")
    entryfix.add_bundle(repo)
    h = commit(repo)
    rep = R.run_report(str(repo), base, h)
    assert rep["status"] == "fail" and rep["auto_merge_eligible"] is False


def test_mixed_fails(repo):
    base = rev(repo)
    add_entry(repo)
    (repo / "tools").mkdir()
    (repo / "tools" / "x.py").write_text("print('x')\n")
    h = commit(repo)
    rep = R.run_report(str(repo), base, h)
    assert rep["status"] == "fail" and rep["change_class"] == "mixed"
    assert any("mixes data and non-data" in e for e in rep["errors"]), rep


def test_maintainer_symlink_still_fails(repo):
    base = rev(repo)
    (repo / "docs").mkdir()
    os.symlink("../README.md", repo / "docs" / "link.md")
    h = commit(repo)
    rep = R.run_report(str(repo), base, h)
    assert rep["status"] == "fail"
    assert any("symlinks are not allowed" in e for e in rep["errors"])


def test_maintainer_submodule_still_fails(repo):
    base = rev(repo)
    sh(repo, "git", "update-index", "--add", "--cacheinfo", "160000,%s,vendor/sub" % base)
    (repo / ".gitmodules").write_text('[submodule "s"]\n\tpath = vendor/sub\n\turl = https://example.invalid/x\n')
    sh(repo, "git", "add", ".gitmodules")
    sh(repo, "git", "commit", "-qm", "s")
    rep = R.run_report(str(repo), base, rev(repo))
    assert rep["status"] == "fail"
    assert any("submodule" in e for e in rep["errors"])


def test_dotdot_still_fails_for_maintainer_paths():
    from tools.checks import paths as P
    errs, eligible, cls = P.classify([("A", "100644", "docs/../tools/x.py")], [])
    assert errs and not eligible


def test_data_filenames_are_restricted():
    from tools.checks import paths as P
    good = ["entries/win11-fwon.fp", "entries/a.provenance.json", "bundles/b-1/manifest.txt",
            "bundles/b/run-12345678-1234-4abc-8def-123456789abc.json"]
    bad = ["entries/A.fp", "entries/LINUX-6.1.fp", "entries/a.txt", "entries/sub/a.fp", "entries/.a.fp",
           "bundles/B/manifest.txt", "bundles/b/other.txt", "bundles/b/run-1.json",
           "entries/a" + "x" * 40 + ".fp"]
    for p in good:
        errs, _, cls = P.classify([("A", "100644", p)], [p])
        assert cls == "data" and not errs, p
    for p in bad:
        errs, _, _ = P.classify([("A", "100644", p)], [p])
        assert errs, p
