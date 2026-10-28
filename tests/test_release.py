"""Release build: entries to database, notes, and the release workflow shape."""
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import entryfix as EF
from tools import release_db as RD
from tools.checks import entry as E

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "release.yml"
CHECK_DB = ROOT / "tools" / "derive" / "check_db.py"


def repo_with(tmp_path, *srcs):
    d = tmp_path / "r"
    (d / "docs").mkdir(parents=True)
    shutil.copy(ROOT / "docs" / "release-notes.template.md", d / "docs")
    for src, name in srcs:
        EF.add_entry(d, src, name)
    return d


def test_persona_list_matches_build_db():
    sys.path.insert(0, str(ROOT / "tools" / "derive"))
    import build_db
    assert tuple(build_db.PERSONA_ORDER) == E.PERSONAS


def test_assemble_builds_a_database_check_db_accepts(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "pass", "win11-fwon"), (EF.FIX / "pass-far", "win11-fwoff"))
    db = RD.build(d, "v1", tmp_path / "out")
    assert db.name == "columbo-v1.db"
    text = db.read_text()
    assert "#@ db-personas: win11-fwon,win11-fwoff" in text
    assert E.block_of((EF.FIX / "pass" / "win11-fwon.fp").read_text()) in text
    rc = subprocess.run([sys.executable, str(CHECK_DB), str(db), "--expect",
                         str(tmp_path / "out" / "columbo-v1.names")]).returncode
    assert rc == 0
    notes = (tmp_path / "out" / "notes.md").read_text()
    assert "- 2 entries" in notes and "`win11-fwon` (firewall on)" in notes
    assert "`win11-fwoff` (firewall off)" in notes
    assert "columbo-v1.db.sha256" in notes and "{{" not in notes


def test_bad_entry_stops_the_build(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "fail" / "unknown-field", "win11-fwon"))
    with pytest.raises(SystemExit):
        RD.build(d, "v1", tmp_path / "out")
    assert not (tmp_path / "out" / "columbo-v1.db").exists()


def test_siblings_stop_the_build(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "pass", "win11-fwon"), (EF.FIX / "fail" / "sibling", "win11-fwoff"))
    with pytest.raises(SystemExit):
        RD.build(d, "v1", tmp_path / "out")


def test_check_db_failure_fails(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "pass", "win11-fwon"))
    db = RD.build(d, "v1", tmp_path / "out")
    db.write_text(db.read_text().replace("IE(", "# x\nIE("))
    rc = subprocess.run([sys.executable, str(CHECK_DB), str(db), "--expect",
                         str(tmp_path / "out" / "columbo-v1.names")], capture_output=True).returncode
    assert rc != 0


def test_bad_tag_refused(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "pass", "win11-fwon"))
    with pytest.raises(SystemExit):
        RD.build(d, "v1; rm", tmp_path / "out")


# Workflow shape (text checks, no YAML library)

def wf():
    return WF.read_text()


def test_release_trigger_is_workflow_dispatch_only():
    on = re.search(r"^on:\n((?:  .*\n|\n)+?)^\S", wf(), re.M).group(1)
    triggers = re.findall(r"^  ([a-z_]+):", on, re.M)
    assert triggers == ["workflow_dispatch"]


def test_release_permissions_minimal():
    t = wf()
    assert re.search(r"^permissions: \{\}$", t, re.M)
    assert t.count("contents: write") == 1
    assert re.findall(r"^\s+[a-z-]+: (?:write|read)$", t, re.M) == ["      contents: write"]
    assert t.count("\n  draft-release:") == 1 and len(re.findall(r"^  [a-z-]+:\n    runs-on", t, re.M)) == 1


def test_release_is_draft_only():
    t = wf()
    creates = [l for l in t.splitlines() if "gh release" in l]
    assert len(creates) == 1 and "gh release create" in creates[0] and "--draft" in creates[0]
    assert "gh release edit" not in t and "--draft=false" not in t and "publish" not in t.lower()


def test_release_uploads_exactly_db_and_sha256():
    t = wf()
    tail = t.split("gh release create", 1)[1]
    assert '"columbo-$TAG.db" "columbo-$TAG.db.sha256"' in tail
    assert tail.strip().endswith('"columbo-$TAG.db" "columbo-$TAG.db.sha256"')


def test_release_no_secrets_no_signing():
    t = wf().lower()
    for bad in ("secrets.", "cosign", "gpg", "sigstore", "signature", ".sig", "sign ", "signing",
                "private_key", "key:", "artifact", "pull_request"):
        assert bad not in t, bad
    assert "sign" not in t.replace("design", "")


def test_release_runs_checks_build_and_check_db():
    t = wf()
    assert "tools/release_db.py" in t and "tools/derive/check_db.py" in t
    assert "sha256sum" in t and "ref: main" in t and "persist-credentials: false" in t
    assert t.index("release_db.py") < t.index("check_db.py") < t.index("sha256sum") < t.index("gh release create")


def test_sp_isr_above_ff_and_ranges_accepted():
    base = (EF.FIX / "pass" / "win11-fwon.fp").read_text()
    ok = base.replace("SP=0%", "SP=10A-11C%").replace("ISR=AA%", "ISR=105-10F%")
    E.parse_fp(ok)
    for bad in ("SP=1000%", "SP=11C-10A%", "SP=10A-10A%", "SP=10a%"):
        with pytest.raises(E.EntryError):
            E.parse_fp(base.replace("SP=0%", bad))


def test_db_header_describes_persona_lines_only(tmp_path):
    d = repo_with(tmp_path, (EF.FIX / "pass", "win11-fwon"))
    text = RD.build(d, "v1", tmp_path / "out").read_text()
    assert "'#@' lines before each block" not in text
    assert "# Provenance: one '#@ persona' line before each block" in text
