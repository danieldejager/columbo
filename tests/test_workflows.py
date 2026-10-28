"""Static checks on the workflow files (text only, no YAML library)."""
import re
from pathlib import Path

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"
USES = re.compile(r"uses:\s*([^@\s]+)@(\S+)")


def text(name):
    return (WF / name).read_text()


def test_all_actions_github_owned_and_sha_pinned():
    for f in WF.glob("*.yml"):
        for owner_repo, ref in USES.findall(f.read_text()):
            assert owner_repo.startswith("actions/"), (f.name, owner_repo)
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (f.name, ref)


def test_no_pull_request_target_anywhere():
    for f in WF.glob("*.yml"):
        assert "pull_request_target" not in f.read_text()


def test_checks_workflow_holds_no_secret():
    t = text("checks.yml")
    assert "secrets." not in t
    assert "contents: read" in t and "write" not in t


def test_path_guard_workflow_shape():
    t = text("path-guard.yml")
    assert "workflow_run:" in t and "workflows: [checks]" in t and "types: [completed]" in t
    assert "github.event.workflow_run.event == 'pull_request'" in t
    # runs whatever the checks conclusion, so a PR cannot avoid it by failing checks
    assert "workflow_run.conclusion" not in t
    perms = re.search(r"^permissions:\n((?:  .+\n)+)", t, re.M).group(1).split("\n")
    assert sorted(p.strip() for p in perms if p.strip()) == ["contents: read", "statuses: write"]
    assert "head_sha" not in "".join(re.findall(r"ref:.*", t))
    assert "ref: main" in t
    assert "base/tools/checks/path_guard.py" in t
    assert "context=path-guard" in t
    assert 'if [ "$OUTCOME" = "success" ]; then state=success;' in t and "else state=failure;" in t
    guard = t.split("- name: Classify changed paths (fail closed)")[1].split("- name:")[0]
    assert "if:" not in guard and "continue-on-error" not in guard


def test_no_workflow_uses_any_repository_secret_or_artifact():
    for f in WF.glob("*.yml"):
        t = f.read_text()
        assert "secrets." not in t, f.name
        assert "artifact" not in t, f.name
