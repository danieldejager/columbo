"""path-guard: the main-run workflow classifies the PR from the compare API, so a
PR that edits its own checks.yml cannot dodge the data/non-data split. Fake
values only."""
import json
import urllib.error

import pytest

from tools.checks import path_guard as D


def cmp(*files, status="ahead"):
    return {"status": status, "files": [
        {"filename": n, "status": s, "sha": "a" * 40, **extra} for n, s, extra in files]}


def run(monkeypatch, tmp_path, compare):
    if isinstance(compare, Exception):
        def boom(*a):
            raise compare
        monkeypatch.setattr(D, "fetch_compare", boom)
    else:
        monkeypatch.setattr(D, "fetch_compare", lambda *a: compare)
    monkeypatch.setenv("GH_TOKEN", "fake-token")
    rep = tmp_path / "rep.json"
    rc = D.main(["--repo-slug", "example/repo",
                 "--base-sha", "main", "--head-sha", "b" * 40, "--report", str(rep)])
    return rc, json.loads(rep.read_text())


def test_classify_compare_classes():
    assert D.classify_compare(cmp(("entries/a.fp", "added", {})))[0] == "data"
    assert D.classify_compare(cmp(("tools/checks/x.py", "modified", {})))[0] == "maintainer"
    cls, errs = D.classify_compare(cmp((".github/workflows/checks.yml", "modified", {}),
                                       ("entries/a.fp", "added", {})))
    assert cls == "mixed" and errs


def test_mixed_pr_editing_checks_yml_fails(monkeypatch, tmp_path):
    rc, rep = run(monkeypatch, tmp_path, cmp((".github/workflows/checks.yml", "modified", {}),
                                             ("entries/a.fp", "added", {})))
    assert rc == 1 and rep["status"] == "fail" and rep.get("change_class") == "mixed"


def test_rename_out_of_data_folder_is_mixed(monkeypatch, tmp_path):
    rc, rep = run(monkeypatch, tmp_path, cmp(("tools/A.fp", "renamed", {"previous_filename": "entries/a.fp"})))
    assert rc == 1 and rep.get("change_class") == "mixed"


def test_code_only_passes_with_notice_without_artifact(monkeypatch, tmp_path, capsys):
    rc, rep = run(monkeypatch, tmp_path, cmp(("tools/checks/x.py", "modified", {})))
    assert rc == 0 and rep["status"] == "pass" and rep["change_class"] == "maintainer"
    assert "::notice::" in capsys.readouterr().out


def test_data_only_passes(monkeypatch, tmp_path):
    rc, rep = run(monkeypatch, tmp_path, cmp(("entries/a.fp", "added", {}),
                                             ("bundles/b/manifest.txt", "modified", {})))
    assert rc == 0 and rep["status"] == "pass" and rep["change_class"] == "data"


def test_missing_token_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(D, "fetch_compare", lambda *a: cmp(("entries/a.fp", "added", {})))
    monkeypatch.delenv("GH_TOKEN", raising=False)
    rep = tmp_path / "rep.json"
    assert D.main(["--repo-slug", "example/repo", "--base-sha", "main", "--head-sha", "b" * 40,
                   "--report", str(rep)]) == 1


def test_data_only_with_bad_name_fails(monkeypatch, tmp_path):
    rc, rep = run(monkeypatch, tmp_path, cmp(("entries/bad name.txt", "added", {})))
    assert rc == 1 and rep["status"] == "fail"


@pytest.mark.parametrize("compare", [
    cmp(), cmp(status="identical"), cmp(("entries/a.fp", "added", {}), status="behind"),
    {"status": "ahead"}, {"status": "ahead", "files": "x"}, {},
    urllib.error.HTTPError("https://example.invalid", 500, "err", {}, None),
    urllib.error.URLError("down"), ValueError("bad json"),
])
def test_none_unexpected_or_api_error_fails_closed(monkeypatch, tmp_path, compare):
    rc, rep = run(monkeypatch, tmp_path, compare)
    assert rc == 1 and rep["status"] == "fail"
