"""path-guard: classify a pull request from GitHub's compare API, using the
path rules in paths.py. Runs from main only (workflow_run), never from the PR.

data only        pass
code only        pass with a notice (gated by maintainer review)
mixed or none    fail
anything else    fail closed (API error, unexpected status, unreadable data)
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tools.checks import paths as P  # noqa: E402

MAX_COMPARE_FILES = 250  # the compare API lists at most 300; anything near that fails closed
COMPARE_OK_STATUS = ("ahead", "diverged")
_STATUS_LETTER = {"added": "A", "modified": "M", "removed": "D", "renamed": "R",
                  "copied": "C", "changed": "M", "unchanged": "M"}


class GuardUnavailable(Exception):
    pass


def classify_compare(compare):
    """Returns (change_class, errors). The compare API gives no file modes, so
    modes stay with the checks workflow; here only paths count. A rename counts
    both its old and its new path."""
    if not isinstance(compare, dict) or compare.get("status") not in COMPARE_OK_STATUS:
        raise GuardUnavailable("unexpected compare status")
    files = compare.get("files")
    if not isinstance(files, list) or len(files) >= MAX_COMPARE_FILES:
        raise GuardUnavailable("change set too large or unreadable")
    changes = []
    for f in files:
        if not isinstance(f, dict) or not isinstance(f.get("filename"), str):
            raise GuardUnavailable("unreadable compare entry")
        letter = _STATUS_LETTER.get(f.get("status"))
        if letter is None:
            raise GuardUnavailable("unexpected file status in compare")
        changes.append((letter, "100644", f["filename"]))
        prev = f.get("previous_filename")
        if prev is not None:
            if not isinstance(prev, str):
                raise GuardUnavailable("unreadable compare entry")
            changes.append(("D", "100644", prev))
    errs, _, cls = P.classify(changes, [c[2] for c in changes])
    if cls == "none":
        errs = errs + ["path: no changed files"]
    return cls, errs


def fetch_compare(repo_slug, base, head, token):
    """GitHub REST compare (contents: read). Any non-200 response raises."""
    url = "https://api.github.com/repos/%s/compare/%s...%s?per_page=100" % (repo_slug, base, head)
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise GuardUnavailable("unexpected HTTP status")
        return json.loads(r.read(4 * 1024 * 1024))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-slug", required=True)
    ap.add_argument("--base-sha", required=True)
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args(argv)
    try:
        token = os.environ.get("GH_TOKEN")
        if not token:
            raise GuardUnavailable("no token for the compare API")
        cls, errs = classify_compare(fetch_compare(a.repo_slug, a.base_sha, a.head_sha, token))
        if errs or cls not in ("data", "maintainer"):
            rep = {"status": "fail", "change_class": cls, "errors": errs or ["path: no changed files"]}
        else:
            if cls == "maintainer":
                print("::notice::No data files changed. Code changes are gated by maintainer review.")
            rep = {"status": "pass", "change_class": cls, "errors": []}
    except Exception as e:
        msg = str(e) if isinstance(e, GuardUnavailable) else type(e).__name__
        rep = {"status": "fail", "change_class": "unknown",
               "errors": ["could not read the change set, failing closed: %s" % msg]}
    with open(a.report, "w") as f:
        json.dump(rep, f, indent=2)
    for e in rep["errors"]:
        print("ERROR:", e)
    return 0 if rep["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
