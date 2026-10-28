"""Workflow 1 checks.

Usage: python3 run_checks.py --repo HEAD_CHECKOUT --base-sha SHA --head-sha SHA --report OUT.json

Reads the PR head only as data through git plumbing. Never executes PR files.
Writes a JSON report. Exit 0 only if every check passed.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tools.checks import entry as E  # noqa: E402
from tools.checks import paths as P  # noqa: E402
from tools.checks import bundle as B  # noqa: E402
from tools.checks import link as L  # noqa: E402

MAX_CHANGED = 200


REVERSE_MSG = "must change in the same pull request"


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, "-c", "core.quotepath=off", *args],
                          check=True, capture_output=True, timeout=60).stdout


def changed_files(repo, base, head):
    out = git(repo, "diff", "--raw", "-z", "--no-renames", "--no-ext-diff", base, head)
    toks = out.split(b"\0")
    res = []
    i = 0
    while i + 1 < len(toks) and toks[i]:
        meta = toks[i].decode("ascii").split()
        path = toks[i + 1].decode("utf-8", "surrogateescape")
        res.append((meta[4], meta[1], path))
        i += 2
    return res


def tree_paths(repo, ref):
    out = git(repo, "ls-tree", "-r", "-z", "--name-only", ref)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def read_blob(repo, ref, path):
    try:
        data = git(repo, "cat-file", "blob", "%s:%s" % (ref, path))
    except subprocess.CalledProcessError:
        return None
    if len(data) > E.MAX_FILE_BYTES:
        raise E.EntryError("%s larger than %d bytes" % (path, E.MAX_FILE_BYTES))
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise E.EntryError("%s is not ASCII text" % path)
    return text


def run(repo, base, head):
    rep = run_report(repo, base, head)
    return rep["errors"], rep["auto_merge_eligible"]


def run_report(repo, base, head):
    errors = []
    changes = changed_files(repo, base, head)
    if not changes:
        errors.append("no changes found")
    if len(changes) > MAX_CHANGED:
        errors.append("too many changed files")
    head_paths = tree_paths(repo, head)
    perr, eligible, cls = P.classify(changes, head_paths)
    errors += perr
    # Entries to check: any entry whose .fp or sidecar changed and is not deleted.
    bases = set()
    for status, mode, path in changes:
        if status == "D" or P.path_problem(path) or mode != "100644":
            continue
        if path.startswith("entries/") and path.endswith(".provenance.json"):
            bases.add(path[len("entries/"):-len(".provenance.json")])
        elif path.startswith("entries/") and path.endswith(".fp"):
            bases.add(path[len("entries/"):-len(".fp")])
    head_fp = {p[len("entries/"):-3]: p for p in head_paths
               if p.startswith("entries/") and p.endswith(".fp") and "/" not in p[len("entries/"):]}
    others = {}
    for b in head_fp:
        if b in bases:
            continue
        try:
            t = read_blob(repo, head, head_fp[b])
        except E.EntryError:
            continue
        fp = E.fingerprint_of(t) if t else None
        if fp:
            others[b] = fp
    labels = set()
    for status, mode, path in changes:
        parts = path.split("/")
        if len(parts) >= 3 and parts[0] == "bundles" and not P.path_problem(path):
            labels.add(parts[1])
    # Reverse link: a changed bundle <name> or <name>-restart (added, changed or
    # deleted) needs entries/<name>.fp and its sidecar changed, not deleted, in
    # the same PR. The entry is then in bases, so the link check runs on it.
    live = {path for status, mode, path in changes if status != "D"}
    for label in sorted(labels):
        name = label[:-len("-restart")] if label.endswith("-restart") else label
        for f in ("entries/%s.fp" % name, "entries/%s.provenance.json" % name):
            if f not in live:
                errors.append("bundles/%s changed: %s %s" % (label, f, REVERSE_MSG))
    pr_bundles = {}
    for label in sorted(labels):
        prefix = "bundles/%s/" % label
        members = [p for p in head_paths if p.startswith(prefix)]
        if not members:
            continue  # bundle deleted
        files = {}
        total = sum(int(git(repo, "cat-file", "-s", "%s:%s" % (head, p))) for p in members)
        if total > B.MAX_BUNDLE_BYTES or len(members) > 64:
            errors.append("%s: bundle too large" % prefix.rstrip("/"))
            continue
        for p in members:
            files[p[len(prefix):]] = git(repo, "cat-file", "blob", "%s:%s" % (head, p))
        berrs = B.check_bundle_dir(label, files)
        errors += berrs
        if not berrs:
            pr_bundles[label] = {
                "manifest": B.parse_manifest(files["manifest.txt"], label, []),
                "runs": [files[k].decode("utf-8") for k in sorted(files) if k != "manifest.txt"],
            }
    checked = {}
    for b in sorted(bases):
        try:
            fp_text = read_blob(repo, head, "entries/%s.fp" % b)
            side = read_blob(repo, head, "entries/%s.provenance.json" % b)
        except E.EntryError as e:
            errors.append("%s: format: %s" % (b, e))
            continue
        if fp_text is None:
            errors.append("%s: sidecar without .fp entry" % b)
            continue
        errs = E.check_entry(b, fp_text, side)
        errors += ["%s: %s" % (b, x) for x in errs]
        if not errs:
            prov, _, _ = E.parse_fp(fp_text)
            errors += ["%s: %s" % (b, x)
                       for x in L.check_link(b, prov, E.block_of(fp_text), pr_bundles)]
        fp = E.fingerprint_of(fp_text)
        if fp:
            checked[b] = fp
    pool = dict(others)
    for b in sorted(checked):
        for o, ofp in sorted(pool.items()):
            if o.casefold() == b.casefold() and o != b:
                errors.append("%s: duplicate name of %s" % (b, o))
        for o, ofp in sorted(pool.items()):
            d = E.distance(checked[b], ofp)
            if d == 0:
                errors.append("%s: duplicate fingerprint of %s" % (b, o))
            elif d < E.MIN_SIBLING_DISTANCE:
                errors.append("%s: near-identical sibling of %s (differs in %d field)" % (b, o, d))
        pool[b] = checked[b]
    return {"status": "fail" if errors else "pass", "errors": errors,
            "auto_merge_eligible": bool(eligible and not errors), "change_class": cls}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base-sha", required=True)
    ap.add_argument("--head-sha", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args(argv)
    report = run_report(a.repo, a.base_sha, a.head_sha)
    errors = report["errors"]
    with open(a.report, "w") as f:
        json.dump(report, f, indent=2)
    for e in errors:
        print("FAIL: " + e)
    if report["change_class"] == "maintainer" and not errors:
        print("maintainer-only change: not eligible for auto-merge; code-owner review required")
    print("status: %s; change class: %s; auto-merge eligible: %s"
          % (report["status"], report["change_class"], report["auto_merge_eligible"]))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
