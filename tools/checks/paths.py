"""Data-path-only rule over a list of changed files from git diff --raw."""
import re
import unicodedata

ALLOWED = (
    re.compile(r"^entries/[a-z0-9][a-z0-9-]{0,39}\.fp$"),
    re.compile(r"^entries/[a-z0-9][a-z0-9-]{0,39}\.provenance\.json$"),
    re.compile(r"^bundles/[a-z0-9-]{1,40}/manifest\.txt$"),
    re.compile(r"^bundles/[a-z0-9-]{1,40}/run-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$"),
)
DATA_PREFIXES = ("entries/", "bundles/")


def path_problem(path):
    if not path:
        return "empty path"
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in path):
        return "non-ASCII or control character in path"
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return "absolute path"
    if "\\" in path:
        return "backslash in path"
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return "path traversal or empty segment"
    if path == ".gitmodules" or parts[-1] == ".gitmodules":
        return "submodule configuration"
    return None


def classify(changes, head_tree_paths):
    """changes: list of (status, new_mode, path).

    Returns (errors, auto_merge_eligible, change_class) where change_class is
    "data" (only entries/ and bundles/), "maintainer" (only other paths),
    "mixed" (both, which fails) or "none".
    """
    errs = []
    fold = {}
    for p in head_tree_paths:
        key = unicodedata.normalize("NFKC", p).casefold()
        fold.setdefault(key, set()).add(p)
    has_data = has_other = False
    for status, mode, path in changes:
        prob = path_problem(path)
        if prob:
            errs.append("path: %r: %s" % (path, prob))
            continue
        if mode == "120000":
            errs.append("path: %s: symlinks are not allowed" % path)
            continue
        if mode == "160000":
            errs.append("path: %s: submodules are not allowed" % path)
            continue
        key = unicodedata.normalize("NFKC", path).casefold()
        if len(fold.get(key, ())) > 1:
            errs.append("path: %s: collides with another path by case or Unicode" % path)
            continue
        if path.startswith(DATA_PREFIXES):
            has_data = True
            if status != "D" and mode != "100644":
                errs.append("path: %s: file mode %s not allowed" % (path, mode))
            elif not any(r.match(path) for r in ALLOWED):
                errs.append("path: %s: unknown file type or bad name" % path)
        else:
            has_other = True
            if status != "D" and mode not in ("100644", "100755"):
                errs.append("path: %s: file mode %s not allowed" % (path, mode))
    if has_data and has_other:
        cls = "mixed"
        errs.append("path: PR mixes data and non-data paths; split it into a data PR and a maintainer PR")
    elif has_data:
        cls = "data"
    elif has_other:
        cls = "maintainer"
    else:
        cls = "none"
    eligible = cls == "data" and not errs
    return errs, eligible, cls


def check_changes(changes, head_tree_paths):
    errs, eligible, _ = classify(changes, head_tree_paths)
    return errs, eligible
