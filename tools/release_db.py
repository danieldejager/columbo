"""Build the release database from entries/ and write the release notes.

Usage: python3 tools/release_db.py --repo . --tag v1 --out-dir OUT

Writes OUT/columbo-<tag>.db, OUT/columbo-<tag>.names (one persona per line,
for check_db.py --expect) and OUT/notes.md. Every entry is checked first
(format, sidecar, duplicates, sibling separation); any failure stops the
build. The database itself comes from tools/derive/build_db.py assemble.
The entry count and names in the notes are read back from the built
database, never typed. Exit 0 only on success.
"""
import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "derive"))
from tools.checks import entry as E  # noqa: E402
import build_db as BD  # noqa: E402

TAG_RE = re.compile(r"^v[0-9]{1,4}(\.[0-9]{1,4}){0,2}$")


def check_entries(entries):
    """entries: {name: (fp_text, sidecar_text or None)}. Return errors."""
    errs, fps = [], {}
    for name in sorted(entries):
        fp, side = entries[name]
        errs += ["%s: %s" % (name, x) for x in E.check_entry(name, fp, side)]
        f = E.fingerprint_of(fp)
        if f:
            fps[name] = f
    names = sorted(fps)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            d = E.distance(fps[a], fps[b])
            if d < E.MIN_SIBLING_DISTANCE:
                errs.append("%s: too close to %s (differs in %d field)" % (b, a, d))
    return errs


# build_db's header says every block has '#@' provenance lines; release blocks
# carry only the '#@ persona' line, so the header is corrected here.
OLD_PROV_LINE = "# Provenance: '#@' lines before each block, sidecar <persona>.provenance.json."
NEW_PROV_LINE = ("# Provenance: one '#@ persona' line before each block; the full provenance"
                 " is in entries/<persona>.provenance.json in the source repository.")


def to_block(name, fp_text):
    """An entry as a build_db block: '#@ persona:' header plus the block."""
    return "#@ persona: %s\n%s" % (name, E.block_of(fp_text))


def read_entries(repo):
    out = {}
    d = Path(repo) / "entries"
    for p in sorted(d.glob("*.fp")) if d.is_dir() else []:
        side = p.with_name(p.name[:-3] + ".provenance.json")
        out[p.name[:-3]] = (p.read_bytes().decode("ascii"),
                            side.read_bytes().decode("ascii") if side.exists() else None)
    return out


def db_names(db_text):
    m = re.search(r"^#@ db-personas: (.*)$", db_text, re.M)
    if not m or m.group(1) == "none":
        return []
    return m.group(1).split(",")


def notes(template, tag, names, db_file, sha_file):
    def fw(n):
        return "firewall off" if n.endswith("-fwoff") else "firewall on"
    lst = "\n".join("  - `%s` (%s)" % (n, fw(n)) for n in names)
    return (template.replace("{{TAG}}", tag).replace("{{ENTRY_COUNT}}", str(len(names)))
            .replace("{{ENTRY_LIST}}", lst).replace("{{DB_FILE}}", db_file)
            .replace("{{SHA_FILE}}", sha_file))


def build(repo, tag, out_dir):
    if not TAG_RE.match(tag):
        raise SystemExit("bad tag %r" % tag)
    entries = read_entries(repo)
    if not entries:
        raise SystemExit("no entries")
    errs = check_entries(entries)
    if errs:
        for e in errs:
            print("FAIL: " + e, file=sys.stderr)
        raise SystemExit(1)
    blocks = [to_block(n, entries[n][0]) for n in sorted(entries)]
    try:
        text, skipped = BD.assemble(blocks, sorted(entries))
    except BD.BuildError as e:
        raise SystemExit("assemble refused: %s" % e)
    if skipped:
        raise SystemExit("assemble skipped entries: %s" % skipped)
    if OLD_PROV_LINE not in text:
        raise SystemExit("database header line not found")
    text = text.replace(OLD_PROV_LINE, NEW_PROV_LINE, 1)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    db_file = "columbo-%s.db" % tag
    (out / db_file).write_text(text, encoding="utf-8", newline="\n")
    names = db_names(text)
    if sorted(names) != sorted(entries):
        raise SystemExit("built database names do not match the entries")
    (out / ("columbo-%s.names" % tag)).write_text("".join(n + "\n" for n in names))
    tpl = (Path(repo) / "docs" / "release-notes.template.md").read_text(encoding="utf-8")
    (out / "notes.md").write_text(notes(tpl, tag, names, db_file, db_file + ".sha256"))
    return out / db_file


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--tag", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    print("wrote %s" % os.path.basename(str(build(a.repo, a.tag, a.out_dir))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
