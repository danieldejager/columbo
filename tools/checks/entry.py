"""Schema, format, range and consistency checks for Columbo entries.

An entry is `#@` provenance lines followed by exactly one personality block
in the form tools/derive/derive.py renders it (the `Fingerprint` line and one
line per test group). The derive comment lines are not part of an entry.
"""
import json
import re

# Persona names the release database accepts (tools/derive/build_db.py
# PERSONA_ORDER). Kept here as a copy so the checks stay standard library
# only; tests/test_entry_format.py asserts the two lists are equal.
PERSONAS = (
    "ubuntu2404",
    "ws2022-fwon", "ws2022-fwoff",
    "ws2019-fwon", "ws2019-fwoff",
    "ws2025-fwon", "ws2025-fwoff",
    "win11-fwon", "win11-fwoff",
)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
PROV_KEYS = ("name", "firewall", "runs", "probe_version", "derive_version")
MIN_RUNS = 6
MAX_RUNS = 40
# Provisional: a new entry must differ from every other entry in at least
# this many fields of the full field set.
MIN_SIBLING_DISTANCE = 2
MAX_FILE_BYTES = 16384

GROUPS = ("SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE")


def _hex(maxval, allow_empty=False):
    def check(v):
        if v == "" and allow_empty:
            return True
        return bool(re.fullmatch(r"[0-9A-F]{1,8}", v)) and int(v, 16) <= maxval
    return check


def _hex_or_range(maxval):
    h = _hex(maxval)

    def check(v):
        if "-" in v:
            lo, _, hi = v.partition("-")
            return h(lo) and h(hi) and int(lo, 16) < int(hi, 16)
        return h(v)
    return check


def _one_of(*opts):
    return lambda v: v in opts


def _ipid(v):
    return v in ("Z", "RD", "RI", "BI", "I") or _hex(0xFFFF)(v)


def _flags(v):
    order = "EUAPRSF"
    return all(c in order for c in v) and list(v) == sorted(set(v), key=order.index)


_opts = lambda v: bool(re.fullmatch(r"[A-Z0-9]{0,40}", v))
_ttl = _hex(0x1FF)
_tg = _one_of("20", "40", "80", "FF")
_yn = _one_of("Y", "N")
_q = _one_of("", "R", "U", "RU")

# Per group: (fields in render order, set of optional fields, value rules).
SEQ_RULES = {
    "SP": _hex_or_range(0xFFF), "GCD": _hex(0xFFFFFFFF), "ISR": _hex_or_range(0xFFF),
    "TI": _ipid, "CI": _ipid, "II": _ipid, "SS": _one_of("S", "O"),
    "TS": lambda v: v in ("U", "0", "1", "7", "8") or _hex(0x3F)(v),
}
ECN_RULES = {"R": _one_of("Y"), "DF": _yn, "T": _ttl, "TG": _tg, "W": _hex(0xFFFF), "O": _opts,
             "CC": _one_of("Y", "N", "S", "O"), "Q": _q}
TCP_RULES = {"R": _one_of("Y"), "DF": _yn, "T": _ttl, "TG": _tg, "W": _hex(0xFFFF),
             "S": _one_of("Z", "A", "A+", "S", "O"), "A": _one_of("Z", "S", "S+", "O"),
             "F": _flags, "O": _opts, "RD": _one_of("0"), "Q": _q}
U1_RULES = {"R": _one_of("Y"), "DF": _yn, "T": _ttl, "TG": _tg, "IPL": _hex(0xFFFF),
            "UN": _hex(0xFFFFFFFF), "RIPL": lambda v: v == "G" or _hex(0xFFFF)(v),
            "RID": lambda v: v == "G" or _hex(0xFFFF)(v), "RIPCK": _one_of("G", "Z", "I"),
            "RUCK": lambda v: v == "G" or _hex(0xFFFF)(v), "RUD": _one_of("G", "I")}
IE_RULES = {"R": _one_of("Y"), "DFI": _one_of("N", "S", "Y", "O"), "T": _ttl, "TG": _tg,
            "CD": lambda v: v in ("Z", "S", "O") or _hex(0xFF)(v)}


def group_spec(g):
    """Return (ordered fields, optional fields, rules, may be R=N)."""
    if g == "SEQ":
        return tuple(SEQ_RULES), set(SEQ_RULES), SEQ_RULES, False
    if g == "OPS":
        r = {"O%d" % i: _opts for i in range(1, 7)}
        return tuple(r), set(), r, False
    if g == "WIN":
        r = {"W%d" % i: _hex(0xFFFF, allow_empty=True) for i in range(1, 7)}
        return tuple(r), set(), r, False
    if g == "ECN":
        return tuple(ECN_RULES), {"W"}, ECN_RULES, True
    if g == "U1":
        return tuple(U1_RULES), set(), U1_RULES, True
    if g == "IE":
        return tuple(IE_RULES), set(), IE_RULES, True
    return tuple(TCP_RULES), {"W"}, TCP_RULES, True


class EntryError(Exception):
    pass


def _parse_group(n, g, body):
    """Return {field: value}; raise EntryError on unknown, duplicate,
    misordered or out-of-range fields."""
    order, optional, rules, may_be_off = group_spec(g)
    if may_be_off and body == "R=N":
        return {"R": "N"}
    if body == "" and g == "SEQ":
        return {}
    vals = {}
    for part in body.split("%"):
        if "=" not in part:
            raise EntryError("line %d: %s: field without '='" % (n, g))
        k, v = part.split("=", 1)
        if k not in rules:
            raise EntryError("line %d: %s: unknown field %s" % (n, g, k))
        if k in vals:
            raise EntryError("line %d: %s: duplicate field %s" % (n, g, k))
        if not rules[k](v):
            raise EntryError("line %d: %s: value out of range for %s" % (n, g, k))
        vals[k] = v
    missing = [k for k in order if k not in vals and k not in optional]
    if missing:
        raise EntryError("line %d: %s: missing field %s" % (n, g, ",".join(missing)))
    if list(vals) != [k for k in order if k in vals]:
        raise EntryError("line %d: %s: fields not in derive order" % (n, g))
    return vals


def parse_fp(text):
    """Return (provenance dict, fingerprint name, {group: {field: value}}).
    Raise EntryError."""
    if "\r" in text:
        raise EntryError("CR characters not allowed, use LF line endings")
    if not text.endswith("\n"):
        raise EntryError("file must end with a newline")
    if any(ord(c) > 0x7E or (ord(c) < 0x20 and c != "\n") for c in text):
        raise EntryError("file must be printable ASCII")
    prov, groups, fp_name = {}, {}, None
    for n, line in enumerate(text[:-1].split("\n"), 1):
        if line.startswith("#@ "):
            if fp_name is not None:
                raise EntryError("line %d: #@ lines must come before the Fingerprint block" % n)
            m = re.fullmatch(r"#@ ([a-z_]+): (\S+)", line)
            if not m:
                raise EntryError("line %d: bad provenance line" % n)
            if m.group(1) not in PROV_KEYS:
                raise EntryError("line %d: provenance key %s is not allowed" % (n, m.group(1)))
            if m.group(1) in prov:
                raise EntryError("line %d: duplicate provenance key %s" % (n, m.group(1)))
            prov[m.group(1)] = m.group(2)
        elif line.startswith("Fingerprint "):
            if fp_name is not None:
                raise EntryError("line %d: only one Fingerprint block allowed" % n)
            fp_name = line[len("Fingerprint "):]
        elif fp_name is not None and re.fullmatch(r"[A-Z0-9]+\(.*\)", line):
            g = line[:line.index("(")]
            if g not in GROUPS:
                raise EntryError("line %d: unknown test group %s" % (n, g))
            if g in groups:
                raise EntryError("line %d: duplicate test group %s" % (n, g))
            if GROUPS.index(g) != len(groups):
                raise EntryError("line %d: test group %s out of order" % (n, g))
            groups[g] = _parse_group(n, g, line[len(g) + 1:-1])
        else:
            raise EntryError("line %d: unexpected line (comments and blank lines are not allowed)" % n)
    if fp_name is None:
        raise EntryError("missing Fingerprint block")
    if len(groups) != len(GROUPS):
        raise EntryError("missing test groups: %s" % ",".join(g for g in GROUPS if g not in groups))
    return prov, fp_name, groups


def block_of(fp_text):
    """The personality block (from the Fingerprint line), as derive renders it."""
    i = fp_text.find("Fingerprint ")
    return fp_text[i:] if i >= 0 else ""


def expected_firewall(name):
    if name.endswith("-fwoff"):
        return "off"
    return "on"


def check_entry(base, fp_text, sidecar_text):
    """Return a list of failure reasons for one entry (empty list means pass)."""
    errs = []
    try:
        prov, fp_name, _ = parse_fp(fp_text)
    except EntryError as e:
        return ["schema: %s" % e]
    for k in PROV_KEYS:
        if k not in prov:
            errs.append("provenance: missing #@ %s" % k)
    if not NAME_RE.match(base):
        errs.append("format: bad entry name %r" % base)
    elif base not in PERSONAS:
        errs.append("format: entry name %r is not a known persona" % base)
    if prov.get("name") is not None and prov["name"] != base:
        errs.append("consistency: #@ name does not match file name")
    if fp_name != base:
        errs.append("consistency: Fingerprint name does not match file name")
    c = prov.get("runs")
    if c is not None:
        if not re.fullmatch(r"\d{1,3}", c):
            errs.append("provenance: runs not an integer")
        elif not MIN_RUNS <= int(c) <= MAX_RUNS:
            errs.append("provenance: runs %s is out of range %d to %d" % (c, MIN_RUNS, MAX_RUNS))
    for k in ("probe_version", "derive_version"):
        if k in prov and not VERSION_RE.match(prov[k]):
            errs.append("provenance: %s must be N.N.N" % k)
    if "firewall" in prov:
        if prov["firewall"] not in ("on", "off"):
            errs.append("provenance: firewall must be on or off")
        elif prov["firewall"] != expected_firewall(base):
            errs.append("consistency: firewall does not match the entry name")
    if sidecar_text is None:
        errs.append("provenance: missing sidecar %s.provenance.json" % base)
        return errs
    try:
        side = json.loads(sidecar_text)
    except ValueError:
        errs.append("sidecar: not valid JSON")
        return errs
    if not isinstance(side, dict) or set(side) != set(PROV_KEYS):
        errs.append("sidecar: must be an object with exactly keys " + ", ".join(PROV_KEYS))
        return errs
    for k in PROV_KEYS:
        want = prov.get(k)
        got = side[k]
        if k == "runs":
            ok = isinstance(got, int) and not isinstance(got, bool) and want is not None and str(got) == want
        else:
            ok = isinstance(got, str) and got == want
        if not ok:
            errs.append("consistency: sidecar %s does not match #@ line" % k)
    return errs


def fingerprint_of(fp_text):
    """Flattened {GROUP.FIELD: value} over the full field set, or None."""
    try:
        _, _, groups = parse_fp(fp_text)
    except EntryError:
        return None
    return {"%s.%s" % (g, k): v for g, f in groups.items() for k, v in f.items()}


def distance(a, b):
    """Fields that differ, over the union of both field sets (a field present
    in one entry and absent in the other counts as different)."""
    return sum(1 for k in set(a) | set(b) if a.get(k) != b.get(k))
