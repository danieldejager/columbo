"""Bundle schema (plan section 3, strict allow-list). Original code.

A bundle is a directory `bundles/<label>/` holding exactly `manifest.txt` and
6 to 20 `run-<uuid>.json` files. Nothing else is allowed. Every manifest key
and every run JSON key at every depth is on an allow-list with a value rule.
"""
import json
import re

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
FORBIDDEN_KEYS = {"cmdline", "timestamp", "probe_plan", "dry_run"}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SAFE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SEMVER_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2}){1,1500}$")
OPTIONS_RE = re.compile(r"^[A-Za-z0-9]{0,64}$")
DOC_NETS = ((192, 0, 2), (198, 51, 100), (203, 0, 113))
RUN_TARGET = "192.0.2.1"
MAX_EXCHANGES = 256
MAX_PACKET = 1500
U32 = 2 ** 32 - 1

# Closed sets. TOOL_NAME is a neutral fixed value: the scrub tool rewrites the
# probe tool's own name to it before a bundle is submitted.
TOOL_NAME = "probe"
EXCHANGE_NAMES = {"SEQ1", "SEQ2", "SEQ3", "SEQ4", "SEQ5", "SEQ6", "ECN", "IE1", "IE2",
                  "T2", "T3", "T4", "T5", "T6", "T7", "U1"}
EXCHANGE_KINDS = {"ecn", "icmp", "syn_seq", "tcp_unusual", "udp"}
OPTION_NAMES = {"EOL", "MSS", "NOP", "SAckOK", "Timestamp", "WScale"}
FLAG_LETTERS = "FSRPAUEC"  # TCP flag bits 0 to 7, in bit order
IP_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp"}


def tcp_flags_ok(v):
    """Empty (the null probe) or distinct letters from FSRPAUEC."""
    return (isinstance(v, str) and len(v) <= 8 and all(c in FLAG_LETTERS for c in v)
            and len(set(v)) == len(v))


def safe_token(v):
    """Short safe identifier: no slashes, no spaces, not host-like (two or more dots), no '..'."""
    return isinstance(v, str) and bool(SAFE_RE.match(v)) and v.count(".") < 2


def is_int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def is_num(v, lo, hi):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi


def in_192_0_2(v):
    if not isinstance(v, str):
        return False
    parts = v.split(".")
    return (len(parts) == 4 and parts[:3] == ["192", "0", "2"]
            and parts[3].isdigit() and len(parts[3]) <= 3 and int(parts[3]) <= 255)


PORTS_KEYS = {"open_tcp", "closed_tcp", "closed_udp"}
PACKET_KEYS = {"hex", "len"}
EXCHANGE_KEYS = {
    "name", "kind", "gap_before_sec", "sent_at_offset_sec",
    "sent", "sent_parsed", "reply", "reply_parsed", "timeout",
}
RUN_KEYS = {"run_id", "run_index", "tool", "tool_version", "target", "ports", "exchanges"}
RUN_REQUIRED = {"run_id", "run_index", "exchanges"}

# Per-key value rules for sent_parsed and reply_parsed. Every value may also be null.
_u8 = lambda v: is_int(v, 0, 255)
_u16 = lambda v: is_int(v, 0, 65535)
_u32 = lambda v: is_int(v, 0, U32)
_flag = lambda v: isinstance(v, bool) or is_int(v, 0, 1)
PARSED_RULES = {
    "l4": lambda v: v in ("tcp", "udp", "icmp", "other"),
    "ip_src": in_192_0_2, "ip_dst": in_192_0_2,
    "ip_id": _u16, "ip_ttl": _u8, "ip_df": _flag, "ip_len": _u16, "ip_tos": _u8,
    "seq": _u32, "ack": _u32, "window": _u16,
    "flags": tcp_flags_ok, "flags_bits": lambda v: is_int(v, 0, 511), "reserved": lambda v: is_int(v, 0, 15),
    "options": lambda v: isinstance(v, str) and bool(OPTIONS_RE.match(v)),
    "options_raw": None,  # checked separately
    "sport": _u16, "dport": _u16, "urgptr": _u16,
    "icmp_type": _u8, "icmp_code": _u8, "icmp_unused": _u32,
    "embedded_ip_ttl": _u8, "embedded_ip_id": _u16, "embedded_ip_len": _u16, "embedded_ip_sum": _u16, "embedded_ip_sum_ok": lambda v: isinstance(v, bool),
    "embedded_udp_sum": _u16,
    "embedded_udp_data_hex": lambda v: isinstance(v, str) and (v == "" or bool(HEX_RE.match(v))),
}
PARSED_KEYS = set(PARSED_RULES)


def _keys(obj, allowed, where, errs, required=()):
    if not isinstance(obj, dict):
        errs.append("%s: must be an object" % where)
        return False
    for k in obj:
        if k in FORBIDDEN_KEYS:
            errs.append("%s: key %r is forbidden" % (where, k))
        elif k not in allowed:
            errs.append("%s: unknown key %r" % (where, k))
    for k in required:
        if k not in obj:
            errs.append("%s: missing key %r" % (where, k))
    return True


def _options_raw(v, where, errs):
    ok = isinstance(v, list) and len(v) <= 40
    if ok:
        for opt in v:
            if not (isinstance(opt, list) and 1 <= len(opt) <= 2 and opt[0] in OPTION_NAMES):
                ok = False
                break
            if len(opt) == 2:
                val = opt[1]
                if val is None or is_int(val, 0, U32):
                    continue
                if isinstance(val, list) and len(val) <= 4 and all(is_int(x, 0, U32) for x in val):
                    continue
                if isinstance(val, str) and (val == "" or HEX_RE.match(val)) and len(val) <= 80:
                    continue
                ok = False
                break
    if not ok:
        errs.append("%s: options_raw must be a short list of [name, integer or hex] pairs, option names from %s" % (where, sorted(OPTION_NAMES)))


def decode_ipv4(b):
    """Decode the header fields the parsed objects carry. Returns a dict."""
    d = {
        "ip_tos": b[1], "ip_len": int.from_bytes(b[2:4], "big"), "ip_id": int.from_bytes(b[4:6], "big"),
        "ip_df": bool(b[6] & 0x40), "ip_ttl": b[8], "l4": IP_PROTOCOLS.get(b[9], "other"),
        "ip_src": ".".join(map(str, b[12:16])), "ip_dst": ".".join(map(str, b[16:20])),
    }
    l4 = b[20:]
    if d["l4"] == "tcp" and len(l4) >= 20:
        d.update(sport=int.from_bytes(l4[0:2], "big"), dport=int.from_bytes(l4[2:4], "big"),
                 seq=int.from_bytes(l4[4:8], "big"), ack=int.from_bytes(l4[8:12], "big"),
                 window=int.from_bytes(l4[14:16], "big"), urgptr=int.from_bytes(l4[18:20], "big"),
                 flags="".join(c for i, c in enumerate(FLAG_LETTERS) if l4[13] >> i & 1),
                 flags_bits=((l4[12] & 1) << 8) | l4[13])
    elif d["l4"] == "udp" and len(l4) >= 8:
        d.update(sport=int.from_bytes(l4[0:2], "big"), dport=int.from_bytes(l4[2:4], "big"))
    elif d["l4"] == "icmp" and len(l4) >= 4:
        d.update(icmp_type=l4[0], icmp_code=l4[1])
    return d


def _packet(p, where, errs):
    """Structure rules; returns the decoded header fields, or None."""
    if not _keys(p, PACKET_KEYS, where, errs, PACKET_KEYS):
        return None
    h, n = p.get("hex"), p.get("len")
    if not (isinstance(h, str) and HEX_RE.match(h)):
        errs.append("%s.hex: must be lower-case hex, even length, at most %d bytes" % (where, MAX_PACKET))
        return None
    if not is_int(n, 1, MAX_PACKET) or n != len(h) // 2:
        errs.append("%s.len: must equal the number of hex bytes" % where)
    b = bytes.fromhex(h)
    if len(b) < 20 or b[0] != 0x45:
        errs.append("%s.hex: must be an IPv4 packet with a 20-byte header (first byte 45)" % where)
        return None
    if int.from_bytes(b[2:4], "big") != len(b):
        errs.append("%s.hex: length must equal the IP total length field exactly (no trailer)" % where)
        return None
    if b[9] not in IP_PROTOCOLS:
        errs.append("%s.hex: IP protocol must be TCP, UDP or ICMP" % where)
        return None
    for label, addr in (("source", b[12:16]), ("destination", b[16:20])):
        if tuple(addr[:3]) not in DOC_NETS:
            errs.append("%s.hex: IPv4 %s address outside documentation ranges" % (where, label))
    return decode_ipv4(b)


def _compare(decoded, parsed, where, errs):
    """Every parsed header field must equal the value decoded from the hex."""
    for k, v in parsed.items():
        if v is None or k not in decoded:
            continue
        want = decoded[k]
        got = bool(v) if k == "ip_df" else v
        if got != want:
            errs.append("%s.%s: does not match the packet hex" % (where, k))

UDP_PROBE_PAYLOAD = b"C" * 300  # the U1 probe shape; no other UDP payload is accepted
_OPT_KIND = {"EOL": 0, "NOP": 1, "MSS": 2, "WScale": 3, "SAckOK": 4, "Timestamp": 8}


def encode_options(opts):
    """Re-encode options_raw to wire bytes. Returns None if a value cannot be encoded."""
    out = b""
    for opt in opts or []:
        if not (isinstance(opt, list) and opt and opt[0] in _OPT_KIND):
            return None
        name, val = opt[0], (opt[1] if len(opt) > 1 else None)
        kind = _OPT_KIND[name]
        if isinstance(val, str) and HEX_RE.match(val or "00"):
            data = bytes.fromhex(val)
        elif name == "MSS" and is_int(val, 0, 65535):
            data = val.to_bytes(2, "big")
        elif name == "WScale" and is_int(val, 0, 255):
            data = bytes([val])
        elif name == "Timestamp" and isinstance(val, list) and len(val) == 2 and all(is_int(x, 0, U32) for x in val):
            data = val[0].to_bytes(4, "big") + val[1].to_bytes(4, "big")
        elif val is None and name in ("EOL", "NOP", "SAckOK"):
            data = b""
        else:
            return None
        out += bytes([kind]) if name in ("EOL", "NOP") else bytes([kind, 2 + len(data)]) + data
    return out


ECHO_PADDING_LENGTHS = (0, 120, 150)  # IE1 and IE2 pad with zero bytes only
URG_POINTER_ALLOWED = (0,)  # allow-list even when URG is set

# Probe field pins: the only non zero TOS, urgent pointer and reserved bits
# accepted anywhere. The probes follow a published scanner method; the ECN
# urgent pointer and reserved bits are matched to observed traffic from it
# (docs/check-rules.md, "Probe field pins"). A pin applies only
# to the sent packet of an exchange with that exact name and kind whose parsed
# l4 and flags equal the pin; every value is exact, never a range. Any other
# packet keeps TOS 0, urgent pointer 0 and reserved bits 0.
PROBE_FIELD_PINS = {
    ("ECN", "ecn"): {"l4": "tcp", "flags": "SEC", "ip_tos": 0, "urgptr": 63477, "reserved": 4},
    ("IE2", "icmp"): {"l4": "icmp", "ip_tos": 4},
}
_PIN_SELECTORS = ("l4", "flags")


def probe_pin(exchange, direction, parsed):
    """The pin for this packet, or an empty dict when none applies."""
    if direction != "sent" or not isinstance(exchange, dict) or not isinstance(parsed, dict):
        return {}
    pin = PROBE_FIELD_PINS.get((exchange.get("name"), exchange.get("kind")))
    if not pin or any(parsed.get(k) != pin[k] for k in _PIN_SELECTORS if k in pin):
        return {}
    return pin
REQUIRED_PARSED = ("l4", "ip_src", "ip_dst", "ip_id", "ip_ttl", "ip_df", "ip_len")
REQUIRED_L4 = {
    "tcp": ("sport", "dport", "seq", "ack", "window"),
    "udp": ("sport", "dport"),
    "icmp": ("icmp_type", "icmp_code"),
}


class RebuildError(Exception):
    pass


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _pseudo(src, dst, proto, n):
    return src + dst + bytes([0, proto]) + n.to_bytes(2, "big")


def _addr(a):
    return bytes(int(x) for x in a.split("."))


def _ip(p, proto, l4, frag_df, tos=0):
    total = 20 + len(l4)
    h = bytearray(bytes([0x45, tos]) + total.to_bytes(2, "big") + p["ip_id"].to_bytes(2, "big")
                  + (b"\x40\x00" if frag_df else b"\x00\x00") + bytes([p["ip_ttl"], proto]) + b"\x00\x00"
                  + _addr(p["ip_src"]) + _addr(p["ip_dst"]))
    h[10:12] = csum(bytes(h)).to_bytes(2, "big")
    return bytes(h), total


def _l4_sum(l4, at, src, dst, proto, udp=False):
    l4 = bytearray(l4)
    c = csum(_pseudo(src, dst, proto, len(l4)) + bytes(l4))
    l4[at:at + 2] = (c or (0xFFFF if udp else 0)).to_bytes(2, "big")
    return bytes(l4)


def rebuild_packet(p, probe=None, pin=None):
    """Rebuild the whole packet from parsed fields. Raises RebuildError.
    TOS and TCP reserved bits come from the parsed fields only when they equal
    this packet's probe pin; otherwise TOS is rebuilt as 0 and reserved bits
    must be zero."""
    pin = pin or {}
    if not isinstance(p, dict):
        raise RebuildError("parsed fields missing")
    l4t = p.get("l4")
    for k in REQUIRED_PARSED + REQUIRED_L4.get(l4t, ()):
        if p.get(k) is None:
            raise RebuildError("parsed field %r missing" % k)
    if l4t not in REQUIRED_L4:
        raise RebuildError("l4 must be tcp, udp or icmp")
    src, dst, n = _addr(p["ip_src"]), _addr(p["ip_dst"]), p["ip_len"]
    if l4t == "tcp":
        res = p.get("reserved") or 0
        if res and res != pin.get("reserved"):
            raise RebuildError("TCP reserved bits must be zero")
        fb = p.get("flags_bits")
        if fb is None:
            fb = sum(1 << FLAG_LETTERS.index(c) for c in p.get("flags") or "")
        opts = encode_options(p.get("options_raw") or [])
        if opts is None:
            raise RebuildError("options_raw cannot be encoded")
        opts += b"\x00" * (-len(opts) % 4)
        off = 20 + len(opts)
        if off > 60:
            raise RebuildError("TCP options too long")
        l4 = (p["sport"].to_bytes(2, "big") + p["dport"].to_bytes(2, "big") + p["seq"].to_bytes(4, "big")
              + p["ack"].to_bytes(4, "big") + bytes([(off // 4) << 4 | res << 1 | fb >> 8, fb & 0xFF])
              + p["window"].to_bytes(2, "big") + b"\x00\x00" + (p.get("urgptr") or 0).to_bytes(2, "big") + opts)
        l4 = _l4_sum(l4, 16, src, dst, 6)
        proto = 6
    elif l4t == "udp":
        data = {28: b"", 28 + len(UDP_PROBE_PAYLOAD): UDP_PROBE_PAYLOAD}.get(n)
        if data is None:
            raise RebuildError("UDP length must fit an empty or U1 payload")
        l4 = p["sport"].to_bytes(2, "big") + p["dport"].to_bytes(2, "big") + (8 + len(data)).to_bytes(2, "big") + b"\x00\x00" + data
        l4 = _l4_sum(l4, 6, src, dst, 17, udp=True)
        proto = 17
    else:
        t = p["icmp_type"]
        dlen = n - 28
        if t in (0, 8):
            if dlen not in ECHO_PADDING_LENGTHS:
                raise RebuildError("ICMP echo padding must be %s zero bytes" % (ECHO_PADDING_LENGTHS,))
            data = b"\x00" * dlen
        elif t == 3:
            if probe is None or len(probe) < 28 or probe[9] != 17 or not 28 <= dlen <= len(probe):
                raise RebuildError("ICMP unreachable must quote this exchange's UDP probe")
            q = bytearray(probe[:dlen])
            for k, at, size in (("embedded_ip_len", 2, 2), ("embedded_ip_id", 4, 2), ("embedded_ip_ttl", 8, 1),
                                ("embedded_ip_sum", 10, 2), ("embedded_udp_sum", 26, 2)):
                if p.get(k) is not None:
                    q[at:at + size] = p[k].to_bytes(size, "big")
            data = bytes(q)
        else:
            if dlen != 0:
                raise RebuildError("ICMP payload must be empty")
            data = b""
        l4 = bytearray(bytes([t, p["icmp_code"], 0, 0]) + (p.get("icmp_unused") or 0).to_bytes(4, "big") + data)
        l4[2:4] = csum(bytes(l4)).to_bytes(2, "big")
        l4 = bytes(l4)
        proto = 1
    tos = pin.get("ip_tos", 0) if (p.get("ip_tos") or 0) == pin.get("ip_tos", 0) else 0
    hdr, total = _ip(p, proto, l4, bool(p["ip_df"]), tos)
    if total != n:
        raise RebuildError("ip_len does not match the rebuilt length")
    return hdr + l4


def _payload(b, parsed, where, errs, probe=None, pin=None):
    """Field diagnostics, then the packet must equal the rebuild from parsed fields."""
    pin = pin or {}
    if b[1] != pin.get("ip_tos", 0):
        errs.append("%s: IP TOS must be %d" % (where, pin.get("ip_tos", 0)))
    if int.from_bytes(b[6:8], "big") & 0xBFFF:
        errs.append("%s: IP fragment offset and MF flag must be zero" % where)
    if csum(b[:20]) != 0:
        errs.append("%s: IP checksum invalid" % where)
    l4, proto, src, dst = b[20:], b[9], b[12:16], b[16:20]
    if proto == 6 and len(l4) >= 20:
        off = (l4[12] >> 4) * 4
        if csum(_pseudo(src, dst, 6, len(l4)) + l4) != 0:
            errs.append("%s: TCP checksum invalid" % where)
        if "urgptr" in pin:
            if int.from_bytes(l4[18:20], "big") != pin["urgptr"]:
                errs.append("%s: TCP urgent pointer must be %d for this probe" % (where, pin["urgptr"]))
        elif int.from_bytes(l4[18:20], "big") not in URG_POINTER_ALLOWED:
            errs.append("%s: TCP urgent pointer must be zero" % where)
        if "reserved" in pin and (l4[12] >> 1) & 7 != pin["reserved"]:
            errs.append("%s: TCP reserved bits must be %d for this probe" % (where, pin["reserved"]))
        if off < 20 or off > len(l4):
            errs.append("%s: TCP data offset invalid" % where)
        else:
            if len(l4) != off:
                errs.append("%s: TCP payload must be empty" % where)
            raw = l4[20:off]
            opts = (parsed or {}).get("options_raw")
            want = encode_options(opts) if isinstance(opts, list) else b""
            if want is None or len(want) > len(raw) or raw != want + b"\x00" * (len(raw) - len(want)):
                errs.append("%s: TCP option bytes must equal options_raw re-encoded" % where)
    elif proto == 17 and len(l4) >= 8:
        if int.from_bytes(l4[4:6], "big") != len(l4):
            errs.append("%s: UDP length must equal the datagram length" % where)
        if l4[6:8] == b"\x00\x00" or csum(_pseudo(src, dst, 17, len(l4)) + l4) != 0:
            errs.append("%s: UDP checksum invalid" % where)
        if l4[8:] not in (b"", UDP_PROBE_PAYLOAD):
            errs.append("%s: UDP payload must be empty or the known probe shape" % where)
    elif proto == 1 and len(l4) >= 8:
        if csum(l4) != 0:
            errs.append("%s: ICMP checksum invalid" % where)
        if l4[0] in (0, 8) and (l4[8:].strip(b"\x00") or len(l4) - 8 not in ECHO_PADDING_LENGTHS):
            errs.append("%s: ICMP echo payload must be zero padding of %s bytes" % (where, ECHO_PADDING_LENGTHS))
    try:
        if rebuild_packet(parsed, probe, pin) != b:
            errs.append("%s: packet bytes do not equal the rebuild from parsed fields" % where)
    except RebuildError as ex:
        errs.append("%s: cannot rebuild from parsed fields: %s" % (where, ex))
    except (TypeError, ValueError, OverflowError, AttributeError, IndexError):
        errs.append("%s: cannot rebuild from parsed fields: bad field value" % where)


def check_run(obj, where="run"):
    errs = []
    if not _keys(obj, RUN_KEYS, where, errs, RUN_REQUIRED):
        return errs
    if "run_id" in obj and not (isinstance(obj["run_id"], str) and UUID_RE.match(obj["run_id"])):
        errs.append("%s.run_id: must be a lower-case random (version 4) UUID" % where)
    if "run_index" in obj and not is_int(obj["run_index"], 0, 99):
        errs.append("%s.run_index: must be an integer 0 to 99" % where)
    if "tool" in obj and obj["tool"] != TOOL_NAME:
        errs.append("%s.tool: must be %r (the scrub tool sets it)" % (where, TOOL_NAME))
    if "tool_version" in obj and not (isinstance(obj["tool_version"], str) and SEMVER_RE.match(obj["tool_version"])):
        errs.append("%s.tool_version: must be N.N.N" % where)
    if "target" in obj and obj["target"] != RUN_TARGET:
        errs.append("%s.target: must be %s" % (where, RUN_TARGET))
    if "ports" in obj and _keys(obj["ports"], PORTS_KEYS, where + ".ports", errs):
        for k, v in obj["ports"].items():
            if k in PORTS_KEYS and not is_int(v, 0, 65535):
                errs.append("%s.ports.%s: must be an integer 0 to 65535" % (where, k))
    ex = obj.get("exchanges")
    if not isinstance(ex, list) or not 1 <= len(ex) <= MAX_EXCHANGES:
        errs.append("%s.exchanges: must be a list of 1 to %d exchanges" % (where, MAX_EXCHANGES))
        return errs
    for i, e in enumerate(ex):
        w = "%s.exchanges[%d]" % (where, i)
        if not _keys(e, EXCHANGE_KEYS, w, errs, ("name",)):
            continue
        if "name" in e and e["name"] not in EXCHANGE_NAMES:
            errs.append("%s.name: must be one of %s" % (w, sorted(EXCHANGE_NAMES)))
        if "kind" in e and e["kind"] not in EXCHANGE_KINDS:
            errs.append("%s.kind: must be one of %s" % (w, sorted(EXCHANGE_KINDS)))
        for k in ("gap_before_sec", "sent_at_offset_sec"):
            if k in e and e[k] is not None and not is_num(e[k], 0, 86400):
                errs.append("%s.%s: must be a number 0 to 86400" % (w, k))
        if "timeout" in e and not isinstance(e["timeout"], bool):
            errs.append("%s.timeout: must be true or false" % w)
        decoded = {}
        for pk in ("sent", "reply"):
            if e.get(pk) is not None:
                decoded[pk] = _packet(e[pk], "%s.%s" % (w, pk), errs)
        for pk in ("sent_parsed", "reply_parsed"):
            p = e.get(pk)
            if p is None:
                continue
            pw = "%s.%s" % (w, pk)
            if not _keys(p, PARSED_KEYS, pw, errs):
                continue
            for k, v in p.items():
                if k not in PARSED_RULES or v is None:
                    continue
                if k == "options_raw":
                    _options_raw(v, pw, errs)
                elif not PARSED_RULES[k](v):
                    errs.append("%s.%s: bad value" % (pw, k))
            dec = decoded.get(pk[:-len("_parsed")])
            if dec:
                _compare(dec, p, pw, errs)
        for pk in ("sent", "reply"):
            if decoded.get(pk):
                probe = bytes.fromhex(e["sent"]["hex"]) if pk == "reply" and decoded.get("sent") else None
                _payload(bytes.fromhex(e[pk]["hex"]), e.get(pk + "_parsed"), "%s.%s" % (w, pk), errs, probe,
                         probe_pin(e, pk, e.get(pk + "_parsed")))
    return errs


MANIFEST_RULES = {
    "label": lambda v: bool(re.fullmatch(r"[a-z0-9-]{1,40}", v)),
    "firewall": lambda v: v in ("on", "off"),
    "restart": lambda v: v in ("0", "1"),
    "runs": lambda v: bool(re.fullmatch(r"[0-9]{1,2}", v)) and MIN_RUNS <= int(v) <= MAX_RUNS,
    "run_gap_s": lambda v: bool(re.fullmatch(r"[0-9]{3,4}", v)) and 300 <= int(v) <= 3600,
    "open_tcp": lambda v: bool(re.fullmatch(r"0|[1-9][0-9]{0,4}", v)) and int(v) <= 65535,
    "closed_tcp": lambda v: bool(re.fullmatch(r"0|[1-9][0-9]{0,4}", v)) and int(v) <= 65535,
    "closed_udp": lambda v: bool(re.fullmatch(r"0|[1-9][0-9]{0,4}", v)) and int(v) <= 65535,
    "probe_version": lambda v: bool(SEMVER_RE.match(v)),
    "derive_version": lambda v: bool(SEMVER_RE.match(v)),
    "python_version": lambda v: bool(re.fullmatch(r"\d{1,4}(\.\d{1,4}){1,3}", v)),
    "scapy_version": lambda v: bool(re.fullmatch(r"\d{1,4}(\.\d{1,4}){1,3}", v)),
    "arch": lambda v: v in ("aarch64", "x86_64"),
}
MANIFEST_REQUIRED = ("label", "firewall", "runs", "probe_version", "derive_version")
MIN_RUNS, MAX_RUNS = 6, 20
RUN_FILE_RE = re.compile(r"^run-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.json$")
MAX_MANIFEST_BYTES = 4096


def parse_manifest(data, where, errs):
    if len(data) > MAX_MANIFEST_BYTES:
        errs.append("%s: manifest.txt too large" % where)
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        errs.append("%s: manifest.txt must be ASCII" % where)
        return None
    if "\r" in text or not text.endswith("\n"):
        errs.append("%s: manifest.txt must use LF line endings and end with a newline" % where)
        return None
    out = {}
    for n, line in enumerate(text[:-1].split("\n"), 1):
        m = re.fullmatch(r"([a-z_]{1,32})=([^\s=]{1,64})", line)
        if not m:
            errs.append("%s: manifest.txt line %d is not key=value" % (where, n))
            continue
        k, v = m.groups()
        if k not in MANIFEST_RULES:
            errs.append("%s: manifest.txt key %r is not allowed" % (where, k))
        elif k in out:
            errs.append("%s: manifest.txt duplicate key %r" % (where, k))
        elif not MANIFEST_RULES[k](v):
            errs.append("%s: manifest.txt bad value for %s" % (where, k))
        else:
            out[k] = v
    for k in MANIFEST_REQUIRED:
        if k not in out and not any(("key %r" % k) in e or ("for %s" % k) in e for e in errs):
            errs.append("%s: manifest.txt missing required key %s" % (where, k))
    return out


def check_bundle_dir(label, files, where=None):
    """label: directory name under bundles/. files: {relative name: bytes}."""
    where = where or "bundles/%s" % label
    errs = []
    if sum(len(v) for v in files.values()) > MAX_BUNDLE_BYTES:
        return ["%s: bundle larger than %d bytes" % (where, MAX_BUNDLE_BYTES)]
    runs = {}
    manifest = None
    for name in sorted(files):
        data = files[name]
        if name == "manifest.txt":
            manifest = parse_manifest(data, where, errs)
            continue
        m = RUN_FILE_RE.match(name)
        if not m:
            errs.append("%s/%s: file not allowed in a bundle (only manifest.txt and run-<uuid>.json)" % (where, name))
            continue
        if len(data) > MAX_MEMBER_BYTES:
            errs.append("%s/%s: run file too large" % (where, name))
            continue
        try:
            obj = json.loads(data.decode("utf-8"))
        except Exception:
            errs.append("%s/%s: not valid JSON" % (where, name))
            continue
        w = "%s/%s" % (where, name)
        errs += check_run(obj, w)
        if isinstance(obj, dict):
            if obj.get("run_id") != m.group(1):
                errs.append("%s: run_id does not match file name" % w)
            runs[name] = obj
    n = sum(1 for k in files if RUN_FILE_RE.match(k))
    if not MIN_RUNS <= n <= MAX_RUNS:
        errs.append("%s: bundle must hold 6 to 20 run files, found %d" % (where, n))
    if manifest is None:
        if "manifest.txt" not in files:
            errs.append("%s: missing manifest.txt" % where)
        return errs
    if manifest.get("label") is not None and manifest["label"] != label:
        errs.append("%s: manifest label does not match directory name" % where)
    if "runs" in manifest and int(manifest["runs"]) != n:
        errs.append("%s: manifest runs=%s does not equal %d run files" % (where, manifest["runs"], n))
    for k in ("open_tcp", "closed_tcp", "closed_udp"):
        if k in manifest:
            for name, obj in sorted(runs.items()):
                ports = obj.get("ports")
                if not isinstance(ports, dict) or ports.get(k) != int(manifest[k]):
                    errs.append("%s/%s: ports.%s does not equal manifest %s" % (where, name, k, k))
    return errs
