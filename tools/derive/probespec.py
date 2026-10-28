"""Probe packet definitions for the probe tool.

Field names and response categories match what honeyd's personality.c parses
(SEQ, OPS, WIN, ECN, T1-T7, U1, IE).

The probe set follows a published scanner method, paraphrased here from the
public description (probes section):
    https://nmap.org/book/osdetect-methods.html
Nothing is taken from scanner source code or from any OS fingerprint
database. Where the page is silent, or differs from what that method sends,
the value is matched to observed traffic from the method and the comment says
so ("observed on the wire"). These values are facts about a probe, not
database text. No OS fingerprint database entries are embedded here.

TCP options are an explicit ORDERED tuple of (kind, value) entries, because
the order and the NOP padding are part of the probe (and of the reply the
target builds). Kinds: "WS" (window scale), "NOP", "MSS", "TS" ((TSval,
TSecr)), "SACK" (SACK permitted), "EOL".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

METHOD_DOC_URL = "https://nmap.org/book/osdetect-methods.html"

TcpOpt = tuple  # ("MSS", 1460) | ("NOP", None) | ...
TS_PROBE = (0xFFFFFFFF, 0)


@dataclass(frozen=True)
class ProbeDef:
    name: str
    kind: str  # syn_seq | tcp_unusual | ecn | icmp | udp
    dst_port_role: str  # open_tcp | closed_tcp | closed_udp | n/a
    window: int | None = None
    flags: str = ""
    reserved: int = 0  # scapy TCP.reserved (3 bits); 4 = the high reserved bit
    urgptr: int = 0
    ack_zero: bool = False  # True: ack field 0; False: the run's random non-zero ack
    tos: int = 0
    df: bool = False
    ip_id: int | None = None  # fixed IP ID (U1 = 0x1042); None = per-run value
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_seq: int | None = None
    icmp_payload_len: int = 0
    udp_payload_len: int = 0
    options: tuple[TcpOpt, ...] = ()
    notes: str = ""


# SEQ: six SYNs to an open port, 100 ms apart (see the page's sequence
# generation section for the per probe windows and options).
# IP DF clear: observed on the wire, page silent.
_SEQ = [
    (1, (("WS", 10), ("NOP", None), ("MSS", 1460), ("TS", TS_PROBE), ("SACK", None))),
    (63, (("MSS", 1400), ("WS", 0), ("SACK", None), ("TS", TS_PROBE), ("EOL", None))),
    (4, (("TS", TS_PROBE), ("NOP", None), ("NOP", None), ("WS", 5), ("NOP", None), ("MSS", 640))),
    (4, (("SACK", None), ("TS", TS_PROBE), ("WS", 10), ("EOL", None))),
    (16, (("MSS", 536), ("SACK", None), ("TS", TS_PROBE), ("WS", 10), ("EOL", None))),
    (512, (("MSS", 265), ("SACK", None), ("TS", TS_PROBE))),
]
SEQ_PROBES: list[ProbeDef] = [
    ProbeDef(name=f"SEQ{i}", kind="syn_seq", dst_port_role="open_tcp", window=w, flags="S",
             df=False, options=o)
    for i, (w, o) in enumerate(_SEQ, start=1)
]
SEQ_GAP_SEC = 0.100

# IE pair (see the page's ICMP echo section). Sent immediately after SEQ (needed for SS).
ICMP_PROBES: list[ProbeDef] = [
    ProbeDef(name="IE1", kind="icmp", dst_port_role="n/a", tos=0, df=True, icmp_type=8,
             icmp_code=9, icmp_seq=295, icmp_payload_len=120,
             notes="echo request, DF, TOS 0, code 9, seq 295, random id, 120 x 0x00"),
    # Per the page, IE2 differs from IE1 in TOS (4), code (0) and payload
    # length (150); the page does not state DF for this probe.
    # IP DF clear: observed on the wire, page silent.
    ProbeDef(name="IE2", kind="icmp", dst_port_role="n/a", tos=4, df=False, icmp_type=8,
             icmp_code=0, icmp_seq=296, icmp_payload_len=150,
             notes="echo request, TOS 4, code 0, id+1, seq 296, 150 x 0x00"),
]

# U1 (see the page's UDP section): 300 x 'C' to a closed port, IP ID 0x1042.
# IP DF clear: observed on the wire, page silent.
UDP_PROBE = ProbeDef(name="U1", kind="udp", dst_port_role="closed_udp", df=False, ip_id=0x1042,
                     udp_payload_len=300, notes="UDP to closed port, IP ID 0x1042")

# ECN (see the page's explicit congestion notification section).
ECN_PROBE = ProbeDef(
    name="ECN", kind="ecn", dst_port_role="open_tcp", window=3, flags="SEC",
    # NOTED DEVIATION. The page places the reserved bit next to CWR (byte 12
    # & 0x01); observed traffic from the method has byte 12 & 0x08 (scapy
    # reserved=4), and the probe matches that. The urgent pointer 0xF7F5
    # without URG is likewise matched to observed traffic from the method.
    # IP DF clear: observed on the wire, page silent.
    # Ack 0 and window 3 as the page describes; options are listed below.
    reserved=4, urgptr=0xF7F5, ack_zero=True, df=False,
    options=(("WS", 10), ("NOP", None), ("MSS", 1460), ("SACK", None), ("NOP", None), ("NOP", None)),
    notes="SYN+ECE+CWR, reserved bit, urg 0xF7F5 without URG, ack 0, window 3",
)

# T2 to T7 (see the page's TCP section): options as in _T_OPTS below, T7 with
# window scale 15.
_T_OPTS = (("WS", 10), ("NOP", None), ("MSS", 265), ("TS", TS_PROBE), ("SACK", None))
_T7_OPTS = (("WS", 15),) + _T_OPTS[1:]
T_PROBES: list[ProbeDef] = [
    ProbeDef(name="T2", kind="tcp_unusual", dst_port_role="open_tcp", window=128, flags="",
             df=True, options=_T_OPTS, notes="NULL flags, DF, open port"),
    ProbeDef(name="T3", kind="tcp_unusual", dst_port_role="open_tcp", window=256, flags="FSPU",
             df=False, options=_T_OPTS, notes="SYN FIN URG PSH, open port"),
    ProbeDef(name="T4", kind="tcp_unusual", dst_port_role="open_tcp", window=1024, flags="A",
             df=True, options=_T_OPTS, notes="ACK, DF, open port"),
    ProbeDef(name="T5", kind="tcp_unusual", dst_port_role="closed_tcp", window=31337, flags="S",
             df=False, options=_T_OPTS, notes="SYN, closed port"),
    ProbeDef(name="T6", kind="tcp_unusual", dst_port_role="closed_tcp", window=32768, flags="A",
             df=True, options=_T_OPTS, notes="ACK, DF, closed port"),
    ProbeDef(name="T7", kind="tcp_unusual", dst_port_role="closed_tcp", window=65535, flags="FPU",
             df=False, options=_T7_OPTS, notes="FIN PSH URG, closed port, WS 15"),
]


def options_letters(options) -> str:
    """TCP options as the letter string used by OPS/O* and personality.c.

    Letters per the TCP options section of
    https://nmap.org/book/osdetect-methods.html (paraphrased): one letter per
    option (end of list, no op, MSS and window scale with a hex value, SACK
    permitted, and timestamp followed by two digits that say whether each
    timestamp value is non zero).
    personality.c's parse_option accepts exactly these letters (M/W as hex,
    T followed by two 0/1 digits).
    """
    letters: list[str] = []
    for opt in options or []:
        name = opt[0] if isinstance(opt, (tuple, list)) else opt
        val = opt[1] if isinstance(opt, (tuple, list)) and len(opt) > 1 else None
        if name in ("MSS", "M"):
            letters.append(f"M{int(val):X}")
        elif name in ("SAckOK", "SAck", "S", "SACK"):
            letters.append("S")
        elif name in ("Timestamp", "TSval", "T", "TS"):
            if isinstance(val, (tuple, list)) and len(val) >= 2:
                letters.append(f"T{int(int(val[0]) != 0)}{int(int(val[1]) != 0)}")
            else:
                letters.append("T00")
        elif name in ("NOP", "N"):
            letters.append("N")
        elif name in ("WScale", "W", "WS"):
            letters.append(f"W{int(val):X}")
        elif name in ("EOL", "L", "E"):
            letters.append("L")
        else:
            letters.append("?")
    return "".join(letters)


def all_probe_defs() -> list[ProbeDef]:
    """Send order: SEQ, then IE right after (doc, for SS), then U1, ECN, T2-T7."""
    return list(SEQ_PROBES) + list(ICMP_PROBES) + [UDP_PROBE, ECN_PROBE] + list(T_PROBES)


def probe_plan_summary() -> list[dict[str, Any]]:
    """Machine-readable plan for --dry-run output."""
    return [
        {"name": p.name, "kind": p.kind, "dst_port_role": p.dst_port_role, "window": p.window,
         "flags": p.flags, "tos": p.tos, "df": p.df, "notes": p.notes}
        for p in all_probe_defs()
    ]
