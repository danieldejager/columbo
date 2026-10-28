"""Whole-packet rebuild: the hex must equal a packet rebuilt from the parsed
fields, with every checksum valid and no unparsed bytes. One must-fail test per
header field."""
import copy
import json
import struct
import sys
from pathlib import Path

from tools.checks import bundle as B

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pktgen as G  # noqa: E402

FIX = HERE / "fixtures" / "runs"
SRC, DST = "192.0.2.10", "192.0.2.1"


def base(name="pass-run.json"):
    return json.loads((FIX / name).read_text())


def put(r, i, side, pkt):
    r["exchanges"][i][side] = {"hex": pkt.hex(), "len": len(pkt)}


def hexb(r, i, side):
    return bytearray.fromhex(r["exchanges"][i][side]["hex"])


def has(errs, word):
    return any(word in e for e in errs)


def test_fixtures_carry_valid_checksums_and_pass():
    for name in ("pass-run.json", "pass-null-probe.json"):
        r = base(name)
        assert B.check_run(r) == [], name
        for e in r["exchanges"]:
            for side in ("sent", "reply"):
                if e.get(side):
                    b = bytes.fromhex(e[side]["hex"])
                    assert G.fix_checksums(b) == b


def test_bad_tcp_checksum_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[36] ^= 0xFF
    put(r, 0, "sent", bytes(b))
    assert has(B.check_run(r), "TCP checksum")


def test_urgent_pointer_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[38:40] = b"\x00\x05"
    put(r, 0, "sent", G.fix_checksums(bytes(b)))
    r["exchanges"][0]["sent_parsed"]["urgptr"] = 5
    assert has(B.check_run(r), "urgent pointer")


def test_ip_tos_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[1] = 0x10
    put(r, 0, "sent", G.fix_checksums(bytes(b)))
    r["exchanges"][0]["sent_parsed"]["ip_tos"] = 16
    assert has(B.check_run(r), "TOS")


def test_bad_ip_checksum_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[10] ^= 0xFF
    put(r, 0, "sent", bytes(b))
    assert has(B.check_run(r), "IP checksum")


def test_fragment_offset_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[6:8] = b"\x40\x01"
    put(r, 0, "sent", G.fix_checksums(bytes(b)))
    assert has(B.check_run(r), "fragment")


def test_more_fragments_flag_fails():
    r = base()
    b = hexb(r, 0, "sent")
    b[6:8] = b"\x60\x00"
    put(r, 0, "sent", G.fix_checksums(bytes(b)))
    assert has(B.check_run(r), "fragment")


def test_df_must_match_parsed():
    r = base()
    r["exchanges"][0]["sent_parsed"]["ip_df"] = False
    assert B.check_run(r) != []


def test_bad_udp_checksum_fails():
    r = base()
    b = hexb(r, 1, "sent")
    b[26] ^= 0xFF
    put(r, 1, "sent", bytes(b))
    assert has(B.check_run(r), "UDP checksum")


def test_bad_icmp_checksum_fails():
    r = base()
    b = hexb(r, 2, "sent")
    b[22] ^= 0xFF
    put(r, 2, "sent", bytes(b))
    assert has(B.check_run(r), "ICMP checksum")


def test_missing_parsed_field_cannot_rebuild():
    r = base()
    del r["exchanges"][0]["sent_parsed"]["ip_ttl"]
    assert has(B.check_run(r), "rebuild")


def test_packet_without_parsed_fails():
    r = base()
    r["exchanges"][0]["sent_parsed"] = None
    assert has(B.check_run(r), "rebuild")


def _echo(r, data):
    p = r["exchanges"][2]["sent_parsed"]
    pkt = G.ip(SRC, DST, 1, G.icmp(8, 9, data=data), ip_id=p["ip_id"])
    put(r, 2, "sent", pkt)
    p["ip_len"] = len(pkt)


def test_echo_zero_padding_of_known_length_passes():
    for n in (120, 150):
        r = base()
        _echo(r, b"\x00" * n)
        assert B.check_run(r) == [], n


def test_echo_other_padding_fails():
    r = base()
    _echo(r, b"\x01" * 120)
    assert has(B.check_run(r), "rebuild")
    r = base()
    _echo(r, b"\x00" * 64)
    assert has(B.check_run(r), "rebuild")


def _unreach(r, quote_len=300, tamper=False):
    sent = bytes.fromhex(r["exchanges"][1]["sent"]["hex"])
    q = bytearray(sent[:28 + quote_len])
    if tamper:
        q[-1] ^= 0x01
    pkt = G.ip(DST, SRC, 1, G.icmp(3, 3, data=bytes(q)), ip_id=7)
    e = r["exchanges"][1]
    e["reply"] = {"hex": pkt.hex(), "len": len(pkt)}
    e["reply_parsed"] = {
        "l4": "icmp", "ip_src": DST, "ip_dst": SRC, "ip_id": 7, "ip_ttl": 64, "ip_df": True,
        "ip_len": len(pkt), "icmp_type": 3, "icmp_code": 3, "icmp_unused": 0,
        "embedded_ip_ttl": sent[8], "embedded_ip_id": int.from_bytes(sent[4:6], "big"),
        "embedded_ip_len": int.from_bytes(sent[2:4], "big"),
        "embedded_ip_sum": int.from_bytes(sent[10:12], "big"),
        "embedded_udp_sum": int.from_bytes(sent[26:28], "big"),
    }
    e["timeout"] = False


def test_unreachable_quote_rebuilt_from_probe_passes():
    r = base()
    _unreach(r)
    assert B.check_run(r) == []
    r = base()
    _unreach(r, quote_len=0)
    assert B.check_run(r) == []


def test_unreachable_quote_with_free_byte_fails():
    r = base()
    _unreach(r, tamper=True)
    assert has(B.check_run(r), "rebuild")


def test_rebuild_is_exact_for_options():
    r = base()
    p = r["exchanges"][0]["sent_parsed"]
    assert B.rebuild_packet(p) == bytes.fromhex(r["exchanges"][0]["sent"]["hex"])
