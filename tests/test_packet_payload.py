"""Packet payload rule: the packet bytes must hold nothing the parsed fields do
not describe. TCP and ICMP carry no payload, TCP option bytes equal options_raw
re-encoded, and UDP payload is only the known probe shape."""
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


def base():
    return json.loads((FIX / "pass-run.json").read_text())


def set_sent(r, i, pkt):
    r["exchanges"][i]["sent"] = {"hex": pkt.hex(), "len": len(pkt)}
    r["exchanges"][i]["sent_parsed"]["ip_len"] = len(pkt)


def errs_mention(errs, word):
    return any(word in e for e in errs)


def test_fixture_still_passes():
    assert B.check_run(base()) == []


def test_tcp_payload_with_corrected_lengths_fails():
    r = base()
    seg = G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=bytes.fromhex("020405b4"))
    set_sent(r, 0, G.ip(SRC, DST, 6, seg + b"extra", ip_id=100))
    assert errs_mention(B.check_run(r), "payload")


def test_altered_mss_option_byte_fails():
    r = base()
    seg = G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=bytes.fromhex("020405b5"))
    set_sent(r, 0, G.ip(SRC, DST, 6, seg, ip_id=100))
    assert errs_mention(B.check_run(r), "options_raw")


def test_option_bytes_without_options_raw_fail():
    r = base()
    del r["exchanges"][0]["sent_parsed"]["options_raw"]
    assert errs_mention(B.check_run(r), "options_raw")


def test_options_with_nop_eol_and_padding_pass():
    r = base()
    opts = bytes.fromhex("020405b4" "01" "030307" "0402" "080a0000000100000000" "00" "000000")
    seg = G.tcp(40000, 22, seq=1000, flags="S", window=1024, options=opts)
    set_sent(r, 0, G.ip(SRC, DST, 6, seg, ip_id=100))
    r["exchanges"][0]["sent_parsed"]["options_raw"] = [
        ["MSS", 1460], ["NOP"], ["WScale", 7], ["SAckOK"], ["Timestamp", [1, 0]], ["EOL"]]
    assert B.check_run(r) == []


def test_udp_payload_other_than_probe_shape_fails():
    r = base()
    set_sent(r, 1, G.ip(SRC, DST, 17, G.udp(40001, 1, b"C" * 299 + b"D"), ip_id=4162, df=False))
    assert errs_mention(B.check_run(r), "payload")


def test_udp_length_field_must_match():
    r = base()
    u = bytearray(G.udp(40001, 1, b"C" * 300))
    struct.pack_into("!H", u, 4, 100)
    set_sent(r, 1, G.ip(SRC, DST, 17, bytes(u), ip_id=4162, df=False))
    assert B.check_run(r) != []


def test_icmp_echo_payload_fails():
    r = base()
    pkt = bytes.fromhex(r["exchanges"][2]["sent"]["hex"])
    body = pkt[20:] + b"\x00" * 8
    set_sent(r, 2, G.ip(SRC, DST, 1, body, ip_id=int.from_bytes(pkt[4:6], "big"), df=bool(pkt[6] & 0x40)))
    assert errs_mention(B.check_run(r), "payload")
