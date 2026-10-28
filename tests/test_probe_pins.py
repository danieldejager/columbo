"""Probe field pins: two probes of the published scanner method carry fixed
non zero header fields. Only those exact values, on that probe name, exchange
kind and flags, in the sent packet, are accepted; everything else stays zero."""
import json
import sys
from pathlib import Path

from tools.checks import bundle as B

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pktgen as G  # noqa: E402

FIX = HERE / "fixtures" / "runs"
SRC, DST = "192.0.2.10", "192.0.2.1"


def tcp_pkt(flags="SEC", urgptr=63477, reserved=4, tos=0):
    seg = bytearray(G.tcp(40000, 22, seq=1000, flags=flags, window=3, urgptr=urgptr))
    seg[12] |= reserved << 1
    return G.fix_checksums(G.ip(SRC, DST, 6, bytes(seg), ip_id=100, tos=tos))


def icmp_pkt(tos=4):
    return G.fix_checksums(G.ip(SRC, DST, 1, G.icmp(8, 9, data=b"\x00" * 150), ip_id=101, df=False, tos=tos))


def run_with(name, kind, pkt, reserved=None, where="sent"):
    r = json.loads((FIX / "pass-run.json").read_text())
    parsed = {k: v for k, v in B.decode_ipv4(pkt).items() if k in B.PARSED_KEYS}
    if parsed["l4"] == "tcp":
        parsed["reserved"] = (pkt[32] >> 1) & 7 if reserved is None else reserved
        parsed["options_raw"] = []
    else:
        parsed["icmp_unused"] = 0
    e = {"name": name, "kind": kind, "timeout": where == "sent"}
    if where == "sent":
        e.update(sent={"hex": pkt.hex(), "len": len(pkt)}, sent_parsed=parsed)
    else:
        sent = r["exchanges"][0]
        e.update(sent=sent["sent"], sent_parsed=sent["sent_parsed"],
                 reply={"hex": pkt.hex(), "len": len(pkt)}, reply_parsed=parsed, timeout=False)
    r["exchanges"] = [e]
    return B.check_run(r)


def test_pin_table_is_the_two_exact_probes():
    assert set(B.PROBE_FIELD_PINS) == {("ECN", "ecn"), ("IE2", "icmp")}
    assert B.PROBE_FIELD_PINS[("ECN", "ecn")] == {"l4": "tcp", "flags": "SEC", "ip_tos": 0, "urgptr": 63477, "reserved": 4}
    assert B.PROBE_FIELD_PINS[("IE2", "icmp")] == {"l4": "icmp", "ip_tos": 4}


def test_ecn_exact_pin_passes_and_rebuilds():
    assert run_with("ECN", "ecn", tcp_pkt()) == []


def test_ie2_exact_pin_passes_and_rebuilds():
    assert run_with("IE2", "icmp", icmp_pkt()) == []


def test_ecn_urgent_pointer_off_by_one_fails():
    assert any("urgent pointer" in e for e in run_with("ECN", "ecn", tcp_pkt(urgptr=63476)))


def test_ecn_urgent_pointer_zero_fails():
    assert any("urgent pointer" in e for e in run_with("ECN", "ecn", tcp_pkt(urgptr=0)))


def test_ecn_other_reserved_bits_fail():
    for res in (0, 1, 2, 5, 7):
        assert any("reserved" in e for e in run_with("ECN", "ecn", tcp_pkt(reserved=res))), res


def test_ecn_non_zero_tos_fails():
    assert any("TOS" in e for e in run_with("ECN", "ecn", tcp_pkt(tos=4)))


def test_ecn_values_with_other_flags_fail():
    errs = run_with("ECN", "ecn", tcp_pkt(flags="SE"))
    assert any("urgent pointer" in e for e in errs) and any("reserved" in e for e in errs)


def test_ecn_values_under_another_kind_fail():
    assert run_with("ECN", "tcp_unusual", tcp_pkt()) != []


def test_ie2_tos_five_fails():
    assert any("TOS" in e for e in run_with("IE2", "icmp", icmp_pkt(tos=5)))


def test_ie2_tos_zero_fails():
    assert any("TOS" in e for e in run_with("IE2", "icmp", icmp_pkt(tos=0)))


def test_tos_four_on_t2_fails():
    assert any("TOS" in e for e in run_with("T2", "tcp_unusual", tcp_pkt(flags="", urgptr=0, reserved=0, tos=4)))


def test_tos_four_on_ie1_fails():
    assert any("TOS" in e for e in run_with("IE1", "icmp", icmp_pkt(tos=4)))


def test_ecn_urgent_pointer_on_another_probe_fails():
    for name, kind in (("T2", "tcp_unusual"), ("SEQ1", "syn_seq")):
        errs = run_with(name, kind, tcp_pkt())
        assert any("urgent pointer" in e for e in errs) and any("reserved" in e for e in errs), name


def test_pins_do_not_apply_to_replies():
    errs = run_with("ECN", "ecn", tcp_pkt(), where="reply")
    assert any("urgent pointer" in e for e in errs)
    assert any("TOS" in e for e in run_with("IE2", "icmp", icmp_pkt(), where="reply"))


def test_parsed_tos_mismatch_fails_rebuild():
    pkt = icmp_pkt()
    r = json.loads((FIX / "pass-run.json").read_text())
    parsed = {k: v for k, v in B.decode_ipv4(pkt).items() if k in B.PARSED_KEYS}
    parsed["icmp_unused"] = 0
    parsed["ip_tos"] = None
    r["exchanges"] = [{"name": "IE2", "kind": "icmp", "timeout": True,
                       "sent": {"hex": pkt.hex(), "len": len(pkt)}, "sent_parsed": parsed}]
    assert any("rebuild" in e for e in B.check_run(r))


# Reply pin: the reply to the ECN probe may carry IP TOS 2, exact value only.

def test_reply_pin_table_is_one_exact_value():
    assert B.REPLY_FIELD_PINS == {("ECN", "ecn"): {"l4": "tcp", "ip_tos": 2}}


def test_ecn_reply_tos_two_passes_and_rebuilds():
    assert run_with("ECN", "ecn", tcp_pkt(flags="SA", urgptr=0, reserved=0, tos=2), where="reply") == []


def test_ecn_reply_tos_zero_still_passes():
    assert run_with("ECN", "ecn", tcp_pkt(flags="SA", urgptr=0, reserved=0, tos=0), where="reply") == []


def test_ecn_reply_other_tos_fails():
    for tos in (1, 3, 4):
        errs = run_with("ECN", "ecn", tcp_pkt(flags="SA", urgptr=0, reserved=0, tos=tos), where="reply")
        assert any("TOS" in e for e in errs), tos


def test_tos_two_on_other_replies_fails():
    for name, kind in (("T1", "tcp"), ("T2", "tcp"), ("SEQ1", "seq"), ("ECN", "tcp")):
        errs = run_with(name, kind, tcp_pkt(flags="SA", urgptr=0, reserved=0, tos=2), where="reply")
        assert any("TOS" in e for e in errs), (name, kind)
    errs = run_with("IE2", "icmp", icmp_pkt(tos=2), where="reply")
    assert any("TOS" in e for e in errs)


def test_tos_two_on_sent_packets_fails():
    assert any("TOS" in e for e in run_with("ECN", "ecn", tcp_pkt(tos=2)))
    assert any("TOS" in e for e in run_with("T1", "tcp", tcp_pkt(flags="S", urgptr=0, reserved=0, tos=2)))
    assert any("TOS" in e for e in run_with("IE2", "icmp", icmp_pkt(tos=2)))


def test_ecn_reply_parsed_tos_must_equal_bytes():
    pkt = tcp_pkt(flags="SA", urgptr=0, reserved=0, tos=2)
    r = json.loads((FIX / "pass-run.json").read_text())
    parsed = {k: v for k, v in B.decode_ipv4(pkt).items() if k in B.PARSED_KEYS}
    parsed["reserved"] = 0
    parsed["options_raw"] = []
    parsed["ip_tos"] = 0
    sent = r["exchanges"][0]
    r["exchanges"] = [{"name": "ECN", "kind": "ecn", "timeout": False, "sent": sent["sent"],
                       "sent_parsed": sent["sent_parsed"], "reply": {"hex": pkt.hex(), "len": len(pkt)},
                       "reply_parsed": parsed}]
    assert B.check_run(r) != []
