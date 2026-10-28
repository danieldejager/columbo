"""Build fake IPv4 packets (documentation addresses only) for test fixtures,
with real IP, TCP, UDP and ICMP checksums."""
import struct

FLAG_BITS = "FSRPAUEC"


def flags_value(s):
    v = 0
    for ch in s:
        v |= 1 << FLAG_BITS.index(ch)
    return v


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def fix_checksums(pkt):
    """Recompute every checksum in a 20-byte-header IPv4 packet."""
    b = bytearray(pkt)
    b[10:12] = b"\x00\x00"
    b[10:12] = struct.pack("!H", csum(bytes(b[:20])))
    proto, l4 = b[9], b[20:]
    pseudo = bytes(b[12:20]) + struct.pack("!BBH", 0, proto, len(l4))
    if proto == 6:
        l4[16:18] = b"\x00\x00"
        l4[16:18] = struct.pack("!H", csum(pseudo + bytes(l4)))
    elif proto == 17:
        l4[6:8] = b"\x00\x00"
        c = csum(pseudo + bytes(l4))
        l4[6:8] = struct.pack("!H", c or 0xFFFF)
    elif proto == 1:
        l4[2:4] = b"\x00\x00"
        l4[2:4] = struct.pack("!H", csum(bytes(l4)))
    return bytes(b[:20]) + bytes(l4)


def ip(src, dst, proto, payload, ip_id=1, ttl=64, df=True, tos=0, frag=None):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos, total, ip_id,
                      (0x4000 if df else 0) if frag is None else frag,
                      ttl, proto, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return fix_checksums(hdr + payload)


def tcp(sport, dport, seq=0, ack=0, flags="", window=0, options=b"", urgptr=0):
    off = (20 + len(options)) // 4
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags_value(flags),
                       window, 0, urgptr) + options


def udp(sport, dport, data=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def icmp(itype, code, rest=b"\x00" * 4, data=b""):
    return struct.pack("!BBH", itype, code, 0) + rest + data
