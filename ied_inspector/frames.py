"""Ethernet / GOOSE (IEC 61850-8-1) / SV (IEC 61850-9-2) frame codecs."""
import struct

from .ber import tlv, ber_parse, first, decode_data, enc_uint, UtcTime

ETH_GOOSE = 0x88B8
ETH_SV = 0x88BA
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)


def mac_str(b):
    return "-".join(f"{x:02X}" for x in b)


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.replace(":", "-").split("-"))


def parse_ethernet(frame):
    """Return dict(dst, src, vlan_id, vlan_prio, ethertype, payload) or None."""
    if len(frame) < 14:
        return None
    dst, src = frame[0:6], frame[6:12]
    et = struct.unpack(">H", frame[12:14])[0]
    off, vid, prio, tagged = 14, None, None, False
    while et in VLAN_TPIDS and len(frame) >= off + 4:
        tci = struct.unpack(">H", frame[off:off + 2])[0]
        if vid is None:
            vid, prio, tagged = tci & 0x0FFF, tci >> 13, True
        et = struct.unpack(">H", frame[off + 2:off + 4])[0]
        off += 4
    return {"dst": mac_str(dst), "src": mac_str(src), "tagged": tagged, "vlan_id": vid,
            "vlan_prio": prio, "ethertype": et, "payload": frame[off:]}


def _hdr(payload):
    appid, length, r1, r2 = struct.unpack(">HHHH", payload[:8])
    return appid, length, r1, r2, payload[8:length] if length >= 8 else payload[8:]


def parse_goose(payload):
    appid, length, r1, r2, apdu = _hdr(payload)
    items = ber_parse(first(ber_parse(apdu), 0x61) or b"")
    g = {"appId": appid, "simulationReserved": bool(r1 & 0x8000), "reserved1": r1}
    for tag, c in items:
        if tag == 0x80:
            g["gocbRef"] = c.decode("utf-8", "replace")
        elif tag == 0x81:
            g["tal"] = int.from_bytes(c, "big")
        elif tag == 0x82:
            g["datSet"] = c.decode("utf-8", "replace")
        elif tag == 0x83:
            g["goID"] = c.decode("utf-8", "replace")
        elif tag == 0x84:
            g["t"] = UtcTime.decode(c)
        elif tag == 0x85:
            g["stNum"] = int.from_bytes(c, "big")
        elif tag == 0x86:
            g["sqNum"] = int.from_bytes(c, "big")
        elif tag == 0x87:
            g["test"] = c != b"\x00"
        elif tag == 0x88:
            g["confRev"] = int.from_bytes(c, "big")
        elif tag == 0x89:
            g["ndsCom"] = c != b"\x00"
        elif tag == 0x8A:
            g["numEntries"] = int.from_bytes(c, "big")
        elif tag == 0xAB:
            g["data"] = [decode_data(t, v) for t, v in ber_parse(c)]
    return g


def parse_sv(payload):
    appid, length, r1, r2, apdu = _hdr(payload)
    sav = first(ber_parse(apdu), 0x60) or b""
    items = ber_parse(sav)
    out = {"appId": appid, "simulationReserved": bool(r1 & 0x8000), "asdus": []}
    seq = first(items, 0xA2)
    for _, asdu in ber_parse(seq or b""):
        a = {}
        for tag, c in ber_parse(asdu):
            if tag == 0x80:
                a["svID"] = c.decode("utf-8", "replace")
            elif tag == 0x81:
                a["datSet"] = c.decode("utf-8", "replace")
            elif tag == 0x82:
                a["smpCnt"] = int.from_bytes(c, "big")
            elif tag == 0x83:
                a["confRev"] = int.from_bytes(c, "big")
            elif tag == 0x85:
                a["smpSynch"] = c[0] if c else 0
            elif tag == 0x86:
                a["smpRate"] = int.from_bytes(c, "big")
            elif tag == 0x87:
                vals = []
                for i in range(0, len(c) - 7, 8):
                    v, q = struct.unpack(">iI", c[i:i + 8])
                    vals.append((v, q))
                a["values"] = vals
        out["asdus"].append(a)
    return out


# ------------------------------------------------------------------ encoders

def eth_header(dst, src, vlan_id, vlan_prio, ethertype):
    h = mac_bytes(dst) + mac_bytes(src)
    if vlan_id is not None:
        h += struct.pack(">HH", 0x8100, ((vlan_prio or 0) << 13) | (vlan_id & 0xFFF))
    return h + struct.pack(">H", ethertype)


def encode_goose(dst, src, vlan_id, vlan_prio, appid, gocb_ref, tal, datset, goid, t, st, sq,
                 test, confrev, ndscom, data_tlvs, simulation=False):
    pdu = (tlv(0x80, gocb_ref.encode()) + tlv(0x81, enc_uint(tal)) + tlv(0x82, datset.encode())
           + tlv(0x83, goid.encode()) + tlv(0x84, UtcTime(t).encode()) + tlv(0x85, enc_uint(st))
           + tlv(0x86, enc_uint(sq)) + tlv(0x87, b"\xFF" if test else b"\x00")
           + tlv(0x88, enc_uint(confrev)) + tlv(0x89, b"\xFF" if ndscom else b"\x00")
           + tlv(0x8A, enc_uint(len(data_tlvs))) + tlv(0xAB, b"".join(data_tlvs)))
    apdu = tlv(0x61, pdu)
    r1 = 0x8000 if simulation else 0
    body = struct.pack(">HHHH", appid, len(apdu) + 8, r1, 0) + apdu
    frame = eth_header(dst, src, vlan_id, vlan_prio, ETH_GOOSE) + body
    return frame + b"\x00" * max(0, 60 - len(frame))


def encode_sv(dst, src, vlan_id, vlan_prio, appid, svid, smpcnt, confrev, values, smpsynch=2, datset=None):
    seqdata = b"".join(struct.pack(">iI", v, q) for v, q in values)
    asdu = tlv(0x80, svid.encode())
    if datset:
        asdu += tlv(0x81, datset.encode())
    asdu += tlv(0x82, struct.pack(">H", smpcnt & 0xFFFF)) + tlv(0x83, struct.pack(">I", confrev)) \
        + tlv(0x85, bytes([smpsynch])) + tlv(0x87, seqdata)
    sav = tlv(0x60, tlv(0x80, b"\x01") + tlv(0xA2, tlv(0x30, asdu)))
    body = struct.pack(">HHHH", appid, len(sav) + 8, 0, 0) + sav
    return eth_header(dst, src, vlan_id, vlan_prio, ETH_SV) + body
