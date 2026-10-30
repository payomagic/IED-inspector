"""ISO-on-TCP transport helpers (TPKT / COTP / Session / Presentation) shared by client and server."""
import socket

from .ber import tlv, ber_parse, first


class MmsError(Exception):
    pass


MMS_AC_OID = bytes.fromhex("28CA220203")      # 1.0.9506.2.3 MMS application context
ACSE_AS_OID = bytes.fromhex("52010001")       # 2.2.1.0.1 ACSE abstract syntax
MMS_AS_OID = bytes.fromhex("28CA220201")      # 1.0.9506.2.1 MMS abstract syntax
BER_TS_OID = b"\x51\x01"                      # 2.1.1 BER transfer syntax


class IsoTransport:
    def __init__(self, sock):
        self.sock = sock

    def send_tpkt(self, payload):
        self.sock.sendall(b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload)

    def recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise MmsError("connection closed by peer")
            buf += chunk
        return bytes(buf)

    def recv_tpkt(self):
        hdr = self.recv_exact(4)
        if hdr[0] != 3:
            raise MmsError("invalid TPKT header")
        return self.recv_exact(int.from_bytes(hdr[2:4], "big") - 4)

    def recv_cotp_data(self):
        data = b""
        while True:
            pkt = self.recv_tpkt()
            if len(pkt) < 3 or pkt[1] != 0xF0:
                raise MmsError(f"unexpected COTP PDU 0x{pkt[1]:02X}" if len(pkt) > 1 else "short COTP PDU")
            data += pkt[3:]
            if pkt[2] & 0x80:
                return data

    def send_cotp_data(self, payload, max_tpdu=1024):
        chunk = max_tpdu - 3
        for i in range(0, max(len(payload), 1), chunk):
            last = i + chunk >= len(payload)
            self.send_tpkt(b"\x02\xF0" + (b"\x80" if last else b"\x00") + payload[i:i + chunk])


def spdu_param(pi, value):
    if len(value) < 255:
        return bytes([pi, len(value)]) + value
    return bytes([pi, 0xFF]) + len(value).to_bytes(2, "big") + value


def spdu(si, params):
    if len(params) < 255:
        return bytes([si, len(params)]) + params
    return bytes([si, 0xFF]) + len(params).to_bytes(2, "big") + params


def session_params(spdu_bytes):
    """Return {pi: value} for a Session SPDU (flattening PGI 0x05 etc. not needed here)."""
    i = 2 if spdu_bytes[1] != 0xFF else 4
    out = {}
    while i < len(spdu_bytes):
        pi = spdu_bytes[i]
        ln = spdu_bytes[i + 1]
        hl = 2
        if ln == 0xFF:
            ln = int.from_bytes(spdu_bytes[i + 2:i + 4], "big")
            hl = 4
        out[pi] = spdu_bytes[i + hl:i + hl + ln]
        i += hl + ln
    return out


def wrap_data(mms_pdu):
    """Session GIVE-TOKENS + DATA-TRANSFER + Presentation user-data around an MMS PDU."""
    pres = tlv(0x61, tlv(0x30, tlv(0x02, b"\x03") + tlv(0xA0, mms_pdu)))
    return b"\x01\x00\x01\x00" + pres


def unwrap_data(spdu_bytes):
    if spdu_bytes[:2] != b"\x01\x00":
        raise MmsError(f"unexpected session SPDU 0x{spdu_bytes[0]:02X}")
    pres = spdu_bytes[4:]
    pdv = first(ber_parse(first(ber_parse(pres), 0x61)), 0x30)
    return first(ber_parse(pdv), 0xA0)
