"""Minimal BER (ASN.1) encoder/decoder and MMS Data/TypeSpecification codecs."""
import struct
import time


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content=b""):
    return bytes([tag]) + ber_len(len(content)) + content


def enc_uint(value):
    return value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")


def enc_int(value):
    n = 1
    while True:
        try:
            return value.to_bytes(n, "big", signed=True)
        except OverflowError:
            n += 1


def ber_uint(tag, value):
    return tlv(tag, enc_uint(value))


def ber_parse(data):
    """Return list of (tag, content) for all TLVs at one level."""
    out, i, n = [], 0, len(data)
    while i < n:
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:
            while data[i] & 0x80:
                i += 1
            i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(data[i:i + nb], "big")
            i += nb
        out.append((tag, bytes(data[i:i + ln])))
        i += ln
    return out


def first(items, tag):
    for t, c in items:
        if t == tag:
            return c
    return None


# ---------------------------------------------------------------------------
# MMS Data
# Python representation:
#   structure/array -> list ; boolean -> bool ; integer/unsigned -> int
#   float -> float ; octet-string -> bytes ; visible/mms string -> str
#   bit-string -> BitString ; utc-time -> UtcTime
# ---------------------------------------------------------------------------

class BitString:
    __slots__ = ("bits",)

    def __init__(self, bits):
        self.bits = bits            # string of '0'/'1'

    def __repr__(self):
        return self.bits

    def __eq__(self, o):
        return isinstance(o, BitString) and o.bits == self.bits

    def to_json(self):
        return self.bits


class UtcTime:
    __slots__ = ("secs", "quality")

    def __init__(self, secs, quality=0x0A):
        self.secs, self.quality = secs, quality

    def __repr__(self):
        t = time.gmtime(self.secs)
        return time.strftime("%Y-%m-%d %H:%M:%S", t) + f".{int((self.secs % 1) * 1000):03d}Z"

    def to_json(self):
        return repr(self)

    def encode(self):
        s = int(self.secs)
        frac = int((self.secs - s) * (1 << 24)) & 0xFFFFFF
        return s.to_bytes(4, "big") + frac.to_bytes(3, "big") + bytes([self.quality])

    @staticmethod
    def decode(c):
        if len(c) != 8:
            return c.hex()
        s = int.from_bytes(c[:4], "big")
        frac = int.from_bytes(c[4:7], "big") / (1 << 24)
        return UtcTime(s + frac, c[7])


class FailedAccess:
    def __init__(self, code):
        self.code = code

    def __repr__(self):
        return f"<access-error {self.code}>"

    def to_json(self):
        return {"error": self.code}


def decode_data(tag, c):
    if tag in (0xA1, 0xA2):
        return [decode_data(t, v) for t, v in ber_parse(c)]
    if tag == 0x83:
        return c != b"\x00"
    if tag == 0x84:
        if not c:
            return BitString("")
        unused = c[0]
        bits = "".join(f"{b:08b}" for b in c[1:])
        return BitString(bits[:len(bits) - unused] if unused else bits)
    if tag == 0x85:
        return int.from_bytes(c, "big", signed=True)
    if tag == 0x86:
        return int.from_bytes(c, "big", signed=False)
    if tag == 0x87:
        if len(c) == 5:
            return struct.unpack(">f", c[1:])[0]
        if len(c) == 9:
            return struct.unpack(">d", c[1:])[0]
        return c.hex()
    if tag == 0x89:
        return bytes(c)
    if tag in (0x8A, 0x90):
        return c.decode("utf-8", "replace")
    if tag == 0x91:
        return UtcTime.decode(c)
    if tag == 0x8C:
        return c.hex()
    if tag == 0x80:
        return FailedAccess(int.from_bytes(c, "big"))
    return c.hex()


def to_jsonable(v):
    if isinstance(v, list):
        return [to_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: to_jsonable(x) for k, x in v.items()}
    if isinstance(v, (bytes, bytearray)):
        return v.hex(" ").upper()
    if hasattr(v, "to_json"):
        return v.to_json()
    if isinstance(v, float):
        return round(v, 6)
    return v


def fmt_value(v):
    """Short human-readable rendering of a decoded value."""
    if isinstance(v, list):
        return "{" + ", ".join(fmt_value(x) for x in v) + "}"
    if isinstance(v, (bytes, bytearray)):
        return v.hex(" ").upper()
    if isinstance(v, float):
        return f"{v:.4g}"
    return str(v)


def decode_type(c):
    """Decode a TypeSpecification into [(name, subtree)] for structures, else None."""
    items = ber_parse(c)
    if not items:
        return None
    tag, body = items[0]
    if tag == 0xA2:
        comps = []
        comp_list = first(ber_parse(body), 0xA1)
        for _, comp in ber_parse(comp_list or b""):
            parts = ber_parse(comp)
            name = first(parts, 0x80)
            ctype = first(parts, 0xA1)
            comps.append((name.decode() if name else "?", decode_type(ctype) if ctype else None))
        return comps
    if tag == 0xA1:                         # array: [elementCount, packed?, elementType]
        parts = ber_parse(body)
        et = first(parts, 0xA2)
        return ("array", decode_type(et) if et else None)
    return None


def name_values(type_tree, value):
    if isinstance(type_tree, tuple) and type_tree and type_tree[0] == "array" and isinstance(value, list):
        return [name_values(type_tree[1], v) for v in value]
    if not isinstance(type_tree, list) or not isinstance(value, list):
        return value
    return {n: name_values(t, v) for (n, t), v in zip(type_tree, value)}
