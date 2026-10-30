"""Build an MMS data model (value tree) for one IED from an SCL file."""
import struct
import time

from .ber import tlv, enc_int, enc_uint, UtcTime, BitString

FC_ORDER = ["ST", "MX", "SP", "SV", "CF", "DC", "SG", "SE", "SR", "OR", "BL", "EX", "CO", "US", "MS", "RP", "BR", "LG", "GO"]


class Leaf:
    __slots__ = ("mtype", "size", "value", "btype", "enum")

    def __init__(self, mtype, size, value, btype=None, enum=None):
        self.mtype, self.size, self.value, self.btype, self.enum = mtype, size, value, btype, enum

    def type_spec(self):
        t, n = self.mtype, self.size
        if t == "bool":
            return tlv(0x83)
        if t == "int":
            return tlv(0x85, bytes([n]))
        if t == "uint":
            return tlv(0x86, bytes([n]))
        if t == "float":
            return tlv(0xA7, tlv(0x02, bytes([n])) + tlv(0x02, b"\x08" if n == 32 else b"\x0B"))
        if t == "bits":
            return tlv(0x84, enc_int(n))
        if t == "vis":
            return tlv(0x8A, enc_int(-n))
        if t == "mmsstr":
            return tlv(0x90, enc_int(-n))
        if t == "octets":
            return tlv(0x89, enc_int(-n))
        if t == "utc":
            return tlv(0x91)
        if t == "btime":
            return tlv(0x8C, b"\xFF")
        return tlv(0x8A, enc_int(-255))

    def encode(self):
        t, v = self.mtype, self.value
        if t == "bool":
            return tlv(0x83, b"\xFF" if v else b"\x00")
        if t == "int":
            return tlv(0x85, enc_int(int(v)))
        if t == "uint":
            return tlv(0x86, enc_uint(int(v)))
        if t == "float":
            return tlv(0x87, b"\x08" + struct.pack(">f", float(v))) if self.size == 32 else \
                tlv(0x87, b"\x0B" + struct.pack(">d", float(v)))
        if t == "bits":
            bits = v.bits if isinstance(v, BitString) else str(v)
            bits = bits.ljust(self.size, "0")[:self.size]
            pad = (8 - len(bits) % 8) % 8
            b = int(bits + "0" * pad, 2).to_bytes((len(bits) + pad) // 8, "big") if bits else b""
            return tlv(0x84, bytes([pad]) + b)
        if t == "vis":
            return tlv(0x8A, str(v).encode())
        if t == "mmsstr":
            return tlv(0x90, str(v).encode())
        if t == "octets":
            return tlv(0x89, bytes(v))
        if t == "utc":
            return tlv(0x91, (v if isinstance(v, UtcTime) else UtcTime(float(v or 0))).encode())
        if t == "btime":
            return tlv(0x8C, b"\x00" * 6)
        return tlv(0x8A, str(v).encode())

    def display(self):
        v = self.value
        if self.enum and isinstance(v, int) and v in self.enum:
            return f"{self.enum[v]} ({v})"
        if self.btype == "Dbpos" and isinstance(v, BitString):
            return {"00": "intermediate", "01": "off", "10": "on", "11": "bad"}.get(v.bits, v.bits) + f" ({v.bits})"
        if isinstance(v, (bytes, bytearray)):
            return v.hex("-").upper()
        if isinstance(v, float):
            return f"{v:.4g}"
        return str(v)


class Struct:
    __slots__ = ("children",)

    def __init__(self):
        self.children = []          # list of (name, node)

    def get(self, name):
        for n, c in self.children:
            if n == name:
                return c
        return None

    def add(self, name, node):
        self.children.append((name, node))

    def type_spec(self):
        comps = b"".join(tlv(0x30, tlv(0x80, n.encode()) + tlv(0xA1, c.type_spec())) for n, c in self.children)
        return tlv(0xA2, tlv(0xA1, comps))

    def encode(self):
        return tlv(0xA2, b"".join(c.encode() for _, c in self.children))


class Array:
    __slots__ = ("items",)

    def __init__(self, items):
        self.items = items

    def type_spec(self):
        return tlv(0xA1, tlv(0x81, enc_uint(len(self.items))) + tlv(0xA2, self.items[0].type_spec()))

    def encode(self):
        return tlv(0xA1, b"".join(c.encode() for c in self.items))


BTYPES = {
    "BOOLEAN": ("bool", 0), "INT8": ("int", 8), "INT16": ("int", 16), "INT24": ("int", 24),
    "INT32": ("int", 32), "INT64": ("int", 64), "INT128": ("int", 128),
    "INT8U": ("uint", 8), "INT16U": ("uint", 16), "INT24U": ("uint", 24), "INT32U": ("uint", 32),
    "FLOAT32": ("float", 32), "FLOAT64": ("float", 64), "Enum": ("int", 8),
    "Dbpos": ("bits", 2), "Tcmd": ("bits", 2), "Check": ("bits", 2), "Quality": ("bits", 13),
    "Timestamp": ("utc", 0), "VisString32": ("vis", 32), "VisString64": ("vis", 64),
    "VisString65": ("vis", 65), "VisString129": ("vis", 129), "VisString255": ("vis", 255),
    "ObjRef": ("vis", 129), "Unicode255": ("mmsstr", 255), "Octet64": ("octets", 64),
    "EntryID": ("octets", 8), "EntryTime": ("btime", 0), "TrgOps": ("bits", 6),
    "OptFlds": ("bits", 10), "SvOptFlds": ("bits", 5), "Currency": ("vis", 3),
}


DBPOS = {"intermediate-state": "00", "intermediate": "00", "off": "01", "on": "10", "bad-state": "11", "bad": "11"}
TCMD = {"stop": "00", "lower": "01", "higher": "10", "reserved": "11"}


def parse_bits(btype, text, size):
    t = str(text).strip()
    m = DBPOS if btype == "Dbpos" else TCMD if btype == "Tcmd" else {}
    if t.lower() in m:
        return BitString(m[t.lower()])
    if t and set(t) <= {"0", "1"}:
        return BitString(t.ljust(size, "0")[:size])
    return BitString("0" * size)


def _default(mtype, size):
    return {"bool": False, "int": 0, "uint": 0, "float": 0.0, "bits": BitString("0" * size),
            "vis": "", "mmsstr": "", "octets": b"", "utc": UtcTime(time.time()), "btime": b""}.get(mtype, "")


class IedModel:
    """domains: {ldName: Struct of LNs}; datasets: {(ld, item): [(ld, item)]}"""

    def __init__(self, scl, ied_name):
        self.scl = scl
        self.ied = scl.ieds[ied_name]
        self.name = ied_name
        self.T = scl.templates
        self.domains = {}
        self.datasets = {}
        self.name_lists = {}
        self._build()

    def _parse_val(self, mtype, size, text, enum_type):
        if text is None:
            return _default(mtype, size)
        try:
            if mtype == "bool":
                return text.strip().lower() in ("true", "1")
            if mtype in ("int", "uint"):
                if enum_type:
                    for k, v in self.T["EnumType"].get(enum_type, {}).items():
                        if v == text.strip():
                            return k
                return int(text)
            if mtype == "float":
                return float(text)
            if mtype == "bits":
                return parse_bits(None, text, size)
            if mtype == "octets":
                return text.encode()
        except ValueError:
            return _default(mtype, size)
        return text

    def _make_da(self, btype, typ, count, val, inst_vals, path):
        if count:
            return Array([self._make_da(btype, typ, 0, val, inst_vals, path + [str(i)]) for i in range(count)])
        if btype == "Struct":
            s = Struct()
            for b in self.T["DAType"].get(typ, []):
                s.add(b["name"], self._make_da(b["bType"], b["type"], b["count"], b["val"], inst_vals, path + [b["name"]]))
            return s
        mtype, size = BTYPES.get(btype, ("vis", 255))
        text = inst_vals.get(".".join(path), val)
        enum = self.T["EnumType"].get(typ) if btype == "Enum" else None
        if mtype == "bits":
            return Leaf(mtype, size, parse_bits(btype, text, size) if text is not None else _default(mtype, size), btype)
        return Leaf(mtype, size, self._parse_val(mtype, size, text, typ if btype == "Enum" else None), btype, enum)

    def _do_for_fc(self, do_type, fc, inst_vals, path):
        dot = self.T["DOType"].get(do_type)
        if not dot:
            return None
        s = Struct()
        for it in dot["items"]:
            if it["kind"] == "DA" and it["fc"] == fc:
                s.add(it["name"], self._make_da(it["bType"], it["type"], it["count"], it["val"], inst_vals,
                                                path + [it["name"]]))
            elif it["kind"] == "SDO":
                sub = self._do_for_fc(it["type"], fc, inst_vals, path + [it["name"]])
                if sub is not None:
                    s.add(it["name"], sub)
        return s if s.children else None

    def _fcs_of(self, do_type, acc=None):
        acc = set() if acc is None else acc
        dot = self.T["DOType"].get(do_type) or {"items": []}
        for it in dot["items"]:
            if it["kind"] == "DA" and it["fc"]:
                acc.add(it["fc"])
            elif it["kind"] == "SDO":
                self._fcs_of(it["type"], acc)
        return acc

    def _build(self):
        for ld in self.ied["lds"]:
            dom = Struct()
            for ln in ld["lns"]:
                lnt = self.T["LNodeType"].get(ln["lnType"])
                fcs = {}
                if lnt:
                    for do in lnt["dos"]:
                        for fc in self._fcs_of(do["type"]):
                            node = self._do_for_fc(do["type"], fc, ln["doi"], [do["name"]])
                            if node is not None:
                                fcs.setdefault(fc, Struct()).add(do["name"], node)
                if ln["name"] == "LLN0":
                    for cb in self.ied["gocbs"]:
                        if cb["ld"] == ld["name"]:
                            fcs.setdefault("GO", Struct()).add(cb["name"], self._gocb_node(cb))
                    for cb in self.ied["svcbs"]:
                        if cb["ld"] == ld["name"]:
                            fcs.setdefault("MS", Struct()).add(cb["name"], self._svcb_node(cb))
                ln_node = Struct()
                for fc in sorted(fcs, key=lambda f: FC_ORDER.index(f) if f in FC_ORDER else 99):
                    ln_node.add(fc, fcs[fc])
                dom.add(ln["name"], ln_node)
            self.domains[ld["name"]] = dom
        for ref, ds in self.ied["datasets"].items():
            ld, item = ref.split("/", 1)
            self.datasets[(ld, item)] = [tuple(m.split("/", 1)) for m in ds["members"]]
        for d, s in self.domains.items():
            names = []

            def walk(node, prefix):
                if isinstance(node, Struct):
                    for n, c in node.children:
                        p = f"{prefix}${n}" if prefix else n
                        names.append(p)
                        walk(c, p)
            walk(s, "")
            self.name_lists[d] = sorted(names)

    @staticmethod
    def _phycomaddr(cb):
        s = Struct()
        mac = cb.get("mac") or "01-0C-CD-01-00-00"
        s.add("Addr", Leaf("octets", 6, bytes(int(x, 16) for x in mac.split("-")), "Octet64"))
        s.add("PRIORITY", Leaf("uint", 8, cb.get("vlanPriority") if cb.get("vlanPriority") is not None else 4))
        s.add("VID", Leaf("uint", 16, cb.get("vlanId") or 0))
        s.add("APPID", Leaf("uint", 16, cb.get("appId") or 0))
        return s

    def _gocb_node(self, cb):
        s = Struct()
        s.add("GoEna", Leaf("bool", 0, True))
        s.add("GoID", Leaf("vis", 129, cb.get("id") or cb["ref"]))
        s.add("DatSet", Leaf("vis", 129, cb.get("datSet") or ""))
        s.add("ConfRev", Leaf("uint", 32, cb.get("confRev") or 1))
        s.add("NdsCom", Leaf("bool", 0, False))
        s.add("DstAddress", self._phycomaddr(cb))
        s.add("MinTime", Leaf("uint", 32, cb.get("minTime") or 4))
        s.add("MaxTime", Leaf("uint", 32, cb.get("maxTime") or 1000))
        s.add("FixedOffs", Leaf("bool", 0, bool(cb.get("fixedOffs"))))
        return s

    def _svcb_node(self, cb):
        s = Struct()
        s.add("SvEna", Leaf("bool", 0, True))
        s.add("MsvID", Leaf("vis", 129, cb.get("id") or ""))
        s.add("DatSet", Leaf("vis", 129, cb.get("datSet") or ""))
        s.add("ConfRev", Leaf("uint", 32, cb.get("confRev") or 1))
        s.add("SmpRate", Leaf("uint", 16, cb.get("smpRate") or 80))
        s.add("OptFlds", Leaf("bits", 5, BitString("00000")))
        s.add("SmpMod", Leaf("int", 8, 0))
        s.add("DstAddress", self._phycomaddr(cb))
        s.add("noASDU", Leaf("uint", 16, cb.get("nofASDU") or 1))
        return s

    # ------------------------------------------------------------------
    def lookup(self, domain, item):
        node = self.domains.get(domain)
        if node is None:
            return None
        for part in item.split("$"):
            if isinstance(node, Struct):
                node = node.get(part)
            elif isinstance(node, Array) and part.isdigit() and int(part) < len(node.items):
                node = node.items[int(part)]
            else:
                return None
            if node is None:
                return None
        return node

    def leaves(self, node, prefix=""):
        if isinstance(node, Leaf):
            yield prefix, node
        elif isinstance(node, Struct):
            for n, c in node.children:
                yield from self.leaves(c, f"{prefix}${n}" if prefix else n)
        elif isinstance(node, Array):
            for i, c in enumerate(node.items):
                yield from self.leaves(c, f"{prefix}${i}")
