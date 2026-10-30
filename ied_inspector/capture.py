"""Network interface listing, live Layer-2 capture/send and pcap/pcapng file I/O.

Backends:
  * Linux  : AF_PACKET raw socket (no extra software). VLAN tags removed by
             NIC offload are restored from PACKET_AUXDATA.
  * Windows: Npcap (wpcap.dll) through ctypes. Install Npcap once from npcap.com.
  * Any OS : libpcap through ctypes if present.
"""
import ctypes
import ctypes.util
import os
import socket
import struct
import sys
import threading
import time

IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# ---------------------------------------------------------------------------
# libpcap / Npcap via ctypes
# ---------------------------------------------------------------------------
_pcap = None
_pcap_err = None


class _sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 14)]


class _pcap_addr(ctypes.Structure):
    pass


_pcap_addr._fields_ = [("next", ctypes.POINTER(_pcap_addr)), ("addr", ctypes.POINTER(_sockaddr)),
                       ("netmask", ctypes.POINTER(_sockaddr)), ("broadaddr", ctypes.POINTER(_sockaddr)),
                       ("dstaddr", ctypes.POINTER(_sockaddr))]


class _pcap_if(ctypes.Structure):
    pass


_pcap_if._fields_ = [("next", ctypes.POINTER(_pcap_if)), ("name", ctypes.c_char_p),
                     ("description", ctypes.c_char_p), ("addresses", ctypes.POINTER(_pcap_addr)),
                     ("flags", ctypes.c_uint)]


class _timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _pkthdr(ctypes.Structure):
    _fields_ = [("ts", _timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


def load_pcap():
    global _pcap, _pcap_err
    if _pcap is not None or _pcap_err is not None:
        return _pcap
    try:
        if IS_WIN:
            npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
            if os.path.isdir(npcap_dir):
                os.add_dll_directory(npcap_dir)
                os.environ["PATH"] = npcap_dir + os.pathsep + os.environ.get("PATH", "")
            lib = ctypes.CDLL("wpcap.dll")
        else:
            name = ctypes.util.find_library("pcap")
            if not name:
                raise OSError("libpcap not found")
            lib = ctypes.CDLL(name)
        lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_pcap_if)), ctypes.c_char_p]
        lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if)]
        lib.pcap_open_live.restype = ctypes.c_void_p
        lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_pkthdr)),
                                     ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        lib.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        lib.pcap_close.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        _pcap = lib
    except Exception as e:
        _pcap_err = str(e)
    return _pcap


def pcap_status():
    lib = load_pcap()
    if lib:
        try:
            lib.pcap_lib_version.restype = ctypes.c_char_p
            return {"available": True, "version": lib.pcap_lib_version().decode()}
        except Exception:
            return {"available": True, "version": "unknown"}
    return {"available": False, "error": _pcap_err}


# ---------------------------------------------------------------------------
# Interface listing
# ---------------------------------------------------------------------------

def _linux_ipv4(ifname):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode()))
        return [socket.inet_ntoa(r[20:24])]
    except OSError:
        return []
    finally:
        s.close()


def list_interfaces():
    out = []
    if IS_LINUX:
        for _, name in socket.if_nameindex():
            mac = ""
            try:
                mac = open(f"/sys/class/net/{name}/address").read().strip().upper().replace(":", "-")
            except OSError:
                pass
            state = ""
            try:
                state = open(f"/sys/class/net/{name}/operstate").read().strip()
            except OSError:
                pass
            out.append({"id": name, "name": name, "description": state, "ips": _linux_ipv4(name),
                        "mac": mac, "backend": "af_packet"})
        return out
    lib = load_pcap()
    if not lib:
        return out
    alldevs = ctypes.POINTER(_pcap_if)()
    err = ctypes.create_string_buffer(256)
    if lib.pcap_findalldevs(ctypes.byref(alldevs), err) != 0:
        return out
    d = alldevs
    while d:
        dev = d.contents
        ips = []
        a = dev.addresses
        while a:
            ad = a.contents
            if ad.addr and ad.addr.contents.sa_family == 2:
                ips.append(".".join(str(x) for x in bytes(ad.addr.contents.sa_data)[2:6]))
            a = ad.next
        out.append({"id": dev.name.decode(), "name": (dev.description or dev.name).decode(errors="replace"),
                    "description": dev.name.decode(), "ips": ips, "mac": "", "backend": "pcap"})
        d = dev.next
    lib.pcap_freealldevs(alldevs)
    return out


def interface_mac(iface):
    if IS_LINUX:
        try:
            return open(f"/sys/class/net/{iface}/address").read().strip().upper().replace(":", "-")
        except OSError:
            pass
    return "00-1A-2B-3C-4D-5E"


# ---------------------------------------------------------------------------
# Live capture / sender
# ---------------------------------------------------------------------------
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 0x10
TP_STATUS_VLAN_TPID_VALID = 0x40
ETH_P_ALL = 0x0003


class L2Port:
    """Open an interface for capture and/or sending."""

    def __init__(self, iface):
        self.iface = iface
        self.sock = None
        self.handle = None
        if IS_LINUX:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            self.sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            self.sock.bind((iface, 0))
            self.sock.settimeout(0.2)
        else:
            lib = load_pcap()
            if not lib:
                raise RuntimeError("Npcap is not installed. Install it from https://npcap.com "
                                   "(tick 'Support raw 802.11 traffic' is not needed).")
            err = ctypes.create_string_buffer(256)
            self.handle = lib.pcap_open_live(iface.encode(), 65535, 1, 100, err)
            if not self.handle:
                raise RuntimeError(err.value.decode(errors="replace"))
        self.lock = threading.Lock()

    def recv(self):
        """Return (ts, frame) or None on timeout."""
        if self.sock:
            try:
                data, anc, _, addr = self.sock.recvmsg(65535, socket.CMSG_SPACE(32))
            except socket.timeout:
                return None
            if addr[2] == 4 and self.iface == "lo":      # PACKET_OUTGOING: loopback shows frames twice
                return None
            for lvl, typ, cdata in anc:
                if lvl == SOL_PACKET and typ == PACKET_AUXDATA and len(cdata) >= 20:
                    status, _, _, _, _, tci, tpid = struct.unpack("IIIHHHH", cdata[:20])
                    if status & TP_STATUS_VLAN_VALID:
                        if not status & TP_STATUS_VLAN_TPID_VALID:
                            tpid = 0x8100
                        data = data[:12] + struct.pack(">HH", tpid, tci) + data[12:]
            return time.time(), data
        lib = _pcap
        hdr = ctypes.POINTER(_pkthdr)()
        pkt = ctypes.POINTER(ctypes.c_ubyte)()
        r = lib.pcap_next_ex(self.handle, ctypes.byref(hdr), ctypes.byref(pkt))
        if r == 1:
            h = hdr.contents
            return h.ts.tv_sec + h.ts.tv_usec / 1e6, ctypes.string_at(pkt, h.caplen)
        if r == 0:
            return None
        raise RuntimeError(lib.pcap_geterr(self.handle).decode(errors="replace"))

    def send(self, frame):
        with self.lock:
            if self.sock:
                self.sock.send(frame)
            else:
                if _pcap.pcap_sendpacket(self.handle, frame, len(frame)) != 0:
                    raise RuntimeError(_pcap.pcap_geterr(self.handle).decode(errors="replace"))

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.handle:
            _pcap.pcap_close(self.handle)
            self.handle = None


class LiveCapture:
    ETHERTYPES = (0x88B8, 0x88BA)

    def __init__(self, iface, on_frame, keep_frames=True, max_frames=200000):
        self.iface, self.on_frame = iface, on_frame
        self.port = L2Port(iface)
        self.running = False
        self.frames = [] if keep_frames else None
        self.max_frames = max_frames
        self.error = None
        self.thread = None
        self.started = None

    def _is_relevant(self, f):
        off = 12
        et = (f[off] << 8) | f[off + 1]
        while et in (0x8100, 0x88A8, 0x9100) and len(f) >= off + 6:
            off += 4
            et = (f[off] << 8) | f[off + 1]
        return et in self.ETHERTYPES

    def start(self):
        self.running = True
        self.started = time.time()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while self.running:
                r = self.port.recv()
                if not r:
                    continue
                ts, frame = r
                if len(frame) < 14 or not self._is_relevant(frame):
                    continue
                if self.frames is not None and len(self.frames) < self.max_frames:
                    self.frames.append((ts, frame))
                self.on_frame(ts, frame)
        except Exception as e:
            self.error = str(e)
            self.running = False

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        self.port.close()


# ---------------------------------------------------------------------------
# pcap / pcapng files
# ---------------------------------------------------------------------------

def _sll_to_eth(pkt):
    if len(pkt) < 16:
        return None
    proto = pkt[14:16]
    addr = pkt[6:12]
    return b"\xFF" * 6 + addr + proto + pkt[16:]


def read_capture_file(data):
    """Yield (ts, ethernet_frame). Supports pcap (us/ns) and pcapng."""
    if len(data) < 24:
        raise ValueError("file too short")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        ns = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        e = "<" if le else ">"
        linktype = struct.unpack(e + "I", data[20:24])[0]
        i = 24
        while i + 16 <= len(data):
            sec, frac, incl, _ = struct.unpack(e + "IIII", data[i:i + 16])
            pkt = data[i + 16:i + 16 + incl]
            i += 16 + incl
            ts = sec + frac / (1e9 if ns else 1e6)
            if linktype == 1:
                yield ts, pkt
            elif linktype == 113:
                f = _sll_to_eth(pkt)
                if f:
                    yield ts, f
        return
    if magic == b"\x0a\x0d\x0d\x0a":
        i, e = 0, "<"
        ifaces = []
        while i + 12 <= len(data):
            btype = struct.unpack(e + "I", data[i:i + 4])[0]
            if btype == 0x0A0D0D0A:
                bom = data[i + 8:i + 12]
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                ifaces = []
            blen = struct.unpack(e + "I", data[i + 4:i + 8])[0]
            body = data[i + 8:i + blen - 4]
            if blen < 12:
                break
            if btype == 1:
                lt = struct.unpack(e + "H", body[:2])[0]
                tsres = 1e6
                j = 8
                while j + 4 <= len(body):
                    code, ln = struct.unpack(e + "HH", body[j:j + 4])
                    if code == 0:
                        break
                    if code == 9 and ln >= 1:
                        v = body[j + 4]
                        tsres = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                    j += 4 + ((ln + 3) & ~3)
                ifaces.append((lt, tsres))
            elif btype == 6:
                ifid, th, tl, cap, _ = struct.unpack(e + "IIIII", body[:20])
                pkt = body[20:20 + cap]
                lt, tsres = ifaces[ifid] if ifid < len(ifaces) else (1, 1e6)
                ts = ((th << 32) | tl) / tsres
                if lt == 1:
                    yield ts, pkt
                elif lt == 113:
                    f = _sll_to_eth(pkt)
                    if f:
                        yield ts, f
            elif btype == 3:
                orig = struct.unpack(e + "I", body[:4])[0]
                lt = ifaces[0][0] if ifaces else 1
                if lt == 1:
                    yield 0.0, body[4:4 + orig]
            i += blen
        return
    raise ValueError("not a pcap or pcapng file")


def write_pcap(frames):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, f in frames:
        s = int(ts)
        out.append(struct.pack("<IIII", s, int((ts - s) * 1e6), len(f), len(f)) + f)
    return b"".join(out)
