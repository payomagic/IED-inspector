"""Simulate one or more IEDs from an SCL file: read-only MMS server + GOOSE and SV publishers."""
import math
import threading
import time

from .ber import BitString
from .capture import L2Port, interface_mac
from .frames import encode_goose, encode_sv, parse_ethernet, parse_goose, parse_sv, ETH_GOOSE, ETH_SV
from .inspect_device import norm_cb_ref, SUPV_RE
from .mms_server import MmsServer
from .sim_model import IedModel, Leaf, Struct

_ports = {}
_ports_lock = threading.Lock()


def get_port(iface):
    with _ports_lock:
        p = _ports.get(iface)
        if p is None:
            p = _ports[iface] = L2Port(iface)
        return p


class GoosePublisher:
    def __init__(self, dev, cb):
        self.dev, self.cb = dev, cb
        self.st, self.sq = 1, 0
        self.enabled = True
        self.vlan_override = None
        self.next_interval = (cb.get("minTime") or 4) / 1000.0
        self.change = threading.Event()
        self.sent = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def members(self):
        ld, item = self.cb["datSet"].split("/", 1) if self.cb.get("datSet") else (None, None)
        return self.dev.model.datasets.get((ld, item), [])

    def frame(self, tal_ms):
        cb = self.cb
        data = []
        for d, it in self.members():
            node = self.dev.model.lookup(d, it)
            data.append(node.encode() if node else Leaf("vis", 1, "?").encode())
        vlan = self.vlan_override if self.vlan_override is not None else cb.get("vlanId")
        return encode_goose(cb.get("mac") or "01-0C-CD-01-00-00", self.dev.src_mac,
                            vlan if vlan is not None else None, cb.get("vlanPriority") or 4,
                            cb.get("appId") or 0, cb["ref"], tal_ms, cb.get("datSet") or "",
                            cb.get("id") or cb["ref"], time.time(), self.st, self.sq,
                            self.dev.test_flag, cb.get("confRev") or 1, False, data,
                            simulation=self.dev.simulation_bit)

    def trigger(self):
        self.st += 1
        self.sq = 0
        self.next_interval = (self.cb.get("minTime") or 4) / 1000.0
        self.change.set()

    def _run(self):
        max_i = (self.cb.get("maxTime") or 1000) / 1000.0
        while self.dev.running:
            if self.enabled:
                interval = self.next_interval
                wait = min(interval * 2, max_i)
                tal = int(max(wait * 2, 0.01) * 1000)
                try:
                    self.dev.port.send(self.frame(tal))
                    self.sent += 1
                except Exception as e:
                    self.dev.error = f"GOOSE send failed: {e}"
                self.sq = (self.sq + 1) & 0xFFFFFFFF
                self.next_interval = wait
            fired = self.change.wait(self.next_interval if self.enabled else 0.5)
            if fired:
                self.change.clear()


class SvPublisher:
    def __init__(self, dev, cb, freq=50.0, rate_limit=None):
        self.dev, self.cb = dev, cb
        self.enabled = True
        self.freq = freq
        self.smp_per_period = cb.get("smpRate") or 80
        self.rate = rate_limit or int(self.smp_per_period * freq)
        self.sent = 0
        self.amplitude_i = 100.0       # A (scaled x1000 → mA)
        self.amplitude_u = 66000.0     # V (scaled x100 → 10 mV)
        self.channels = self._channels()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _channels(self):
        ld, item = self.cb["datSet"].split("/", 1) if self.cb.get("datSet") else (None, None)
        members = self.dev.model.datasets.get((ld, item), [])
        chans = [it for _, it in members if not it.endswith("$q")]
        return chans or ["I1", "I2", "I3", "In", "U1", "U2", "U3", "Un"]

    def _run(self):
        n = len(self.channels)
        t0 = time.perf_counter()
        k = 0
        while self.dev.running:
            if not self.enabled:
                time.sleep(0.2)
                t0, k = time.perf_counter(), 0
                continue
            due = t0 + k / self.rate
            now = time.perf_counter()
            if due > now:
                time.sleep(min(due - now, 0.002))
                continue
            smp = k % (self.smp_per_period * int(self.freq))
            ph = 2 * math.pi * self.freq * (k / self.rate)
            vals = []
            for i, ch in enumerate(self.channels):
                is_u = "TVTR" in ch or "Vol" in ch or ch.startswith("U")
                pidx = i % 4
                if pidx == 3:
                    v = 0
                else:
                    a = self.amplitude_u * 100 if is_u else self.amplitude_i * 1000
                    v = int(a * math.sin(ph - pidx * 2 * math.pi / 3))
                vals.append((v, 0))
            cb = self.cb
            frame = encode_sv(cb.get("mac") or "01-0C-CD-04-00-00", self.dev.src_mac, cb.get("vlanId"),
                              cb.get("vlanPriority") or 4, cb.get("appId") or 0x4000, cb.get("id") or "SV",
                              smp, cb.get("confRev") or 1, vals)
            try:
                self.dev.port.send(frame)
                self.sent += 1
            except Exception as e:
                self.dev.error = f"SV send failed: {e}"
                time.sleep(0.5)
            k += 1


class Subscriber:
    """Emulates LGOS / LSVS: listens on the interface and updates St, SimSt, LastStNum, RxConfRevNum.
    accept_vlans emulates the switch-port VLAN membership of the subscriber (None = all VLANs)."""

    def __init__(self, dev):
        self.dev = dev
        self.entries = []          # dicts: ld, ln, kind, ref, last, tal
        self.accept_vlans = None
        self.dropped = 0
        self.port = None
        model = dev.model
        for ld, dom in model.domains.items():
            for ln_name, ln in dom.children:
                m = SUPV_RE.match(ln_name)
                if not m:
                    continue
                kind = "GOOSE" if m.group(1) == "LGOS" else "SV"
                ref = None
                for fc in ("SP", "CF"):
                    for key in ("GoCBRef", "SvCBRef"):
                        node = model.lookup(ld, f"{ln_name}${fc}${key}$setSrcRef")
                        if node is not None and node.value:
                            ref = norm_cb_ref(str(node.value), kind)
                if ref:
                    exp = None
                    pub = dev.scl.cb_by_ref().get(ref)
                    if pub:
                        exp = pub.get("confRev")
                        self._set(ld, ln_name, "ConfRevNum", exp)
                    self._set(ld, ln_name, "St", False)
                    self.entries.append({"ld": ld, "ln": ln_name, "kind": kind, "ref": ref, "last": 0.0, "tal": 2.0,
                                         "svid": pub.get("id") if pub else None, "received": 0})
        # ABB 615/620 style device-level diagnostics (LD?/GSEGGIO1) for all subscriptions from the SCD
        from .vendor_supervision import ABB615_LN
        self.gse = None
        self.gse_refs = {}
        self.counters = {i: 0 for i in range(1, 11)}
        for ld, dom in model.domains.items():
            for ln_name, _ in dom.children:
                if ABB615_LN.match(ln_name):
                    self.gse = (ld, ln_name)
        if self.gse:
            ied = dev.scl.ieds[dev.name]
            for e in ied["extrefs"]:
                ref = e.get("_publisherCb")
                if ref and not ref.startswith("?") and "$GO$" in ref:
                    pub = dev.scl.cb_by_ref().get(ref) or {}
                    self.gse_refs[ref] = {"last": 0.0, "tal": 2.0, "st": None, "confRev": pub.get("confRev"), "active": False}
            self._set(*self.gse, "Alm", bool(self.gse_refs))
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _set(self, ld, ln, do, value):
        node = self.dev.model.lookup(ld, f"{ln}$ST${do}$stVal")
        if isinstance(node, Leaf) and value is not None:
            node.value = value
            parent = self.dev.model.lookup(ld, f"{ln}$ST${do}")
            t = parent.get("t") if isinstance(parent, Struct) else None
            if isinstance(t, Leaf) and t.mtype == "utc":
                from .ber import UtcTime
                t.value = UtcTime(time.time())

    def start(self, iface):
        if not self.entries and not self.gse_refs:
            return
        self.port = L2Port(iface)
        self.thread.start()
        threading.Thread(target=self._supervise, daemon=True).start()

    def _run(self):
        by_ref = {e["ref"]: e for e in self.entries if e["kind"] == "GOOSE"}
        by_svid = {e["svid"]: e for e in self.entries if e["kind"] == "SV" and e["svid"]}
        while self.dev.running:
            try:
                r = self.port.recv()
            except Exception:
                break
            if not r:
                continue
            ts, frame = r
            eth = parse_ethernet(frame)
            if not eth or eth["ethertype"] not in (ETH_GOOSE, ETH_SV):
                continue
            vid = eth["vlan_id"] if eth["tagged"] else 0
            try:
                if eth["ethertype"] == ETH_GOOSE:
                    g = parse_goose(eth["payload"])
                    ref = norm_cb_ref(g.get("gocbRef", ""))
                    ge = self.gse_refs.get(ref)
                    if ge is not None:
                        if self.accept_vlans is not None and vid not in self.accept_vlans:
                            self.dropped += 1
                        else:
                            c = self.counters
                            c[1] += 1
                            if g.get("test"):
                                c[5] += 1
                            if ge["confRev"] is not None and g.get("confRev") != ge["confRev"]:
                                c[8] += 1
                            elif g.get("ndsCom"):
                                c[9] += 1
                            else:
                                if ge["st"] is not None and g.get("stNum") != ge["st"]:
                                    c[3] += 1
                                else:
                                    c[4] += 1
                                ge["st"] = g.get("stNum")
                                ge["last"], ge["tal"] = time.time(), (g.get("tal") or 2000) / 1000.0
                    e = by_ref.get(ref)
                    if not e:
                        continue
                    if self.accept_vlans is not None and vid not in self.accept_vlans:
                        self.dropped += 1
                        continue
                    e["last"], e["tal"] = time.time(), (g.get("tal") or 2000) / 1000.0
                    e["received"] += 1
                    self._set(e["ld"], e["ln"], "LastStNum", g.get("stNum"))
                    self._set(e["ld"], e["ln"], "RxConfRevNum", g.get("confRev"))
                    self._set(e["ld"], e["ln"], "SimSt", bool(g.get("simulationReserved")))
                else:
                    sv = parse_sv(eth["payload"])
                    for a in sv["asdus"]:
                        e = by_svid.get(a.get("svID"))
                        if not e:
                            continue
                        if self.accept_vlans is not None and vid not in self.accept_vlans:
                            self.dropped += 1
                            continue
                        e["last"], e["tal"] = time.time(), 0.5
                        e["received"] += 1
                        self._set(e["ld"], e["ln"], "RxConfRevNum", a.get("confRev"))
            except Exception:
                continue

    def _supervise(self):
        while self.dev.running:
            now = time.time()
            for e in self.entries:
                self._set(e["ld"], e["ln"], "St", (now - e["last"]) <= e["tal"])
            if self.gse:
                for ge in self.gse_refs.values():
                    active = (now - ge["last"]) <= ge["tal"]
                    if ge["active"] and not active:
                        self.counters[7] += 1
                    ge["active"] = active
                self._set(*self.gse, "Alm", not all(ge["active"] for ge in self.gse_refs.values()))
                for i, v in self.counters.items():
                    self._set(*self.gse, f"IntIn{i}", v)
                self._set(*self.gse, "IntIn2", sum(p.sent for p in self.dev.goose))
            time.sleep(0.2)
        if self.port:
            self.port.close()

    def status(self):
        now = time.time()
        return {"acceptVlans": None if self.accept_vlans is None else sorted(self.accept_vlans), "dropped": self.dropped,
                "entries": [{"ln": f"{e['ld']}/{e['ln']}", "ref": e["ref"], "kind": e["kind"], "received": e["received"],
                             "active": (now - e["last"]) <= e["tal"]} for e in self.entries]
                + [{"ln": f"{self.gse[0]}/{self.gse[1]} (device level)", "ref": r, "kind": "GOOSE",
                    "received": None, "active": (now - g["last"]) <= g["tal"]} for r, g in self.gse_refs.items()]}


class SimDevice:
    def __init__(self, scl, ied_name, ip, port=102, iface=None, mms=True, goose=True, sv=True, sv_rate=None):
        self.scl, self.name, self.ip, self.mms_port, self.iface = scl, ied_name, ip, port, iface
        self.model = IedModel(scl, ied_name)
        self.server = None
        self.port = None
        self.running = False
        self.test_flag = False
        self.simulation_bit = False
        self.error = None
        self.src_mac = interface_mac(iface) if iface else "00-1A-2B-3C-4D-5E"
        self.goose = []
        self.sv = []
        self.opts = {"mms": mms, "goose": goose, "sv": sv, "sv_rate": sv_rate}
        self.subscriber = Subscriber(self)
        self.started = None

    def start(self):
        self.running = True
        self.started = time.time()
        ied = self.scl.ieds[self.name]
        if self.opts["mms"]:
            self.server = MmsServer(self.model, self.ip, self.mms_port, vendor=ied.get("manufacturer") or "IED Inspector",
                                    model_name=f"Simulated {ied.get('type') or self.name}", revision="sim")
            try:
                self.server.start()
            except OSError as e:
                self.running = False
                raise RuntimeError(f"cannot listen on {self.ip}:{self.mms_port} – {e}. "
                                   "Use an IP address that exists on this computer (e.g. 127.0.0.x, "
                                   "or add a secondary IP to the network adapter).")
        if self.iface:
            try:
                self.subscriber.start(self.iface)
            except Exception as e:
                self.error = f"subscriber emulation not available: {e}"
        if self.iface and (self.opts["goose"] or self.opts["sv"]):
            self.port = get_port(self.iface)
            if self.opts["goose"]:
                for cb in ied["gocbs"]:
                    p = GoosePublisher(self, cb)
                    self.goose.append(p)
                    p.thread.start()
            if self.opts["sv"]:
                for cb in ied["svcbs"]:
                    p = SvPublisher(self, cb, rate_limit=self.opts["sv_rate"])
                    self.sv.append(p)
                    p.thread.start()

    def stop(self):
        self.running = False
        for p in self.goose:
            p.change.set()
        if self.server:
            self.server.stop()

    def set_value(self, ref, value):
        """ref = 'LD/LN$FC$DO$DA'. Updates the value and fires GOOSE for affected datasets."""
        ld, item = ref.split("/", 1)
        node = self.model.lookup(ld, item.replace(".", "$"))
        if not isinstance(node, Leaf):
            raise ValueError("only basic attributes can be changed")
        t = node.mtype
        if t == "bool":
            node.value = str(value).lower() in ("1", "true", "on", "yes")
        elif t in ("int", "uint"):
            sv = str(value).strip()
            if node.enum and not sv.lstrip("-").isdigit():
                match = [k for k, txt in node.enum.items() if txt == sv]
                if not match:
                    raise ValueError(f"unknown enum value '{sv}'")
                node.value = match[0]
            else:
                node.value = int(sv)
        elif t == "float":
            node.value = float(value)
        elif t == "bits":
            from .sim_model import parse_bits
            node.value = parse_bits(node.btype, value, node.size)
        else:
            node.value = str(value)
        # update timestamp sibling 't' if present
        parent = self.model.lookup(ld, "$".join(item.split("$")[:-1]))
        if isinstance(parent, Struct):
            tn = parent.get("t")
            if isinstance(tn, Leaf) and tn.mtype == "utc":
                from .ber import UtcTime
                tn.value = UtcTime(time.time())
        hit = 0
        for p in self.goose:
            for d, it in p.members():
                if d == ld and (item == it or item.startswith(it + "$")):
                    p.trigger()
                    hit += 1
                    break
        return hit

    def signals(self):
        out = []
        for p in self.goose:
            for d, it in p.members():
                node = self.model.lookup(d, it)
                if node is None:
                    continue
                for path, leaf in self.model.leaves(node, it):
                    out.append({"ref": f"{d}/{path}", "cb": p.cb["ref"], "type": leaf.btype or leaf.mtype,
                                "mtype": leaf.mtype, "value": leaf.display()})
        return out

    def status(self):
        return {
            "name": self.name, "ip": self.ip, "port": self.mms_port, "iface": self.iface,
            "running": self.running, "error": self.error, "test": self.test_flag,
            "simulation": self.simulation_bit, "srcMac": self.src_mac,
            "clients": list(self.server.clients) if self.server else [],
            "requests": self.server.requests if self.server else 0,
            "mms": bool(self.server),
            "goose": [{"ref": p.cb["ref"], "enabled": p.enabled, "stNum": p.st, "sqNum": p.sq, "sent": p.sent,
                       "vlan": p.vlan_override if p.vlan_override is not None else p.cb.get("vlanId"),
                       "vlanOverridden": p.vlan_override is not None, "appId": p.cb.get("appId")} for p in self.goose],
            "subscriber": self.subscriber.status(),
            "sv": [{"ref": p.cb["ref"], "enabled": p.enabled, "sent": p.sent, "rate": p.rate,
                    "vlan": p.cb.get("vlanId"), "channels": len(p.channels)} for p in self.sv],
        }


class Simulator:
    def __init__(self):
        self.devices = {}
        self.lock = threading.Lock()

    def start(self, scl, ied_name, ip, port=102, iface=None, mms=True, goose=True, sv=True, sv_rate=None):
        with self.lock:
            key = f"{ied_name}@{ip}:{port}"
            if key in self.devices:
                raise RuntimeError(f"{ied_name} is already simulated on {ip}:{port}")
            dev = SimDevice(scl, ied_name, ip, port, iface, mms, goose, sv, sv_rate)
            dev.start()
            self.devices[key] = dev
            return key

    def stop(self, key):
        with self.lock:
            dev = self.devices.pop(key, None)
        if dev:
            dev.stop()

    def stop_all(self):
        for k in list(self.devices):
            self.stop(k)

    def get(self, key):
        d = self.devices.get(key)
        if not d:
            raise KeyError(f"no simulated device {key}")
        return d

    def status(self):
        return {k: d.status() for k, d in self.devices.items()}
