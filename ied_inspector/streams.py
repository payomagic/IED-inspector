"""GOOSE / SV stream tracking: timeouts, test/simulation bits, sequence checks."""
import threading
import time

from .ber import to_jsonable, fmt_value
from .frames import parse_ethernet, parse_goose, parse_sv, ETH_GOOSE, ETH_SV

MAX_EVENTS = 300


class StreamTracker:
    def __init__(self, source, live=True):
        self.source = source          # e.g. "live:eth0" or "pcap:file.pcap"
        self.live = live
        self.goose = {}
        self.sv = {}
        self.events = []
        self.frames = 0
        self.first_ts = None
        self.last_ts = None
        self.untagged_goose = 0
        self.tagged_goose = 0
        self.lock = threading.Lock()

    def _event(self, ts, kind, severity, key, msg):
        self.events.append({"ts": ts, "kind": kind, "severity": severity, "stream": key, "message": msg})
        if len(self.events) > MAX_EVENTS:
            del self.events[:len(self.events) - MAX_EVENTS]

    def feed(self, ts, frame):
        eth = parse_ethernet(frame)
        if not eth or eth["ethertype"] not in (ETH_GOOSE, ETH_SV):
            return
        with self.lock:
            self.frames += 1
            self.first_ts = ts if self.first_ts is None else self.first_ts
            self.last_ts = ts
            try:
                if eth["ethertype"] == ETH_GOOSE:
                    self._goose(ts, eth, parse_goose(eth["payload"]))
                else:
                    self._sv(ts, eth, parse_sv(eth["payload"]))
            except Exception as e:
                self._event(ts, "decode", "warning", eth["src"], f"malformed frame: {e}")

    def _goose(self, ts, eth, g):
        key = f"{eth['src']}|{g.get('appId')}|{g.get('gocbRef')}"
        s = self.goose.get(key)
        if eth["tagged"]:
            self.tagged_goose += 1
        else:
            self.untagged_goose += 1
        if s is None:
            s = self.goose[key] = {
                "key": key, "src": eth["src"], "dst": eth["dst"], "gocbRef": g.get("gocbRef"),
                "first": ts, "count": 0, "stChanges": 0, "timeouts": 0, "seqErrors": 0,
                "vlanHistory": [], "testFrames": 0, "simFrames": 0, "maxGap": 0.0}
            self._event(ts, "new", "info", key, f"new GOOSE stream {g.get('gocbRef')} from {eth['src']}")
        else:
            gap = ts - s["last"]
            s["maxGap"] = max(s["maxGap"], gap)
            tal = s.get("tal") or 0
            if tal and gap * 1000 > tal:
                s["timeouts"] += 1
                self._event(ts, "timeout", "error", key,
                            f"{s['gocbRef']}: no frame for {gap * 1000:.0f} ms (TAL {tal} ms)")
            st, sq = g.get("stNum"), g.get("sqNum")
            if st is not None and s.get("stNum") is not None:
                if st != s["stNum"]:
                    s["stChanges"] += 1
                    s["lastChange"] = ts
                    if sq not in (0, None):
                        s["seqErrors"] += 1
                        self._event(ts, "sequence", "warning", key, f"{s['gocbRef']}: stNum changed but sqNum={sq} (expected 0)")
                    self._event(ts, "state", "info", key, f"{s['gocbRef']}: stNum {s['stNum']} → {st}")
                elif sq is not None and s.get("sqNum") is not None and sq != s["sqNum"] + 1 and not (sq == 0 and s["sqNum"] >= 0xFFFFFFFF):
                    s["seqErrors"] += 1
                    self._event(ts, "sequence", "warning", key, f"{s['gocbRef']}: sqNum {s['sqNum']} → {sq}")
        vid = eth["vlan_id"] if eth["tagged"] else None
        if not s["vlanHistory"] or s["vlanHistory"][-1] != vid:
            if s["vlanHistory"]:
                self._event(ts, "vlan", "warning", key, f"{s['gocbRef']}: VLAN changed {s['vlanHistory'][-1]} → {vid}")
            s["vlanHistory"].append(vid)
        if g.get("test"):
            s["testFrames"] += 1
            if not s.get("test"):
                self._event(ts, "test", "warning", key, f"{s['gocbRef']}: TEST flag is set")
        if g.get("simulationReserved"):
            s["simFrames"] += 1
            if not s.get("simulation"):
                self._event(ts, "simulation", "warning", key, f"{s['gocbRef']}: simulation bit is set")
        if g.get("ndsCom") and not s.get("ndsCom"):
            self._event(ts, "ndsCom", "warning", key, f"{s['gocbRef']}: needs commissioning (ndsCom) is set")
        data = g.get("data") or []
        s.update({
            "last": ts, "count": s["count"] + 1, "dst": eth["dst"], "tagged": eth["tagged"],
            "vlanId": vid, "vlanPriority": eth["vlan_prio"], "appId": g.get("appId"),
            "goID": g.get("goID"), "datSet": g.get("datSet"), "tal": g.get("tal"),
            "stNum": g.get("stNum"), "sqNum": g.get("sqNum"), "test": g.get("test", False),
            "simulation": g.get("simulationReserved", False), "confRev": g.get("confRev"),
            "ndsCom": g.get("ndsCom", False), "numEntries": g.get("numEntries"),
            "t": repr(g["t"]) if g.get("t") is not None else None,
            "values": [to_jsonable(v) for v in data], "valueText": [fmt_value(v) for v in data]})

    def _sv(self, ts, eth, sv):
        for a in sv["asdus"]:
            key = f"{eth['src']}|{sv['appId']}|{a.get('svID')}"
            s = self.sv.get(key)
            if s is None:
                s = self.sv[key] = {"key": key, "src": eth["src"], "svID": a.get("svID"), "first": ts,
                                    "count": 0, "smpErrors": 0, "rateWindow": [ts, 0]}
                self._event(ts, "new", "info", key, f"new SV stream {a.get('svID')} from {eth['src']}")
            prev = s.get("smpCnt")
            if prev is not None and a.get("smpCnt") is not None:
                exp = prev + 1
                if a["smpCnt"] != exp and a["smpCnt"] != 0:
                    s["smpErrors"] += 1
            w = s["rateWindow"]
            w[1] += 1
            if ts - w[0] >= 1.0:
                s["rate"] = round(w[1] / (ts - w[0]))
                s["rateWindow"] = [ts, 0]
            s.update({"last": ts, "count": s["count"] + 1, "dst": eth["dst"], "tagged": eth["tagged"],
                      "vlanId": eth["vlan_id"] if eth["tagged"] else None, "vlanPriority": eth["vlan_prio"],
                      "appId": sv["appId"], "smpCnt": a.get("smpCnt"), "confRev": a.get("confRev"),
                      "smpSynch": a.get("smpSynch"), "datSet": a.get("datSet"),
                      "simulation": sv["simulationReserved"],
                      "values": [v for v, _ in (a.get("values") or [])][:16]})

    def snapshot(self, now=None):
        with self.lock:
            ref = now if (now is not None and self.live) else (self.last_ts or time.time())
            gl = []
            for s in self.goose.values():
                d = dict(s)
                tal = (s.get("tal") or 0) / 1000.0
                d["age"] = round(ref - s["last"], 3)
                alive = tal == 0 or (ref - s["last"]) <= tal
                status = "ok" if alive else "timeout"
                warnings = []
                if s.get("test"):
                    warnings.append("TEST flag set")
                if s.get("simulation"):
                    warnings.append("simulation bit set")
                if s.get("ndsCom"):
                    warnings.append("needs commissioning")
                if s["timeouts"]:
                    warnings.append(f"{s['timeouts']} timeout(s) seen")
                if len(set(s["vlanHistory"])) > 1:
                    warnings.append("VLAN changed during capture")
                d["status"] = status
                d["warnings"] = warnings
                d.pop("rateWindow", None)
                gl.append(d)
            svl = []
            for s in self.sv.values():
                d = dict(s)
                d.pop("rateWindow", None)
                d["age"] = round(ref - s["last"], 3)
                d["status"] = "ok" if ref - s["last"] < 1.0 else "timeout"
                d["warnings"] = (["simulation bit set"] if s.get("simulation") else []) + \
                                ([f"{s['smpErrors']} smpCnt gaps"] if s["smpErrors"] else [])
                svl.append(d)
            hint = None
            if self.untagged_goose and not self.tagged_goose:
                hint = ("All GOOSE frames arrive without a VLAN tag. Either the IEDs publish untagged/"
                        "priority-tagged frames, the switch port strips the tag (access port), or the "
                        "network adapter driver removes it (common on Windows: disable 'Priority & VLAN' "
                        "offload / set 'Packet Priority & VLAN' to disabled in the adapter's advanced settings).")
            return {"source": self.source, "live": self.live, "frames": self.frames,
                    "first": self.first_ts, "last": self.last_ts, "goose": gl, "sv": svl,
                    "events": list(self.events[-MAX_EVENTS:]), "vlanHint": hint}
