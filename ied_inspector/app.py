"""Local web server + JSON API. Runs on 127.0.0.1 by default and opens the browser."""
import argparse
import concurrent.futures
import json
import os
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from . import reports
from .analysis import analyze
from .capture import LiveCapture, list_interfaces, pcap_status, read_capture_file, write_pcap, IS_WIN, IS_LINUX
from .inspect_device import inspect, probe
from .scl import SclModel
from .simulator import Simulator
from .streams import StreamTracker

# PyInstaller one-file builds unpack data files to sys._MEIPASS
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(BASE_DIR, "ied_inspector", "web")
EXAMPLES_DIR = os.path.join(BASE_DIR, "examples")
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".ied_inspector.json")


class Session:
    def __init__(self):
        self.started = time.time()
        self.lock = threading.RLock()
        self.scl = None
        self.scl_name = None
        self.connections = []
        self.live = None           # (LiveCapture, StreamTracker)
        self.past_live = []        # finished live trackers
        self.pcaps = {}            # id -> (name, tracker)
        self.probes = {}           # ip -> {reachable, identity, ts}
        self.sim = Simulator()
        self.log = []
        self.scd_history = []
        self.sim_history = []
        self.settings = {"backend": "builtin", "libPath": "", "timeout": 5.0, "autoProbe": True, "probeInterval": 30}
        self._load_settings()
        self.pcap_seq = 0

    def _load_settings(self):
        try:
            with open(CONFIG_PATH) as f:
                self.settings.update(json.load(f))
        except (OSError, ValueError):
            pass

    def save_settings(self):
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump(self.settings, f, indent=2)
        except OSError:
            pass

    def event(self, text):
        with self.lock:
            self.log.append({"ts": time.time(), "text": text})
            self.log = self.log[-2000:]

    def trackers(self):
        t = [tr for _, tr in self.past_live] + [tr for _, tr in self.pcaps.values()]
        if self.live:
            t.append(self.live[1])
        return t

    def analysis(self):
        return analyze(self.scl, self.connections, self.trackers(), self.probes)


S = Session()


def probe_scd_ieds():
    if not S.scl:
        return {}
    ips = [i["ip"] for i in S.scl.ieds.values() if i.get("ip")]
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(probe, ip, 102, 2.0, S.settings["backend"], S.settings.get("libPath") or None): ip for ip in ips}
        for f in concurrent.futures.as_completed(futs):
            ip = futs[f]
            r = f.result()
            r["ts"] = time.time()
            out[ip] = r
    with S.lock:
        S.probes.update(out)
    return out


def _probe_loop():
    while True:
        time.sleep(max(10, int(S.settings.get("probeInterval", 30))))
        if S.scl and S.settings.get("autoProbe"):
            try:
                probe_scd_ieds()
            except Exception:
                pass


# --------------------------------------------------------------------------- API
class Api:
    @staticmethod
    def state(q, body):
        a = S.analysis()
        live = None
        if S.live:
            cap, tr = S.live
            live = {"iface": cap.iface, "running": cap.running, "error": cap.error, "started": cap.started,
                    "frames": tr.frames}
        return {
            "version": __version__, "platform": sys.platform, "session": {"started": S.started},
            "scd": S.scl.summary() if S.scl else None,
            "connections": [{k: c.get(k) for k in ("id", "ip", "port", "ok", "error", "identity", "started",
                                                    "duration_ms", "backend")} | {"gocbs": len(c.get("gocbs", [])),
                                                                                  "svcbs": len(c.get("svcbs", []))}
                            for c in S.connections],
            "probes": S.probes, "live": live,
            "pcaps": [{"id": k, "name": n, "frames": t.frames} for k, (n, t) in S.pcaps.items()],
            "pastCaptures": [{"id": i, "source": t.source, "frames": t.frames} for i, (_, t) in enumerate(S.past_live)],
            "sim": S.sim.status(), "settings": S.settings, "analysis": a,
            "log": S.log[-200:],
        }

    @staticmethod
    def interfaces(q, body):
        return {"interfaces": list_interfaces(), "pcap": pcap_status(), "isWindows": IS_WIN, "isLinux": IS_LINUX}

    @staticmethod
    def connect(q, body):
        ip = (body.get("ip") or "").strip()
        if not ip:
            raise ValueError("enter an IP address")
        port = int(body.get("port") or 102)
        backend = body.get("backend") or S.settings["backend"]
        rec = inspect(ip, port, float(body.get("timeout") or S.settings["timeout"]), backend,
                      body.get("localIp") or None, S.settings.get("libPath") or None)
        with S.lock:
            rec["id"] = len(S.connections) + 1
            S.connections.append(rec)
            S.probes[ip] = {"reachable": rec["ok"], "identity": rec.get("identity"), "ts": time.time(),
                            "hostUp": True if rec["ok"] else rec.get("hostUp"), "hostCheck": rec.get("hostCheck")}
        S.event(f"MMS {ip}:{port} – " + (f"connected, {len(rec['gocbs'])} GOOSE / {len(rec['svcbs'])} SV control blocks read"
                                          if rec["ok"] else f"failed: {rec['error']}"))
        return rec

    @staticmethod
    def connect_all(q, body):
        if not S.scl:
            raise ValueError("load an SCD file first")
        ips = [i["ip"] for i in S.scl.ieds.values() if i.get("ip")]
        res = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for r in ex.map(lambda ip: Api.connect({}, {"ip": ip}), ips):
                res.append({"ip": r["ip"], "ok": r["ok"], "error": r["error"]})
        return {"results": res}

    @staticmethod
    def connection(q, body):
        cid = int(q.get("id", [0])[0])
        for c in S.connections:
            if c["id"] == cid:
                return c
        raise KeyError("connection not found")

    @staticmethod
    def probe_all(q, body):
        return {"probes": probe_scd_ieds()}

    @staticmethod
    def scd_load(q, body, raw=None):
        name = q.get("name", ["model.scd"])[0]
        m = SclModel.load(raw, name)
        with S.lock:
            S.scl, S.scl_name = m, name
        v = m.validate()
        S.scd_history.append({"ts": time.time(), "file": name, "ieds": len(m.ieds),
                              "errors": sum(1 for f in v if f["severity"] == "error"),
                              "warnings": sum(1 for f in v if f["severity"] == "warning")})
        S.event(f"SCD loaded: {name} ({len(m.ieds)} IEDs, {len(v)} validation findings)")
        if S.settings.get("autoProbe"):
            threading.Thread(target=probe_scd_ieds, daemon=True).start()
        return {"summary": m.summary(), "validation": v}

    @staticmethod
    def scd_demo(q, body):
        with open(os.path.join(EXAMPLES_DIR, "demo_substation.scd"), "rb") as f:
            return Api.scd_load({"name": ["demo_substation.scd"]}, {}, f.read())

    @staticmethod
    def scd_unload(q, body):
        S.scl = None
        S.event("SCD unloaded")
        return {}

    @staticmethod
    def scd_ied(q, body):
        if not S.scl:
            raise ValueError("no SCD loaded")
        name = q.get("name", [""])[0]
        ied = S.scl.ieds[name]
        return {"name": name, "ip": ied["ip"], "gocbs": ied["gocbs"], "svcbs": ied["svcbs"],
                "datasets": list(ied["datasets"].values()),
                "extrefs": [{k: v for k, v in e.items()} for e in ied["extrefs"]]}

    @staticmethod
    def capture_start(q, body):
        iface = body.get("iface")
        if not iface:
            raise ValueError("choose a network interface")
        Api.capture_stop({}, {})
        tr = StreamTracker(f"live:{body.get('label') or iface}")
        cap = LiveCapture(iface, tr.feed)
        cap.start()
        S.live = (cap, tr)
        S.event(f"capture started on {body.get('label') or iface}")
        return {"ok": True}

    @staticmethod
    def capture_stop(q, body):
        if S.live:
            cap, tr = S.live
            cap.stop()
            S.past_live.append((cap, tr))
            S.live = None
            S.event(f"capture stopped ({tr.frames} GOOSE/SV frames)")
        return {"ok": True}

    @staticmethod
    def captures(q, body):
        out = []
        if S.live:
            out.append({"id": "live", **S.live[1].snapshot(time.time())})
        for i, (_, t) in enumerate(S.past_live):
            out.append({"id": f"past{i}", **t.snapshot()})
        for k, (n, t) in S.pcaps.items():
            out.append({"id": k, **t.snapshot()})
        return {"captures": out}

    @staticmethod
    def capture_clear(q, body):
        cid = body.get("id")
        if cid == "all":
            S.past_live.clear()
            S.pcaps.clear()
        elif cid and cid.startswith("past"):
            idx = int(cid[4:])
            if idx < len(S.past_live):
                S.past_live.pop(idx)
        elif cid in S.pcaps:
            S.pcaps.pop(cid)
        return {}

    @staticmethod
    def pcap_load(q, body, raw=None):
        name = q.get("name", ["capture.pcap"])[0]
        tr = StreamTracker(f"pcap:{name}", live=False)
        n = 0
        for t, f in read_capture_file(raw):
            tr.feed(t, f)
            n += 1
        S.pcap_seq += 1
        S.pcaps[f"pcap{S.pcap_seq}"] = (name, tr)
        S.event(f"pcap analysed: {name} ({n} frames, {tr.frames} GOOSE/SV)")
        return tr.snapshot()

    @staticmethod
    def sim_start(q, body):
        if not S.scl:
            raise ValueError("load an SCD file first")
        key = S.sim.start(S.scl, body["ied"], body.get("ip") or "127.0.0.1", int(body.get("port") or 102),
                          body.get("iface") or None, body.get("mms", True), body.get("goose", True), body.get("sv", True),
                          int(body["svRate"]) if body.get("svRate") else None)
        S.sim_history.append({"ts": time.time(), "text": f"started {key} (iface {body.get('iface') or 'none'})"})
        S.event(f"simulator: started {key}")
        return {"key": key}

    @staticmethod
    def sim_stop(q, body):
        if body.get("key") == "all":
            S.sim.stop_all()
        else:
            S.sim.stop(body["key"])
        S.sim_history.append({"ts": time.time(), "text": f"stopped {body.get('key')}"})
        S.event(f"simulator: stopped {body.get('key')}")
        return {}

    @staticmethod
    def sim_signals(q, body):
        return {"signals": S.sim.get(q["key"][0]).signals()}

    @staticmethod
    def sim_value(q, body):
        dev = S.sim.get(body["key"])
        hits = dev.set_value(body["ref"], body["value"])
        S.sim_history.append({"ts": time.time(), "text": f"{body['key']}: {body['ref']} = {body['value']}"})
        return {"goosesTriggered": hits}

    @staticmethod
    def sim_flags(q, body):
        dev = S.sim.get(body["key"])
        if "test" in body:
            dev.test_flag = bool(body["test"])
        if "simulation" in body:
            dev.simulation_bit = bool(body["simulation"])
        for p in dev.goose:
            p.trigger()
        S.sim_history.append({"ts": time.time(), "text": f"{body['key']}: test={dev.test_flag} simulation={dev.simulation_bit}"})
        return {}

    @staticmethod
    def sim_cb(q, body):
        dev = S.sim.get(body["key"])
        for p in dev.goose + dev.sv:
            if p.cb["ref"] == body["ref"]:
                if "enabled" in body:
                    p.enabled = bool(body["enabled"])
                if "vlan" in body and hasattr(p, "vlan_override"):
                    v = body["vlan"]
                    p.vlan_override = None if v in (None, "") else int(v)
                    p.trigger()
                S.sim_history.append({"ts": time.time(), "text": f"{body['key']}: {body['ref']} {json.dumps({k: body[k] for k in body if k in ('enabled', 'vlan')})}"})
                return {}
        raise KeyError("control block not found")

    @staticmethod
    def sim_port_vlans(q, body):
        dev = S.sim.get(body["key"])
        txt = str(body.get("vlans") or "").strip()
        if not txt or txt.lower() == "all":
            dev.subscriber.accept_vlans = None
        else:
            dev.subscriber.accept_vlans = {int(x) for x in txt.replace(";", ",").replace(" ", ",").split(",") if x.strip()}
        S.sim_history.append({"ts": time.time(), "text": f"{body['key']}: subscriber accepts VLANs {txt or 'all'}"})
        return {}

    @staticmethod
    def settings(q, body):
        if body:
            for k in ("backend", "libPath", "timeout", "autoProbe", "probeInterval"):
                if k in body:
                    S.settings[k] = body[k]
            S.save_settings()
            S.event(f"settings saved (MMS backend: {S.settings['backend']})")
        return S.settings

    @staticmethod
    def test_lib(q, body):
        from .backend_libiec61850 import lib_version
        path = body.get("libPath") or S.settings.get("libPath") or None
        return {"ok": True, "version": lib_version(path)}


GET_ROUTES = {"/api/state": Api.state, "/api/interfaces": Api.interfaces, "/api/connection": Api.connection,
              "/api/captures": Api.captures, "/api/sim/signals": Api.sim_signals, "/api/settings": Api.settings,
              "/api/scd/ied": Api.scd_ied}
POST_ROUTES = {"/api/connect": Api.connect, "/api/connect-all": Api.connect_all, "/api/probe": Api.probe_all,
               "/api/scd/unload": Api.scd_unload, "/api/scd/demo": Api.scd_demo, "/api/capture/start": Api.capture_start,
               "/api/capture/stop": Api.capture_stop, "/api/capture/clear": Api.capture_clear,
               "/api/sim/start": Api.sim_start, "/api/sim/stop": Api.sim_stop, "/api/sim/value": Api.sim_value,
               "/api/sim/flags": Api.sim_flags, "/api/sim/port-vlans": Api.sim_port_vlans, "/api/sim/cb": Api.sim_cb, "/api/settings": Api.settings,
               "/api/settings/test-lib": Api.test_lib}
RAW_ROUTES = {"/api/scd": Api.scd_load, "/api/pcap": Api.pcap_load}


class Handler(BaseHTTPRequestHandler):
    server_version = f"IEDInspector/{__version__}"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", filename=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, reports.to_json(obj))

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path in GET_ROUTES:
                return self._json(GET_ROUTES[u.path](q, {}))
            if u.path.startswith("/report/"):
                return self._report(u.path[8:], q)
            self._send(404, "not found", "text/plain")
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 400)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            if u.path in RAW_ROUTES:
                return self._json(RAW_ROUTES[u.path](q, {}, raw))
            if u.path in POST_ROUTES:
                body = json.loads(raw or b"{}")
                return self._json(POST_ROUTES[u.path](q, body))
            self._send(404, "not found", "text/plain")
        except Exception as e:
            traceback.print_exc()
            self._json({"error": f"{e}"}, 400)

    def _report(self, kind, q):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        fmt = q.get("format", ["html"])[0]
        if kind == "comparison":
            a = S.analysis()
            S.event(f"comparison report exported ({fmt})")
            if fmt == "csv":
                table = q.get("table", ["controlblocks"])[0]
                return self._send(200, reports.comparison_csv(a, table), "text/csv; charset=utf-8", f"comparison_{table}_{stamp}.csv")
            if fmt == "json":
                return self._send(200, reports.to_json(a), "application/json", f"comparison_{stamp}.json")
            return self._send(200, reports.comparison_html(a, S.scl_name if S.scl else None), "text/html; charset=utf-8", f"comparison_{stamp}.html")
        if kind == "connection":
            c = Api.connection(q, {})
            name = f"connection_{c['ip'].replace(':', '_')}_{stamp}"
            if fmt == "txt":
                return self._send(200, reports.connection_text(c), "text/plain; charset=utf-8", name + ".txt")
            if fmt == "json":
                return self._send(200, reports.to_json(c), "application/json", name + ".json")
            return self._send(200, reports.connection_html(c), "text/html; charset=utf-8", name + ".html")
        if kind == "datamodel":
            c = Api.connection(q, {})
            idt = c.get("identity") or {}
            lines = [f"# Data model of {c['ip']} – {idt.get('vendor', '')} {idt.get('model', '')} {idt.get('revision', '')}",
                     f"# read {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c.get('started') or 0))} by IED Inspector {__version__}", ""]
            for dom, names in (c.get("model") or {}).items():
                lines.append(f"[{dom}]")
                lines += [f"  {n}" for n in names]
                lines.append("")
            return self._send(200, "\n".join(lines), "text/plain; charset=utf-8", f"datamodel_{c['ip']}_{stamp}.txt")
        if kind == "summary":
            snaps = [t.snapshot(time.time()) for t in S.trackers()]
            sess = {"started": S.started, "connections": S.connections, "capture_snapshots": snaps,
                    "scd_history": S.scd_history, "sim_history": S.sim_history, "log": S.log}
            a = S.analysis()
            if fmt == "json":
                return self._send(200, reports.to_json({"session": sess, "analysis": a}), "application/json", f"session_summary_{stamp}.json")
            return self._send(200, reports.summary_html(sess, a, S.scl_name if S.scl else None), "text/html; charset=utf-8", f"session_summary_{stamp}.html")
        if kind == "pcap":
            if not S.live and not S.past_live:
                raise ValueError("no live capture in this session")
            cap = S.live[0] if S.live else S.past_live[-1][0]
            return self._send(200, write_pcap(list(cap.frames or [])), "application/vnd.tcpdump.pcap", f"capture_{stamp}.pcap")
        self._send(404, "unknown report", "text/plain")


def main(argv=None):
    ap = argparse.ArgumentParser(description="IED Inspector – read-only IEC 61850 MMS/GOOSE/SV inspection tool")
    ap.add_argument("--host", default="127.0.0.1", help="address for the web interface (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8061, help="port for the web interface (default 8061)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    ap.add_argument("--scd", help="load this SCD file at start")
    a = ap.parse_args(argv)

    if a.scd:
        with open(a.scd, "rb") as f:
            Api.scd_load({"name": [os.path.basename(a.scd)]}, {}, f.read())
    threading.Thread(target=_probe_loop, daemon=True).start()
    try:
        httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    except OSError as e:
        print(f"Cannot start the web interface on {a.host}:{a.port}: {e}")
        print("Is IED Inspector already running? Use --port to choose another port.")
        sys.exit(1)
    httpd.daemon_threads = True
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '') else a.host}:{a.port}/"
    print(f"IED Inspector {__version__} – open {url} in your browser.", flush=True)
    print("Keep this window open while you use the tool. Close it (or press Ctrl+C) to quit.", flush=True)
    if a.host not in ("127.0.0.1", "localhost"):
        print("WARNING: the web interface is reachable from the network. There is no login.")
    S.event("session started")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        S.sim.stop_all()
        if S.live:
            S.live[0].stop()
        httpd.server_close()
