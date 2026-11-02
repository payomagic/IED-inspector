"""Read GOOSE / SV control blocks and their datasets from one IED via MMS."""
import re
import time

from .ber import name_values, to_jsonable, fmt_value, FailedAccess
from .iso import MmsError

GOCB_RE = re.compile(r"^LLN0\$GO\$[^$]+$")
SVCB_RE = re.compile(r"^LLN0\$(MS|US)\$[^$]+$")
SUPV_RE = re.compile(r"^[A-Za-z0-9_]*?(LGOS|LSVS)\d*$")


def _dig(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def norm_cb_ref(ref, kind="GOOSE"):
    """Normalise a control block reference: 'LD/LLN0.GCB' or 'LD/LLN0$GO$GCB' -> 'LD/LLN0$GO$GCB'."""
    if not ref or "/" not in ref:
        return ref
    ld, rest = ref.split("/", 1)
    parts = rest.replace(".", "$").split("$")
    fc = "GO" if kind == "GOOSE" else "MS"
    if len(parts) == 2:
        parts = [parts[0], fc, parts[1]]
    return ld + "/" + "$".join(parts)


def read_supervision(cli, dom, names, log):
    """Read LGOS / LSVS subscription supervision LNs (IEC 61850-7-4 Ed2)."""
    out = []
    nameset = set(names)
    for ln in names:
        m = SUPV_RE.match(ln)
        if not m:
            continue
        kind = "GOOSE" if m.group(1) == "LGOS" else "SV"
        e = {"ld": dom, "ln": ln, "kind": kind, "ref": None}
        for fc in ("ST", "SP", "CF"):
            if f"{ln}${fc}" not in nameset:
                continue
            try:
                named = name_values(cli.get_type(dom, f"{ln}${fc}"), cli.read(dom, f"{ln}${fc}"))
            except Exception as ex:
                log.append(f"read {dom}/{ln}${fc} failed: {ex}")
                continue
            if not isinstance(named, dict):
                continue
            if fc == "ST":
                e["st"] = _dig(named, "St", "stVal")
                e["simSt"] = _dig(named, "SimSt", "stVal")
                e["lastStNum"] = _dig(named, "LastStNum", "stVal")
                e["confRevNum"] = _dig(named, "ConfRevNum", "stVal")
                e["rxConfRevNum"] = _dig(named, "RxConfRevNum", "stVal")
                e["errSt"] = _dig(named, "ErrSt", "stVal")
                e["quality"] = to_jsonable(_dig(named, "St", "q"))
            for key in ("GoCBRef", "SvCBRef"):
                v = _dig(named, key, "setSrcRef")
                if v:
                    e["ref"] = norm_cb_ref(v, kind)
        if e.get("st") is None and not e["ref"]:
            continue
        log.append(f"{dom}/{ln}: subscription to {e['ref'] or '?'} is {'ACTIVE' if e.get('st') else 'NOT active'}")
        out.append(e)
    return out


def fmt_mac(b):
    if isinstance(b, (bytes, bytearray)) and len(b) == 6:
        return "-".join(f"{x:02X}" for x in b)
    return None if b is None else str(b)


def split_ref(ref):
    """'LD/LLN0$DS' -> ('LD','LLN0$DS')"""
    if ref and "/" in ref:
        d, i = ref.split("/", 1)
        return d, i.replace(".", "$")
    return None, ref


def host_alive(ip, timeout=1.0):
    """Is the host up even if MMS does not answer? TCP RST on 102 means up; otherwise try OS ping."""
    import socket
    import subprocess
    import sys
    try:
        socket.create_connection((ip, 102), timeout=timeout).close()
        return True, "TCP 102 open"
    except ConnectionRefusedError:
        return True, "host answers, TCP 102 closed"
    except OSError:
        pass
    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if sys.platform.startswith("win") \
        else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 2,
                           creationflags=0x08000000 if sys.platform.startswith("win") else 0)
        if r.returncode == 0:
            return True, "answers ping, TCP 102 not reachable"
        return False, "no answer to TCP 102 or ping"
    except (OSError, subprocess.SubprocessError):
        return False, "no answer on TCP 102 (ping not available)"


BEH = {1: "on", 2: "blocked", 3: "test", 4: "test/blocked", 5: "off"}
LPHD_RE = re.compile(r"^[A-Za-z0-9_]*LPHD\d*$")


def read_mode(cli, dom, names, log):
    """Operating mode of one logical device: LLN0.Mod/Beh (test, test/blocked, off …) and
    LPHD.Sim (simulation mode = the IED accepts simulated GOOSE/SV instead of the real ones)."""
    nameset = set(names)
    out = {"ld": dom, "mod": None, "beh": None, "sim": None, "simLn": None}

    def rd(item):
        # Read directly: many IEDs list only LN / DO level names in GetNameList, so a leaf
        # like LLN0$ST$Mod$stVal is often missing from the list although it can be read.
        try:
            v = cli.read(dom, item)
        except Exception:
            v = None
        if v is None or hasattr(v, "code"):          # not readable / DataAccessError
            parent = item.rsplit("$", 1)[0]          # fall back to the data object, take stVal from it
            try:
                tree = name_values(cli.get_type(dom, parent), cli.read(dom, parent))
                v = tree.get("stVal") if isinstance(tree, dict) else None
            except Exception:
                v = None
        return None if v is None or hasattr(v, "code") else v

    if any(n == "LLN0" or n.startswith("LLN0$") for n in names) or not names:
        for key, item in (("mod", "LLN0$ST$Mod$stVal"), ("beh", "LLN0$ST$Beh$stVal")):
            v = rd(item)
            if isinstance(v, int) and not isinstance(v, bool):
                out[key] = BEH.get(v, str(v))
    lphds = [ln for ln in names if "$" not in ln and LPHD_RE.match(ln)]
    if not lphds and any(n.startswith("LPHD1") for n in names):
        lphds = ["LPHD1"]
    for ln in lphds:
        v = rd(f"{ln}$ST$Sim$stVal")
        if isinstance(v, bool):
            out["sim"], out["simLn"] = v, ln
            break
    if out["mod"] is None and out["beh"] is None and out["sim"] is None:
        return []
    flags = []
    if out["beh"] in ("test", "test/blocked") or out["mod"] in ("test", "test/blocked"):
        flags.append(f"TEST mode (Mod={out['mod']}, Beh={out['beh']})")
    if out["beh"] in ("off", "blocked") or out["mod"] in ("off", "blocked"):
        flags.append(f"logical device {out['beh'] or out['mod']}")
    if out["sim"]:
        flags.append(f"SIMULATION mode ({out['simLn']}.Sim = true)")
    out["flags"] = flags
    log.append(f"{dom}: Mod={out['mod']} Beh={out['beh']} Sim={out['sim']}" + (f" -> {'; '.join(flags)}" if flags else ""))
    return [out]


def make_client(backend, ip, port, timeout, local_ip=None, lib_path=None):
    if backend == "libiec61850":
        from .backend_libiec61850 import LibIec61850Client
        return LibIec61850Client(ip, port, timeout, lib_path=lib_path)
    from .mms_client import BuiltinMmsClient
    return BuiltinMmsClient(ip, port, timeout, local_ip=local_ip)


def _read_dataset(cli, ds_ref, log):
    dom, item = split_ref(ds_ref)
    if not dom:
        return []
    members, values = [], []
    try:
        members = cli.dataset_directory(dom, item)
    except (MmsError, Exception) as e:
        log.append(f"dataset directory {ds_ref} failed: {e}")
    try:
        values = cli.read_dataset(dom, item)
    except (MmsError, Exception) as e:
        log.append(f"dataset read {ds_ref} failed: {e}")
    out = []
    for i in range(max(len(members), len(values))):
        ref = None
        if i < len(members):
            d, it = members[i]
            ref = f"{d}/{it}"
        v = values[i] if i < len(values) else None
        out.append({"index": i, "ref": ref,
                    "value": to_jsonable(v), "text": fmt_value(v) if v is not None else "",
                    "error": isinstance(v, FailedAccess)})
    return out


def inspect(ip, port=102, timeout=5.0, backend="builtin", local_ip=None, lib_path=None):
    t0 = time.time()
    rec = {"ip": ip, "port": port, "backend": backend, "started": t0, "ok": False,
           "identity": {}, "domains": [], "gocbs": [], "svcbs": [], "supervision": [], "vendorSupervision": [],
           "model": {}, "mode": [], "log": [], "error": None}
    cli = None
    try:
        cli = make_client(backend, ip, port, timeout, local_ip, lib_path)
        cli.connect()
        rec["ok"] = True
        try:
            rec["identity"] = cli.identify()
        except Exception as e:
            cli.log.append(f"identify not supported: {e}")
        doms = cli.domains()
        rec["domains"] = doms
        for dom in doms:
            names = cli.variables(dom)
            for item in names:
                is_go = bool(GOCB_RE.match(item))
                is_sv = bool(SVCB_RE.match(item))
                if not (is_go or is_sv):
                    continue
                cb = {"domain": dom, "item": item, "name": item.split("$")[-1],
                      "ref": f"{dom}/{item}", "kind": "GOOSE" if is_go else "SV"}
                try:
                    named = name_values(cli.get_type(dom, item), cli.read(dom, item))
                    if not isinstance(named, dict):
                        raise MmsError("control block is not a structure")
                    da = named.get("DstAddress") or {}
                    cb.update({
                        "enabled": named.get("GoEna", named.get("SvEna")),
                        "id": named.get("GoID", named.get("MsvID", named.get("UsvID"))),
                        "datSet": named.get("DatSet"),
                        "confRev": named.get("ConfRev"),
                        "ndsCom": named.get("NdsCom"),
                        "minTime": named.get("MinTime"),
                        "maxTime": named.get("MaxTime"),
                        "smpRate": named.get("SmpRate"),
                        "mac": fmt_mac(da.get("Addr")),
                        "vlanPriority": da.get("PRIORITY"),
                        "vlanId": da.get("VID"),
                        "appId": da.get("APPID"),
                        "raw": to_jsonable(named),
                    })
                    cb["members"] = _read_dataset(cli, cb["datSet"], cli.log) if cb["datSet"] else []
                except Exception as e:
                    cb["error"] = str(e)
                (rec["gocbs"] if is_go else rec["svcbs"]).append(cb)
            rec["model"][dom] = names
            rec["mode"] += read_mode(cli, dom, names, cli.log)
            rec["supervision"] += read_supervision(cli, dom, names, cli.log)
            try:
                from .vendor_supervision import read_vendor_supervision
                rec["vendorSupervision"] += read_vendor_supervision(cli, dom, names, cli.log)
            except Exception as ex:
                cli.log.append(f"vendor supervision scan failed in {dom}: {ex}")
        cli.log.append(f"found {len(rec['gocbs'])} GOOSE and {len(rec['svcbs'])} SV control blocks, "
                       f"{len(rec['supervision'])} subscription supervision LNs (LGOS/LSVS)")
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"
        if not rec["ok"]:
            up, how = host_alive(ip, min(timeout, 2.0))
            rec["hostUp"], rec["hostCheck"] = up, how
    finally:
        if cli:
            rec["log"] = list(cli.log)
            try:
                cli.close()
            except Exception:
                pass
    from .scl import device_profile
    idt = rec.get("identity") or {}
    rec["profile"] = device_profile(idt.get("vendor"), idt.get("model"), idt.get("revision"))
    if rec.get("hostCheck"):
        rec["log"].append(f"reachability: {rec['hostCheck']}")
    rec["finished"] = time.time()
    rec["duration_ms"] = int((rec["finished"] - t0) * 1000)
    return rec


def probe(ip, port=102, timeout=2.0, backend="builtin", lib_path=None):
    """Fast reachability check: TCP + MMS association + Identify."""
    cli = None
    try:
        cli = make_client(backend, ip, port, timeout, lib_path=lib_path)
        cli.connect()
        ident = {}
        try:
            ident = cli.identify()
        except Exception:
            pass
        return {"reachable": True, "identity": ident}
    except Exception as e:
        up, how = host_alive(ip, timeout)
        return {"reachable": False, "error": str(e), "hostUp": up, "hostCheck": how}
    finally:
        if cli:
            try:
                cli.close()
            except Exception:
                pass
