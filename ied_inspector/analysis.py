"""Joins SCD, MMS and on-the-wire data, compares them and builds views per
control block, signal, VLAN, device and IP. Recomputed on demand, so an SCD
loaded later validates everything that was collected before."""
import os
import re
import time
from collections import defaultdict

SEV_RANK = {"ok": 0, "info": 1, "warning": 2, "error": 3}
FIELDS = [("vlanId", "VLAN ID", "error"), ("vlanPriority", "VLAN priority", "warning"),
          ("appId", "APPID", "error"), ("mac", "Destination MAC", "error"),
          ("confRev", "ConfRev", "error"), ("id", "GoID / SvID", "warning"), ("datSet", "DataSet", "warning")]


def norm_ref(ref):
    if not ref:
        return ref
    if "/" in ref:
        ld, rest = ref.split("/", 1)
        return ld + "/" + rest.replace(".", "$")
    return ref.replace(".", "$")


LD_SUFFIX = re.compile(r"(LD0|LD\d+|CTRL|PROT|MEAS|MET|DR|SUPV|SUP|CON|CMD|APP\d*|SYS|LN0)$", re.I)


def ied_name_from_domains(domains):
    """IEC 61850 LD names are <IEDname><LDinst>: the common prefix of all LDs is the IED name.
    With a single LD, strip a well-known LD instance suffix (LD0, CTRL, PROT, …)."""
    doms = [d for d in domains if d]
    if not doms:
        return None
    if len(doms) > 1:
        p = os.path.commonprefix(doms)
        return p if len(p) >= 3 else None
    base = LD_SUFFIX.sub("", doms[0])
    return base if len(base) >= 3 else doms[0]


def vlanTxt(v):
    return "untagged" if v is None else str(v)


def worst(*sevs):
    s = "ok"
    for x in sevs:
        if x and SEV_RANK.get(x, 0) > SEV_RANK[s]:
            s = x
    return s


def fmt(field, v):
    if v is None:
        return None
    if field == "appId" and isinstance(v, int):
        return f"0x{v:04X}"
    return v


def analyze(scl=None, connections=None, trackers=None, probes=None, now=None):
    now = now or time.time()
    connections = connections or []
    trackers = trackers or []
    probes = probes or {}
    findings = []
    rows = {}

    def row(ref, kind):
        r = rows.get(ref)
        if r is None:
            r = rows[ref] = {"ref": ref, "kind": kind, "readFrom": None, "supervision": [], "name": ref.split("$")[-1], "ld": ref.split("/")[0],
                             "device": None, "ip": None, "scd": None, "mms": None, "wire": None,
                             "members": [], "subscribers": [], "checks": [], "findings": []}
        return r

    # ---------------- SCD
    ld_to_ied = {}
    if scl:
        for ied in scl.ieds.values():
            for ld in ied["lds"]:
                ld_to_ied[ld["name"]] = ied["name"]
        for cb in scl.all_gocbs() + scl.all_svcbs():
            r = row(cb["ref"], "GOOSE" if "$GO$" in cb["ref"] else "SV")
            r["scd"] = {k: cb.get(k) for k in ("vlanId", "vlanPriority", "appId", "mac", "confRev", "id", "datSet",
                                               "minTime", "maxTime", "smpRate", "subnet")}
            r["scd"]["members"] = cb.get("members", [])
            r["device"], r["ip"] = cb["iedName"], cb.get("ip")
        for sub, pub_ref, e in scl.subscriptions():
            r = rows.get(pub_ref)
            if r is not None:
                sig = f"{e.get('prefix', '')}{e.get('lnClass', '')}{e.get('lnInst', '')}.{e.get('doName', '')}" + \
                      (f".{e['daName']}" if e.get("daName") else "")
                r["subscribers"].append({"device": sub, "signal": sig, "intAddr": e.get("intAddr")})

    ip_to_ied = {}
    if scl:
        for ied in scl.ieds.values():
            if ied["ip"]:
                ip_to_ied[ied["ip"]] = ied["name"]

    # ---------------- MMS (latest successful connection per IP wins)
    latest = {}
    for c in connections:
        if c.get("ok"):
            latest[c["ip"]] = c
    conn_dev = {}
    for ip, c in latest.items():
        name = ip_to_ied.get(ip) or next((ld_to_ied[d] for d in c.get("domains", []) if d in ld_to_ied), None)
        conn_dev[ip] = name or ied_name_from_domains(c.get("domains", [])) or \
            (f"{(c.get('identity') or {}).get('model')} @ {ip}" if (c.get("identity") or {}).get("model") else ip)
    # two different IPs must never be merged into one device just because their names look alike
    seen = defaultdict(list)
    for ip, n in conn_dev.items():
        seen[n].append(ip)
    for n, ips in seen.items():
        if len(ips) > 1 and n not in (scl.ieds if scl else {}):
            for ip in ips:
                conn_dev[ip] = f"{n} @ {ip}"
        elif len(ips) > 1:
            for ip in ips:
                if ip != (scl.ieds[n].get("ip") if scl else None):
                    conn_dev[ip] = f"{n} @ {ip}"
    for ip, c in latest.items():
        for cb in c.get("gocbs", []) + c.get("svcbs", []):
            ref = norm_ref(cb["ref"])
            prev = rows.get(ref)
            if prev is not None and prev["mms"] and prev.get("readFrom") not in (None, ip):
                # same reference read from another IP (e.g. two simulators from one CID) – keep both
                ref = f"{ref} @ {ip}"
            r = row(ref, cb["kind"])
            r["name"] = cb.get("name") or r["name"]
            r["ld"] = cb.get("domain") or r["ld"]
            r["mms"] = {k: cb.get(k) for k in ("vlanId", "vlanPriority", "appId", "mac", "confRev", "id", "datSet",
                                               "enabled", "ndsCom", "minTime", "maxTime", "error")}
            r["mms"]["datSet"] = norm_ref(r["mms"]["datSet"])
            r["mms"]["connId"] = c.get("id")
            r["mms"]["readAt"] = c.get("started")
            r["mms"]["members"] = cb.get("members", [])
            r["ip"] = r["ip"] or ip
            r["readFrom"] = ip
            if not r["device"]:
                r["device"] = ld_to_ied.get(r["ld"]) or conn_dev[ip]
            if r["ip"] and r["ip"] != ip:
                if ip.startswith("127."):
                    r["findings"].append(("info", f"read from local address {ip} (simulator?), SCD address is {r['ip']}"))
                else:
                    r["findings"].append(("warning", f"SCD places this control block on {r['ip']} but it was read from {ip}"))

    # ---------------- wire
    for tr in trackers:
        snap = tr.snapshot(now) if hasattr(tr, "snapshot") else tr
        for s in snap["goose"]:
            ref = norm_ref(s.get("gocbRef") or f"?{s['src']}/{s.get('appId')}")
            r = rows.get(ref)
            if r is None:
                r = row(ref, "GOOSE")
            w = r["wire"]
            if w is None or (s.get("last") or 0) >= (w.get("last") or 0):
                r["wire"] = {"vlanId": s.get("vlanId"), "vlanPriority": s.get("vlanPriority"), "appId": s.get("appId"),
                             "mac": s.get("dst"), "confRev": s.get("confRev"), "id": s.get("goID"),
                             "datSet": norm_ref(s.get("datSet")), "tagged": s.get("tagged"), "src": s.get("src"),
                             "status": s["status"], "warnings": s.get("warnings", []), "stNum": s.get("stNum"),
                             "sqNum": s.get("sqNum"), "tal": s.get("tal"), "test": s.get("test"),
                             "simulation": s.get("simulation"), "ndsCom": s.get("ndsCom"), "count": s.get("count"),
                             "last": s.get("last"), "age": s.get("age"), "source": snap["source"],
                             "live": snap["live"], "values": s.get("valueText", [])}
            if not r["device"]:
                r["device"] = ld_to_ied.get(r["ld"]) or s.get("src")
        for s in snap["sv"]:
            ref = None
            for rr in rows.values():
                if rr["kind"] == "SV" and ((rr["scd"] or {}).get("id") == s.get("svID") or (rr["mms"] or {}).get("id") == s.get("svID")):
                    ref = rr["ref"]
                    break
            r = rows.get(ref) if ref else row(f"?SV/{s.get('svID')}", "SV")
            r["wire"] = {"vlanId": s.get("vlanId"), "vlanPriority": s.get("vlanPriority"), "appId": s.get("appId"),
                         "mac": s.get("dst"), "confRev": s.get("confRev"), "id": s.get("svID"),
                         "datSet": norm_ref(s.get("datSet")) if s.get("datSet") else None, "tagged": s.get("tagged"),
                         "src": s.get("src"), "status": s["status"], "warnings": s.get("warnings", []),
                         "rate": s.get("rate"), "smpSynch": s.get("smpSynch"), "count": s.get("count"),
                         "last": s.get("last"), "age": s.get("age"), "source": snap["source"], "live": snap["live"],
                         "simulation": s.get("simulation"), "values": [str(v) for v in s.get("values", [])]}
            if not r["device"]:
                r["device"] = s.get("src")

    captured = any(True for _ in trackers)

    # ---------------- vendor device-level receive supervision (e.g. ABB GSEGGIO1) -> per-stream entries
    vendor = []
    for ip, c in latest.items():
        for vs in c.get("vendorSupervision", []):
            vendor.append(dict(vs, device=conn_dev[ip], ip=ip, readAt=c.get("started")))
    for vs in vendor:
        if vs["scope"] != "device":
            continue
        has_lgos = {norm_ref(e.get("ref")) for e in (latest.get(vs["ip"]) or {}).get("supervision", [])}
        for r in rows.values():
            if r["ref"] in has_lgos:
                continue
            if any(s["device"] == vs["device"] for s in r["subscribers"]):
                r["supervision"].append({"device": vs["device"], "ip": vs["ip"], "ld": vs["ld"],
                                         "ln": vs["ln"] + " (device level)", "deviceLevel": True,
                                         "st": True if vs["ok"] else None, "readAt": vs["readAt"],
                                         "lastStNum": None, "confRevNum": None, "rxConfRevNum": None, "simSt": None})

    # ---------------- subscriber supervision (LGOS / LSVS read over MMS)
    supv_unlinked = []
    for ip, c in latest.items():
        for e in c.get("supervision", []):
            ent = dict(e, device=conn_dev[ip], ip=ip, readAt=c.get("started"))
            r = rows.get(norm_ref(e.get("ref"))) if e.get("ref") else None
            if r is None:
                supv_unlinked.append(ent)
            else:
                r["supervision"].append(ent)

    # ---------------- checks per control block
    for r in rows.values():
        srcs = [(n, r[n]) for n in ("scd", "mms", "wire") if r[n]]
        for field, label, sev in FIELDS:
            vals = {n: d.get(field) for n, d in srcs}
            if field == "datSet" and "wire" in vals and vals["wire"] is None:
                vals.pop("wire")
            present = {n: v for n, v in vals.items() if v is not None}
            if field == "vlanId" and r["wire"] is not None and not r["wire"].get("tagged"):
                present["wire"] = "untagged"
            distinct = set(present.values())
            if field == "vlanId" and distinct == {0, "untagged"}:
                distinct = {0}
            status = "match" if len(distinct) <= 1 else "mismatch"
            if not present:
                status = "n/a"
            r["checks"].append({"field": field, "label": label, "status": status,
                                "values": {n: fmt(field, v) for n, v in vals.items()}})
            if status == "mismatch":
                txt = ", ".join(f"{n.upper()}={fmt(field, v)}" for n, v in present.items())
                msg = f"{label} differs: {txt}"
                if field == "vlanId" and present.get("wire") == "untagged":
                    msg += " (frames arrive untagged: check switch port mode or NIC VLAN offload)"
                r["findings"].append((sev, msg))
        if r["scd"] and r["mms"]:
            sm, mm = r["scd"]["members"], [m.get("ref") for m in r["mms"]["members"]]
            if mm and sm and [norm_ref(x) for x in sm] != [norm_ref(x) for x in mm]:
                r["findings"].append(("error", f"DataSet content differs: SCD has {len(sm)} members, device has {len(mm)} (or a different order)"))
        if r["mms"]:
            if r["mms"].get("error"):
                r["findings"].append(("error", f"MMS read failed: {r['mms']['error']}"))
            if r["mms"].get("enabled") is False:
                r["findings"].append(("warning", "publishing is disabled on the device (GoEna/SvEna = false)"))
            if r["mms"].get("ndsCom"):
                r["findings"].append(("warning", "device reports NdsCom (needs commissioning)"))
        if r["wire"]:
            w = r["wire"]
            if w["status"] == "timeout":
                r["findings"].append(("error", f"stream timed out (last frame {w.get('age')} s ago, TAL {w.get('tal')} ms)"
                                      if r["kind"] == "GOOSE" else f"SV stream stopped ({w.get('age')} s ago)"))
            for wmsg in w.get("warnings", []):
                r["findings"].append(("warning", wmsg))
            if scl and not r["scd"]:
                r["findings"].append(("warning", "published on the network but not defined in the SCD"))
        elif captured and (r["scd"] or r["mms"]) and (r["mms"] or {}).get("enabled") is not False:
            r["findings"].append(("info", "not seen on the network during capture/pcap"))
        for sv in r["supervision"]:
            who = f"{sv['device']} ({sv['ln']})"
            vlan_now = (r["wire"] or {}).get("vlanId") if r["wire"] else (r["mms"] or r["scd"] or {}).get("vlanId")
            if sv.get("st") is True and sv.get("deviceLevel"):
                r["findings"].append(("ok", f"subscriber {who} reports no GOOSE receive alarm – reception confirmed at device level"))
            elif sv.get("st") is None and sv.get("deviceLevel"):
                r["findings"].append(("warning", f"subscriber {who} has a GOOSE receive alarm – this stream may be the one "
                                                 f"not received (VLAN {vlanTxt(vlan_now)})"))
            elif sv.get("st") is True:
                r["findings"].append(("ok", f"subscriber {who} receives this stream – VLAN path confirmed"))
            elif sv.get("st") is False:
                if r["wire"] and r["wire"]["status"] == "ok":
                    msg = (f"subscriber {who} does NOT receive it although it is published on VLAN {vlanTxt(vlan_now)} "
                           f"– check that VLAN {vlanTxt(vlan_now)} is allowed on the subscriber's switch port and on all trunks")
                else:
                    msg = (f"subscriber {who} does NOT receive it (LGOS/LSVS St = false)"
                           + (f"; expected on VLAN {vlanTxt(vlan_now)}" if vlan_now is not None else ""))
                r["findings"].append(("error", msg))
            pub_rev = next((r[n].get("confRev") for n in ("wire", "mms", "scd") if r[n] and r[n].get("confRev") is not None), None)
            if sv.get("confRevNum") not in (None, 0) and pub_rev is not None and sv["confRevNum"] != pub_rev:
                r["findings"].append(("error", f"subscriber {who} expects ConfRev {sv['confRevNum']}, publisher uses {pub_rev}"))
            if sv.get("simSt"):
                r["findings"].append(("warning", f"subscriber {who} is accepting simulated messages (SimSt = true)"))
        if r["mms"] and scl and not r["scd"]:
            r["findings"].append(("warning", "control block exists on the device but not in the SCD"))
        if r["scd"] and not r["mms"] and r["ip"] in latest:
            r["findings"].append(("error", "defined in the SCD but not found on the device"))
        r["findings"].sort(key=lambda f: -SEV_RANK.get(f[0], 0))
        r["status"] = worst(*[s for s, _ in r["findings"]])
        own = [(s_, m) for s_, m in r["findings"] if not m.startswith("subscriber ")]
        r["pubStatus"] = worst(*[s_ for s_, _ in own])
        r["pubFindings"] = own
        sup = r["supervision"]
        r["rx"] = {"ok": sum(1 for x in sup if x.get("st") is True), "total": len(sup)} if sup else None
        r["effective"] = {f: next((r[n][f] for n in ("wire", "mms", "scd") if r[n] and r[n].get(f) is not None), None)
                          for f, _, _ in FIELDS}
        if r["wire"] is not None and not r["wire"].get("tagged") and r["effective"]["vlanId"] is None:
            r["effective"]["vlanId"] = None
        for sev, msg in r["findings"]:
            if sev == "ok":
                continue
            findings.append({"severity": sev, "category": "Comparison", "device": r["device"], "object": r["ref"], "message": msg})

    # ---------------- signals
    signals = []
    for r in rows.values():
        smem = (r["scd"] or {}).get("members", [])
        mmem = (r["mms"] or {}).get("members", [])
        wvals = (r["wire"] or {}).get("values", [])
        n = max(len(smem), len(mmem), len(wvals))
        for i in range(n):
            sref = smem[i] if i < len(smem) else None
            m = mmem[i] if i < len(mmem) else {}
            mref = m.get("ref")
            st = "ok"
            note = ""
            if sref and mref and norm_ref(sref) != norm_ref(mref):
                st, note = "error", "member differs between SCD and device"
            elif (sref or mref) and r["wire"] and i >= len(wvals):
                st, note = "warning", "member missing in GOOSE frame"
            ref = norm_ref(sref or mref) or f"{r['ref']}[{i}]"
            parts = ref.split("/")[-1].split("$")
            msig = ".".join([parts[0]] + parts[2:]) if len(parts) > 2 else ".".join(parts)
            subs = sorted({s["device"] for s in r["subscribers"]
                           if s["signal"] == msig or msig.startswith(s["signal"] + ".") or s["signal"].startswith(msig + ".")})
            signals.append({"ref": ref, "index": i, "cb": r["ref"], "kind": r["kind"], "device": r["device"],
                            "ip": r["ip"], "vlanId": r["effective"]["vlanId"],
                            "scdRef": sref, "mmsRef": mref, "mmsValue": m.get("text"),
                            "wireValue": wvals[i] if i < len(wvals) else None,
                            "subscribers": subs, "status": st, "note": note})

    # ---------------- devices
    devices = {}

    def dev(name):
        d = devices.get(name)
        if d is None:
            d = devices[name] = {"name": name, "ip": None, "inScd": False, "reachable": None, "identity": {},
                                 "publishes": set(), "subscribes": set(), "cbs": [], "status": "ok",
                                 "findings": [], "lastRead": None, "desc": None, "type": None, "readFrom": None,
                                 "profile": None, "hostUp": None, "mode": [], "simulation": None, "testMode": None}
        return d

    def _inbound(sd, r, v, via, signal=None, receiving=None, receiving_ln=None, device_level=False):
        """Collect the streams a device receives (from SCD ExtRefs and from LGOS/LSVS/vendor supervision)."""
        ib = sd.setdefault("_in", {}).get(r["ref"])
        if ib is None:
            ib = sd["_in"][r["ref"]] = {
                "ref": r["ref"], "name": r["name"], "kind": r["kind"], "publisher": r["device"],
                "publisherIp": r.get("readFrom") or r["ip"], "vlanId": v,
                "vlanBySource": {n: r[n].get("vlanId") for n in ("scd", "mms", "wire") if r[n]},
                "appId": r["effective"]["appId"], "mac": r["effective"]["mac"],
                "pubStatus": r["pubStatus"], "net": (r["wire"] or {}).get("status"),
                "signals": [], "receiving": None, "receivingLn": None, "deviceLevel": False, "via": set()}
        ib["via"].add(via)
        if signal and signal not in ib["signals"]:
            ib["signals"].append(signal)
        if via == "supervision" and (ib["receiving"] is None or ib["deviceLevel"]):
            ib["receiving"], ib["receivingLn"], ib["deviceLevel"] = receiving, receiving_ln, device_level

    if scl:
        for ied in scl.ieds.values():
            d = dev(ied["name"])
            d.update(ip=ied["ip"], inScd=True, desc=ied.get("desc"), type=ied.get("type"), profile=ied.get("profile"))
    for r in rows.values():
        d = dev(r["device"] or "unknown")
        d["ip"] = d["ip"] or r["ip"]
        d["cbs"].append(r["ref"])
        v = r["effective"]["vlanId"]
        d["publishes"].add(v if v is not None else "untagged")
        if r["pubStatus"] in ("warning", "error"):
            d["findings"].append(f"{r['name']}: {r['pubFindings'][0][1] if r['pubFindings'] else r['pubStatus']}")
        d["status"] = worst(d["status"], r["pubStatus"])
        for sv in r["supervision"]:
            sd = dev(sv["device"])
            sd["subscribes"].add(v if v is not None else "untagged")
            _inbound(sd, r, v, "supervision", receiving=sv.get("st"),
                     receiving_ln=sv.get("ln"), device_level=bool(sv.get("deviceLevel")))
            if sv.get("st") is False:
                msg = f"does not receive {r['ref']} (VLAN {vlanTxt(v)}) – LGOS/LSVS St = false"
                sd["findings"].insert(0, msg)
                sd["status"] = worst(sd["status"], "error")
                findings.append({"severity": "error", "category": "VLAN", "device": sv["device"], "object": r["ref"], "message": msg})
            elif sv.get("st") is True:
                sd.setdefault("receiving", []).append(r["ref"])
        for s in r["subscribers"]:
            sd = dev(s["device"])
            sd["subscribes"].add(v if v is not None else "untagged")
            _inbound(sd, r, v, "scd", signal=s["signal"])
            sv = (r["scd"] or {}).get("vlanId")
            if sv is not None and v is not None and sv != v:
                msg = f"subscribes to {r['ref']} which is configured for VLAN {sv} in the SCD but published on VLAN {v}"
                sd["findings"].append(msg)
                sd["status"] = worst(sd["status"], "error")
                findings.append({"severity": "error", "category": "VLAN", "device": s["device"], "object": r["ref"], "message": msg})
    for ip, c in latest.items():
        d = dev(conn_dev[ip])
        d["mode"] = c.get("mode", [])
        sim = [m for m in d["mode"] if m.get("sim")]
        test = [m for m in d["mode"] if m.get("beh") in ("test", "test/blocked") or m.get("mod") in ("test", "test/blocked")]
        off = [m for m in d["mode"] if m.get("beh") in ("off", "blocked") or m.get("mod") in ("off", "blocked")]
        d["simulation"], d["testMode"] = bool(sim), bool(test)
        if sim:
            msg = (f"SIMULATION mode is ON ({sim[0]['ld']}/{sim[0]['simLn']}.Sim = true) – the IED accepts simulated "
                   f"GOOSE/SV instead of the real ones; switch it off after testing")
            d["findings"].insert(0, msg)
            d["status"] = worst(d["status"], "warning")
            findings.append({"severity": "warning", "category": "Test / simulation", "device": d["name"],
                             "object": f"{sim[0]['ld']}/{sim[0]['simLn']}", "message": msg})
        for m in test:
            msg = f"logical device {m['ld']} is in TEST mode (Mod={m['mod']}, Beh={m['beh']}) – its GOOSE carry the TEST flag"
            d["findings"].insert(0, msg)
            d["status"] = worst(d["status"], "warning")
            findings.append({"severity": "warning", "category": "Test / simulation", "device": d["name"],
                             "object": m["ld"], "message": msg})
        for m in off:
            msg = f"logical device {m['ld']} is {m['beh'] or m['mod']} (Mod={m['mod']}, Beh={m['beh']})"
            d["findings"].append(msg)
            d["status"] = worst(d["status"], "warning")
            findings.append({"severity": "warning", "category": "Test / simulation", "device": d["name"],
                             "object": m["ld"], "message": msg})
        d["readFrom"] = ip
        d["ip"] = d["ip"] or ip
        d["identity"] = c.get("identity") or {}
        d["profile"] = d["profile"] or c.get("profile")
        d["lastRead"] = c.get("finished")
        d["reachable"] = True
    for c in connections:
        if not c.get("ok") and c["ip"] not in latest:
            name = ip_to_ied.get(c["ip"], c["ip"])
            d = dev(name)
            d["ip"] = d["ip"] or c["ip"]
            d["reachable"] = False
            d["hostUp"] = c.get("hostUp")
    for ip, p in probes.items():
        name = ip_to_ied.get(ip)
        if name and name in devices:
            if devices[name].get("readFrom") and devices[name]["readFrom"] != ip:
                continue
            if devices[name]["reachable"] is None or p.get("ts", 0) > (devices[name]["lastRead"] or 0):
                devices[name]["reachable"] = p.get("reachable")
                devices[name]["hostUp"] = p.get("hostUp") if not p.get("reachable") else True
                if p.get("identity"):
                    devices[name]["identity"] = p["identity"]
    # ---- TEST / simulation flag seen in the device's own GOOSE/SV frames on the network
    for d in devices.values():
        own_wire = [r for r in rows.values() if r["device"] == d["name"] and r["wire"]]
        test_net = [r for r in own_wire if r["wire"].get("test")]
        sim_net = [r for r in own_wire if r["wire"].get("simulation")]
        src = []
        if d.get("testMode"):
            src.append("MMS")
        if test_net:
            src.append("network")
            if not d.get("testMode"):
                beh = ", ".join(f"{m['ld']}: Beh={m.get('beh')}" for m in d.get("mode", [])) or "not read over MMS"
                msg = (f"publishes GOOSE with the TEST flag ({', '.join(r['name'] for r in test_net)}) – the IED is in "
                       f"test mode; MMS mode: {beh}")
                d["findings"].insert(0, msg)
                d["status"] = worst(d["status"], "warning")
                findings.append({"severity": "warning", "category": "Test / simulation", "device": d["name"],
                                 "object": test_net[0]["ref"], "message": msg})
            d["testMode"] = True
        d["testSource"] = src
        if sim_net:
            msg = (f"publishes frames with the SIMULATION bit ({', '.join(r['name'] for r in sim_net)}) – "
                   f"subscribers in simulation mode will use these instead of the real values")
            d["findings"].insert(0, msg)
            d["status"] = worst(d["status"], "warning")
            findings.append({"severity": "warning", "category": "Test / simulation", "device": d["name"],
                             "object": sim_net[0]["ref"], "message": msg})
            d["simFrames"] = True
    for d in devices.values():
        if d["reachable"] is False and not d.get("hostUp"):
            if any(r["device"] == d["name"] and r["wire"] and r["wire"]["status"] == "ok" for r in rows.values()):
                d["hostUp"] = True          # its GOOSE/SV is alive on the network, so the device itself is up
        if d["reachable"] is False:
            if d.get("hostUp"):
                d["status"] = worst(d["status"], "warning")
                hint = (" – check that the CI868 MMS server is enabled in the hardware configuration and the CID is downloaded"
                        if d.get("profile") == "ABB CI868" else "")
                d["findings"].insert(0, "host is up but MMS (TCP 102) does not answer" + hint)
            else:
                d["status"] = worst(d["status"], "error")
                d["findings"].insert(0, "not reachable (no MMS, no answer on TCP 102 or ping)")
        if d.get("profile") == "ABB CI868":
            alive = [r for r in rows.values() if r["device"] == d["name"] and r["wire"] and r["wire"]["status"] == "ok"]
            if alive:
                d["findings"].append(f"CI868 publishes {len(alive)} GOOSE stream(s) on the network")
        inbound = []
        for ib in (d.pop("_in", None) or {}).values():
            ib["via"] = sorted(ib["via"])
            scd_v = ib["vlanBySource"].get("scd")
            vlan_diff = len({x for x in ib["vlanBySource"].values() if x is not None}) > 1
            if ib["receiving"] is False:
                st = "error"
            elif vlan_diff:
                st = "error"
            elif ib["net"] == "timeout":
                st = "error"
            else:
                st = worst(ib["pubStatus"], "ok")
            ib["status"] = st
            ib["vlanMismatch"] = vlan_diff
            ib["scdVlan"] = scd_v
            inbound.append(ib)
        d["inbound"] = sorted(inbound, key=lambda x: (str(x["vlanId"]), x["publisher"] or "", x["name"]))
        # VLAN usage of this device: which VLANs it sends on, which it receives on, and what
        use = {}
        for r in rows.values():
            if r["device"] == d["name"]:
                k = r["effective"]["vlanId"]
                use.setdefault(k, {"vlan": k, "publishes": [], "subscribes": []})["publishes"].append(r["name"])
        for ib in d["inbound"]:
            k = ib["vlanId"]
            use.setdefault(k, {"vlan": k, "publishes": [], "subscribes": []})["subscribes"].append(
                f"{ib['publisher']} {ib['name']}")
        d["vlanUse"] = sorted(use.values(), key=lambda u: (u["vlan"] is None, u["vlan"] or 0))
        pubs = {v for v in d["publishes"] if v != "untagged"}
        d["requiredVlans"] = sorted({v for v in (d["publishes"] | d["subscribes"]) if isinstance(v, int)})
        d["publishes"] = sorted(d["publishes"], key=str)
        d["subscribes"] = sorted(d["subscribes"], key=str)
        if len(pubs) > 1:
            d["findings"].append(f"publishes on {len(pubs)} VLANs: {', '.join(map(str, sorted(pubs)))}")

    # ---------------- VLANs
    vlans = defaultdict(lambda: {"publishers": [], "subscribers": set(), "devices": set(), "streams": 0, "seenOnWire": False})
    for r in rows.values():
        v = r["effective"]["vlanId"]
        key = "untagged" if v is None else v
        e = vlans[key]
        e["publishers"].append({"ref": r["ref"], "device": r["device"], "kind": r["kind"], "status": r["status"],
                                "sources": [n for n in ("scd", "mms", "wire") if r[n]],
                                "vlanBySource": {n: (r[n] or {}).get("vlanId") for n in ("scd", "mms", "wire") if r[n]}})
        e["devices"].add(r["device"])
        for s in r["subscribers"]:
            e["subscribers"].add(s["device"])
        if r["wire"]:
            e["streams"] += 1
            e["seenOnWire"] = True
    vlan_list = []
    for k, e in sorted(vlans.items(), key=lambda kv: (isinstance(kv[0], str), kv[0] if isinstance(kv[0], int) else 0)):
        vlan_list.append({"vlan": k, "publishers": e["publishers"], "subscribers": sorted(e["subscribers"]),
                          "devices": sorted(x for x in e["devices"] if x), "streams": e["streams"],
                          "seenOnWire": e["seenOnWire"],
                          "status": worst(*[p["status"] for p in e["publishers"]])})

    for vs in vendor:
        d = dev(vs["device"])
        d.setdefault("vendorSupervision", []).append(vs)
        if vs["ok"] is False:
            vl = ", ".join(map(str, sorted(d["subscribes"], key=str))) or "unknown"
            msg = (f"{vs['ln']}: {vs['summary']} – subscribed VLANs {vl}; check them on this IED's switch port"
                   if vs["scope"] == "device" else f"{vs['ln']}: {vs['summary']}")
            d["findings"].insert(0, msg)
            d["status"] = worst(d["status"], "error")
            findings.append({"severity": "error", "category": "GOOSE reception", "device": vs["device"],
                             "object": f"{vs['ld']}/{vs['ln']}", "message": msg})
        elif vs["ok"] is True:
            d.setdefault("receiving", []).append(f"{vs['ln']}: {vs['summary']}")
    for e in supv_unlinked:
        d = dev(e["device"])
        msg = f"{e['ln']} supervises {e.get('ref') or 'an unknown control block'} which is not known from SCD, MMS or capture"
        d["findings"].append(msg)
        if e.get("st") is False:
            d["status"] = worst(d["status"], "warning")
    supervision = [dict(e, linked=True) for r in rows.values() for e in r["supervision"]] + \
                  [dict(e, linked=False) for e in supv_unlinked]

    scd_findings = scl.validate() if scl else []
    all_findings = scd_findings + findings
    counts = defaultdict(int)
    for f in all_findings:
        counts[f["severity"]] += 1
    return {
        "generated": now, "scdLoaded": bool(scl), "connections": len(connections), "captures": len(trackers),
        "controlBlocks": sorted(rows.values(), key=lambda r: (r["device"] or "", r["ref"])),
        "signals": signals, "devices": sorted(devices.values(), key=lambda d: d["name"]),
        "vlans": vlan_list, "findings": all_findings, "counts": dict(counts), "supervision": supervision,
        "vendorSupervision": vendor,
    }
