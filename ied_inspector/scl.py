"""SCL (.scd / .cid / .icd / .iid) parser and validator."""
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import defaultdict


def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
        for k in list(el.attrib):
            if "}" in k:
                el.attrib[k.split("}", 1)[1]] = el.attrib.pop(k)
    return root


def _hex(s):
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def _int(s, default=None):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def norm_mac(s):
    if not s:
        return None
    h = s.replace("-", "").replace(":", "").replace(" ", "").upper()
    if len(h) != 12:
        return s.upper()
    return "-".join(h[i:i + 2] for i in range(0, 12, 2))


CI868_RE = re.compile(r"CI\s?868|AC\s?800M", re.I)
# ABB CI868A data sheet (3BSE092691R1): max 120 IEDs via GOOSE, 40 IEDs via MMS, 40 IEDs when both are combined
CI868_LIMITS = {"goose": 120, "mms": 40, "combined": 40}


def device_profile(*texts):
    t = " ".join(x for x in texts if x)
    if CI868_RE.search(t):
        return "ABB CI868"
    if re.search(r"\b(RE[A-Z]6[1-2]\d)\b", t):
        return "ABB Relion 615/620"
    if re.search(r"\b(RE[A-Z]6[5-7]0)\b", t):
        return "ABB Relion 650/670"
    return None


def ln_name(prefix, ln_class, inst):
    if ln_class == "LLN0":
        return "LLN0"
    return f"{prefix or ''}{ln_class}{inst or ''}"


def fcda_ref(ld_name, f):
    ln = ln_name(f.get("prefix"), f.get("lnClass"), f.get("lnInst"))
    parts = [ln, f.get("fc", "")]
    if f.get("doName"):
        parts += f["doName"].split(".")
    if f.get("daName"):
        parts += f["daName"].split(".")
    return f"{ld_name}/" + "$".join(p for p in parts if p)


class SclModel:
    def __init__(self):
        self.filename = None
        self.header = {}
        self.version = None
        self.ieds = {}            # name -> dict
        self.subnets = []         # list of dicts
        self.templates = {"LNodeType": {}, "DOType": {}, "DAType": {}, "EnumType": {}}
        self.root = None

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, data, filename="model.scd"):
        m = cls()
        m.filename = filename
        root = _strip_ns(ET.fromstring(data))
        m.root = root
        m.version = (root.get("version"), root.get("revision"), root.get("release"))
        h = root.find("Header")
        if h is not None:
            m.header = dict(h.attrib)
        m._parse_templates(root.find("DataTypeTemplates"))
        m._parse_communication(root.find("Communication"))
        for ied in root.findall("IED"):
            m._parse_ied(ied)
        m._link()
        return m

    def _parse_templates(self, dtt):
        if dtt is None:
            return
        for lnt in dtt.findall("LNodeType"):
            self.templates["LNodeType"][lnt.get("id")] = {
                "lnClass": lnt.get("lnClass"),
                "dos": [{"name": d.get("name"), "type": d.get("type")} for d in lnt.findall("DO")]}
        for dot in dtt.findall("DOType"):
            items = []
            for ch in dot:
                if ch.tag == "DA":
                    items.append({"kind": "DA", "name": ch.get("name"), "fc": ch.get("fc"),
                                  "bType": ch.get("bType"), "type": ch.get("type"),
                                  "count": _int(ch.get("count"), 0),
                                  "val": (ch.findtext("Val") or None)})
                elif ch.tag == "SDO":
                    items.append({"kind": "SDO", "name": ch.get("name"), "type": ch.get("type")})
            self.templates["DOType"][dot.get("id")] = {"cdc": dot.get("cdc"), "items": items}
        for dat in dtt.findall("DAType"):
            self.templates["DAType"][dat.get("id")] = [
                {"name": b.get("name"), "bType": b.get("bType"), "type": b.get("type"),
                 "count": _int(b.get("count"), 0), "val": (b.findtext("Val") or None)}
                for b in dat.findall("BDA")]
        for et in dtt.findall("EnumType"):
            self.templates["EnumType"][et.get("id")] = {
                _int(v.get("ord")): (v.text or "") for v in et.findall("EnumVal")}

    def _parse_communication(self, comm):
        if comm is None:
            return
        for sn in comm.findall("SubNetwork"):
            snd = {"name": sn.get("name"), "type": sn.get("type"), "aps": []}
            for cap in sn.findall("ConnectedAP"):
                ap = {"iedName": cap.get("iedName"), "apName": cap.get("apName"),
                      "address": {}, "gse": [], "smv": []}
                addr = cap.find("Address")
                if addr is not None:
                    ap["address"] = {p.get("type"): (p.text or "").strip() for p in addr.findall("P")}
                for tag, key in (("GSE", "gse"), ("SMV", "smv")):
                    for g in cap.findall(tag):
                        a = {}
                        ga = g.find("Address")
                        if ga is not None:
                            a = {p.get("type"): (p.text or "").strip() for p in ga.findall("P")}
                        ap[key].append({
                            "ldInst": g.get("ldInst"), "cbName": g.get("cbName"),
                            "mac": norm_mac(a.get("MAC-Address")),
                            "appId": _hex(a.get("APPID")),
                            "vlanIdRaw": a.get("VLAN-ID"),
                            "vlanId": _hex(a.get("VLAN-ID")),
                            "vlanPriority": _int(a.get("VLAN-PRIORITY")),
                            "minTime": _int(g.findtext("MinTime")),
                            "maxTime": _int(g.findtext("MaxTime")),
                        })
                snd["aps"].append(ap)
            self.subnets.append(snd)

    def _parse_ied(self, ied):
        name = ied.get("name")
        d = {"name": name, "manufacturer": ied.get("manufacturer"), "type": ied.get("type"),
             "desc": ied.get("desc"), "configVersion": ied.get("configVersion"),
             "lds": [], "ip": None, "subnet": None, "gocbs": [], "svcbs": [], "datasets": {},
             "extrefs": [], "aps": [], "rcbClients": [],
             "profile": device_profile(ied.get("type"), ied.get("name"), ied.get("desc"), ied.get("manufacturer"))}
        for ap in ied.findall("AccessPoint"):
            d["aps"].append(ap.get("name"))
            srv = ap.find("Server")
            if srv is None:
                continue
            for ld in srv.findall("LDevice"):
                inst = ld.get("inst")
                ld_name = (ld.get("ldName") or (name + inst))
                ldd = {"inst": inst, "name": ld_name, "ap": ap.get("name"), "lns": []}
                for ln in [ld.find("LN0")] + ld.findall("LN"):
                    if ln is None:
                        continue
                    lnd = {"lnClass": ln.get("lnClass"), "inst": ln.get("inst", ""),
                           "prefix": ln.get("prefix", ""), "lnType": ln.get("lnType"),
                           "name": ln_name(ln.get("prefix"), ln.get("lnClass"), ln.get("inst")),
                           "doi": self._parse_doi(ln)}
                    ldd["lns"].append(lnd)
                    for ds in ln.findall("DataSet"):
                        fcdas = [dict(f.attrib) for f in ds.findall("FCDA")]
                        for f in fcdas:
                            f.setdefault("ldInst", inst)
                        ref = f"{ld_name}/{lnd['name']}${ds.get('name')}"
                        d["datasets"][ref] = {"name": ds.get("name"), "ld": ld_name, "ln": lnd["name"],
                                              "ref": ref, "fcdas": fcdas,
                                              "members": [fcda_ref(self._ld_name_for(ied, f.get("ldInst"), name), f) for f in fcdas]}
                    for rc in ln.findall("ReportControl"):
                        for cl in rc.findall("RptEnabled/ClientLN"):
                            if cl.get("iedName"):
                                d["rcbClients"].append({"client": cl.get("iedName"), "rcb": rc.get("name"),
                                                        "ld": ld_name, "ln": lnd["name"]})
                    for inp in ln.findall("Inputs"):
                        for er in inp.findall("ExtRef"):
                            e = dict(er.attrib)
                            e["_subscriberLd"] = ld_name
                            e["_subscriberLn"] = lnd["name"]
                            d["extrefs"].append(e)
                    if ln.tag == "LN0":
                        for gc in ln.findall("GSEControl"):
                            if (gc.get("type") or "GOOSE") != "GOOSE":
                                continue
                            d["gocbs"].append({
                                "ld": ld_name, "ldInst": inst, "name": gc.get("name"),
                                "ref": f"{ld_name}/LLN0$GO${gc.get('name')}",
                                "id": gc.get("appID"), "confRev": _int(gc.get("confRev"), 0),
                                "datSet": f"{ld_name}/LLN0${gc.get('datSet')}" if gc.get("datSet") else None,
                                "fixedOffs": gc.get("fixedOffs") == "true"})
                        for sc in ln.findall("SampledValueControl"):
                            d["svcbs"].append({
                                "ld": ld_name, "ldInst": inst, "name": sc.get("name"),
                                "ref": f"{ld_name}/LLN0$MS${sc.get('name')}",
                                "id": sc.get("smvID"), "confRev": _int(sc.get("confRev"), 0),
                                "smpRate": _int(sc.get("smpRate"), 80),
                                "nofASDU": _int(sc.get("nofASDU"), 1),
                                "multicast": sc.get("multicast", "true") != "false",
                                "datSet": f"{ld_name}/LLN0${sc.get('datSet')}" if sc.get("datSet") else None})
                d["lds"].append(ldd)
        self.ieds[name] = d

    @staticmethod
    def _ld_name_for(ied, inst, ied_name):
        for ap in ied.findall("AccessPoint"):
            srv = ap.find("Server")
            if srv is None:
                continue
            for ld in srv.findall("LDevice"):
                if ld.get("inst") == inst:
                    return ld.get("ldName") or (ied_name + inst)
        return ied_name + (inst or "")

    @staticmethod
    def _parse_doi(ln):
        vals = {}

        def walk(el, path):
            for ch in el:
                if ch.tag in ("DOI", "SDI", "DAI"):
                    p = path + [ch.get("name")]
                    if ch.tag == "DAI":
                        v = ch.find("Val")
                        if v is not None and v.text is not None:
                            vals[".".join(p)] = v.text.strip()
                    else:
                        walk(ch, p)
        walk(ln, [])
        return vals

    def _link(self):
        for sn in self.subnets:
            for ap in sn["aps"]:
                ied = self.ieds.get(ap["iedName"])
                if not ied:
                    continue
                if ap["address"].get("IP") and not ied["ip"]:
                    ied["ip"] = ap["address"]["IP"]
                    ied["subnet"] = sn["name"]
                for key, cbs in (("gse", ied["gocbs"]), ("smv", ied["svcbs"])):
                    for g in ap[key]:
                        for cb in cbs:
                            if cb["ldInst"] == g["ldInst"] and cb["name"] == g["cbName"]:
                                cb.update({k: g[k] for k in ("mac", "appId", "vlanId", "vlanIdRaw",
                                                             "vlanPriority", "minTime", "maxTime")})
                                cb["subnet"] = sn["name"]
                                cb["hasAddress"] = True
        for ied in self.ieds.values():
            for cb in ied["gocbs"] + ied["svcbs"]:
                cb["iedName"] = ied["name"]
                cb["ip"] = ied["ip"]
                ds = ied["datasets"].get(cb["datSet"])
                cb["members"] = ds["members"] if ds else []
                cb.setdefault("hasAddress", False)
        # subscriptions
        for ied in self.ieds.values():
            for e in ied["extrefs"]:
                e["_publisherCb"] = self._resolve_extref(e)

    def _resolve_extref(self, e):
        pub = self.ieds.get(e.get("iedName"))
        if not pub:
            return None
        if e.get("srcCBName"):
            src_ld = e.get("srcLDInst") or e.get("ldInst")
            for cb in pub["gocbs"] + pub["svcbs"]:
                if cb["name"] == e["srcCBName"] and (not src_ld or cb["ldInst"] == src_ld):
                    return cb["ref"]
            return "?" + e["srcCBName"]
        # Ed1: match FCDA in published datasets
        for cb in pub["gocbs"] + pub["svcbs"]:
            ds = pub["datasets"].get(cb["datSet"])
            if not ds:
                continue
            for f in ds["fcdas"]:
                if (f.get("ldInst") == e.get("ldInst") and f.get("lnClass") == e.get("lnClass")
                        and (f.get("lnInst") or "") == (e.get("lnInst") or "")
                        and (f.get("prefix") or "") == (e.get("prefix") or "")
                        and f.get("doName") == e.get("doName")
                        and (not e.get("daName") or (f.get("daName") or "").startswith(e.get("daName")) or not f.get("daName"))):
                    return cb["ref"]
        return None

    # ------------------------------------------------------------------
    def all_gocbs(self):
        return [cb for ied in self.ieds.values() for cb in ied["gocbs"]]

    def all_svcbs(self):
        return [cb for ied in self.ieds.values() for cb in ied["svcbs"]]

    def cb_by_ref(self):
        return {cb["ref"]: cb for cb in self.all_gocbs() + self.all_svcbs()}

    def subscriptions(self):
        """List of (subscriberIed, publisherCbRef, extref) tuples."""
        out = []
        for ied in self.ieds.values():
            for e in ied["extrefs"]:
                if e.get("_publisherCb") and not e["_publisherCb"].startswith("?"):
                    out.append((ied["name"], e["_publisherCb"], e))
        return out

    def summary(self):
        return {
            "filename": self.filename, "header": self.header,
            "version": "".join(x for x in self.version if x),
            "subnets": [{"name": s["name"], "type": s["type"], "aps": len(s["aps"])} for s in self.subnets],
            "ieds": [{"name": i["name"], "manufacturer": i["manufacturer"], "type": i["type"], "profile": i.get("profile"),
                      "desc": i["desc"], "ip": i["ip"], "subnet": i["subnet"],
                      "lds": [ld["name"] for ld in i["lds"]],
                      "gocbs": len(i["gocbs"]), "svcbs": len(i["svcbs"]),
                      "subscriptions": len(i["extrefs"])} for i in self.ieds.values()],
        }

    # ------------------------------------------------------------------
    def validate(self):
        F = []

        def add(sev, cat, ied, obj, msg):
            F.append({"severity": sev, "category": cat, "device": ied, "object": obj, "message": msg})

        names = defaultdict(int)
        for ied in self.root.findall("IED"):
            names[ied.get("name")] += 1
        for n, c in names.items():
            if c > 1:
                add("error", "IED", n, n, f"IED name '{n}' is defined {c} times")

        ips = defaultdict(list)
        for ied in self.ieds.values():
            if ied["ip"]:
                ips[ied["ip"]].append(ied["name"])
                try:
                    ipaddress.ip_address(ied["ip"])
                except ValueError:
                    add("error", "Addressing", ied["name"], ied["name"], f"IP address '{ied['ip']}' is not valid")
            elif ied["lds"]:
                add("warning", "Addressing", ied["name"], ied["name"], "IED has no IP address in the Communication section")
        for ip, lst in ips.items():
            if len(lst) > 1:
                add("error", "Addressing", ", ".join(lst), ip, f"IP {ip} is used by several IEDs: {', '.join(lst)}")

        appids, macs, goids = defaultdict(list), defaultdict(list), defaultdict(list)
        for ied in self.ieds.values():
            for kind, cbs in (("GOOSE", ied["gocbs"]), ("SV", ied["svcbs"])):
                for cb in cbs:
                    o = cb["ref"]
                    if not cb["hasAddress"]:
                        add("error", kind, ied["name"], o, f"{kind} control block '{cb['name']}' has no "
                            f"{'GSE' if kind == 'GOOSE' else 'SMV'} address in the Communication section")
                        continue
                    v = cb.get("vlanId")
                    if cb.get("vlanIdRaw") is None:
                        add("warning", "VLAN", ied["name"], o, "VLAN-ID not defined (frames will be untagged or use the device default)")
                    elif v is None:
                        add("error", "VLAN", ied["name"], o, f"VLAN-ID '{cb['vlanIdRaw']}' is not a valid hex value")
                    elif not 0 <= v <= 0xFFF:
                        add("error", "VLAN", ied["name"], o, f"VLAN-ID {v} is outside 0–4095")
                    elif v == 0:
                        add("info", "VLAN", ied["name"], o, "VLAN-ID 0: priority-tagged only, switch uses the port's native VLAN")
                    elif v == 0xFFF:
                        add("error", "VLAN", ied["name"], o, "VLAN-ID 4095 (0xFFF) is reserved")
                    elif cb.get("vlanIdRaw") and len(cb["vlanIdRaw"]) != 3:
                        add("info", "VLAN", ied["name"], o,
                            f"VLAN-ID '{cb['vlanIdRaw']}' is not 3 hex digits; it is read as hex = {v} decimal")
                    p = cb.get("vlanPriority")
                    if p is not None and not 0 <= p <= 7:
                        add("error", "VLAN", ied["name"], o, f"VLAN-PRIORITY {p} is outside 0–7")
                    a = cb.get("appId")
                    lo, hi = (0x0000, 0x3FFF) if kind == "GOOSE" else (0x4000, 0x7FFF)
                    if a is None:
                        add("error", kind, ied["name"], o, "APPID missing or not hex")
                    elif not lo <= a <= hi:
                        add("warning", kind, ied["name"], o, f"APPID 0x{a:04X} is outside the recommended {kind} range 0x{lo:04X}–0x{hi:04X}")
                    else:
                        appids[(kind, a)].append(o)
                    mac = cb.get("mac")
                    if not mac:
                        add("error", kind, ied["name"], o, "MAC-Address missing")
                    else:
                        first_octet = int(mac[:2], 16) if len(mac) >= 2 else 0
                        if not first_octet & 1:
                            add("error", kind, ied["name"], o, f"MAC {mac} is not a multicast address")
                        pref = "01-0C-CD-01-" if kind == "GOOSE" else "01-0C-CD-04-"
                        if not mac.startswith(pref) or mac[12:14] not in ("00", "01"):
                            add("warning", kind, ied["name"], o, f"MAC {mac} is outside the IEC 61850 recommended range {pref}00-00 … {pref}01-FF")
                        macs[mac].append((o, v))
                    if not cb.get("datSet"):
                        add("error", "DataSet", ied["name"], o, "control block has no DataSet")
                    elif cb["datSet"] not in ied["datasets"]:
                        add("error", "DataSet", ied["name"], o, f"DataSet {cb['datSet']} does not exist")
                    elif not ied["datasets"][cb["datSet"]]["fcdas"]:
                        add("warning", "DataSet", ied["name"], o, "DataSet is empty")
                    if cb.get("confRev") in (0, None):
                        add("warning", kind, ied["name"], o, "confRev is 0 or missing")
                    if cb.get("id"):
                        goids[(kind, cb["id"])].append(o)
                    if kind == "GOOSE" and cb.get("minTime") and cb.get("maxTime") and cb["minTime"] > cb["maxTime"]:
                        add("error", "GOOSE", ied["name"], o, f"MinTime {cb['minTime']} > MaxTime {cb['maxTime']}")
            for ds in ied["datasets"].values():
                for f, ref in zip(ds["fcdas"], ds["members"]):
                    if not self._fcda_exists(ied, f):
                        add("error", "DataSet", ied["name"], ds["ref"], f"FCDA {ref} does not exist in the data model")
        for (kind, a), lst in appids.items():
            if len(lst) > 1:
                add("warning", kind, "", ", ".join(lst), f"APPID 0x{a:04X} is used by {len(lst)} control blocks")
        for mac, lst in macs.items():
            if len(lst) > 1:
                same_vlan = len({v for _, v in lst}) < len(lst)
                add("error" if same_vlan else "warning", "Addressing", "", ", ".join(o for o, _ in lst),
                    f"Destination MAC {mac} is shared by {len(lst)} control blocks" + (" in the same VLAN" if same_vlan else ""))
        for (kind, gid), lst in goids.items():
            if len(lst) > 1:
                add("warning", kind, "", ", ".join(lst), f"{'GoID' if kind == 'GOOSE' else 'smvID'} '{gid}' is not unique")

        for ied in self.ieds.values():
            if ied.get("profile") != "ABB CI868":
                continue
            goose_src = sorted({e["iedName"] for e in ied["extrefs"] if e.get("iedName")
                                and (e.get("serviceType") == "GOOSE" or "$GO$" in (e.get("_publisherCb") or ""))})
            mms_srv = sorted({o["name"] for o in self.ieds.values() if o is not ied
                              and any(c["client"] == ied["name"] for c in o["rcbClients"])})
            both = sorted(set(goose_src) | set(mms_srv))
            L = CI868_LIMITS
            add("info", "CI868", ied["name"], ied["name"],
                f"CI868 module load: GOOSE from {len(goose_src)} IEDs, MMS reports from {len(mms_srv)} IEDs, "
                f"{len(both)} different IEDs in total")
            if len(goose_src) > L["goose"]:
                add("error", "CI868", ied["name"], ied["name"],
                    f"subscribes GOOSE from {len(goose_src)} IEDs – CI868A supports at most {L['goose']}")
            if len(mms_srv) > L["mms"]:
                add("error", "CI868", ied["name"], ied["name"],
                    f"is MMS report client of {len(mms_srv)} IEDs – CI868A supports at most {L['mms']}")
            if goose_src and mms_srv and len(both) > L["combined"]:
                add("warning", "CI868", ied["name"], ied["name"],
                    f"uses GOOSE and MMS with {len(both)} different IEDs – the CI868A data sheet allows "
                    f"{L['combined']} IEDs when both protocols are combined; split the IEDs over more modules")
            if not ied["ip"]:
                add("error", "CI868", ied["name"], ied["name"], "CI868 has no IP address in the Communication section")

        cbmap = self.cb_by_ref()
        for ied in self.ieds.values():
            for e in ied["extrefs"]:
                if not e.get("iedName"):
                    continue
                desc = f"{e.get('iedName')}/{e.get('ldInst', '')}/{e.get('prefix', '')}{e.get('lnClass', '')}{e.get('lnInst', '')}.{e.get('doName', '')}{('.' + e['daName']) if e.get('daName') else ''}"
                if e["iedName"] not in self.ieds:
                    add("error", "Subscription", ied["name"], desc, f"subscribes to unknown IED '{e['iedName']}'")
                    continue
                pcb = e.get("_publisherCb")
                if pcb is None:
                    if e.get("serviceType") in ("GOOSE", "SMV") or e.get("srcCBName"):
                        add("warning", "Subscription", ied["name"], desc, "signal is not in any published GOOSE/SV dataset")
                elif pcb.startswith("?"):
                    add("error", "Subscription", ied["name"], desc, f"source control block '{pcb[1:]}' not found in {e['iedName']}")
                else:
                    cb = cbmap.get(pcb)
                    if cb and ied["subnet"] and cb.get("subnet") and ied["subnet"] != cb["subnet"]:
                        add("warning", "Subscription", ied["name"], desc,
                            f"publisher {pcb} is on subnetwork {cb['subnet']}, subscriber on {ied['subnet']}")
        return F

    def _fcda_exists(self, ied, f):
        T = self.templates
        if not T["LNodeType"]:
            return True
        for ld in ied["lds"]:
            if ld["inst"] != f.get("ldInst"):
                continue
            for ln in ld["lns"]:
                if ln["lnClass"] == f.get("lnClass") and (ln["inst"] or "") == (f.get("lnInst") or "") \
                        and (ln["prefix"] or "") == (f.get("prefix") or ""):
                    lnt = T["LNodeType"].get(ln["lnType"])
                    if not lnt:
                        return False
                    if not f.get("doName"):
                        return True
                    parts = f["doName"].split(".")
                    do = next((d for d in lnt["dos"] if d["name"] == parts[0]), None)
                    if not do:
                        return False
                    dot = T["DOType"].get(do["type"])
                    for sdo in parts[1:]:
                        it = next((i for i in (dot or {}).get("items", []) if i["name"] == sdo and i["kind"] == "SDO"), None)
                        if not it:
                            return False
                        dot = T["DOType"].get(it["type"])
                    if not f.get("daName") or not dot:
                        return dot is not None
                    da_parts = f["daName"].split(".")
                    da = next((i for i in dot["items"] if i["name"] == da_parts[0] and i["kind"] == "DA"), None)
                    if not da:
                        return False
                    typ = da.get("type")
                    for b in da_parts[1:]:
                        bdas = T["DAType"].get(typ) or []
                        bd = next((x for x in bdas if x["name"] == b), None)
                        if not bd:
                            return False
                        typ = bd.get("type")
                    return True
            return False
        return False
