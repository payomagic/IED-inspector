"""Vendor-specific GOOSE receive supervision read over MMS.

ABB Relion 615 / 620 series (REF615, RED620, RET620 …):
    LD0.GSEGGIO1 – GOOSE communication diagnostics (device level, all subscriptions together)
      Alm      receiver alarm: peer time-out, ConfRev mismatch, data set error or NdsCom received
      IntIn1   received messages          IntIn6   state / sequence number errors
      IntIn2   transmitted messages       IntIn7   receiver time-outs
      IntIn3   received state changes     IntIn8   received ConfRev mismatches
      IntIn4   received sequence numbers  IntIn9   received frames with Needs Commissioning
      IntIn5   received frames with test  IntIn10  errors in received data set
    Source: ABB 615 series IEC 61850 Engineering Guide (1MRS756475), "GOOSE supervision".

ABB Relion 670 / 650 series (RED670 …):
    GOOSE receive function blocks (GOOSEBINRCV, GOOSEDPRCV, GOOSEINTRCV, GOOSEMVRCV,
    GOOSESPRCV, GOOSEINTLKRCV, GOOSEXLNRCV, GOOSEVCTRRCV) with outputs DATAVALID/DVALIDn,
    COMMVALID and TEST. How these outputs appear in the MMS data model depends on the
    configuration, so they are found by name (any LN whose name contains 'RCV', any data
    object/attribute named *DataValid*, *DValid*, *CommValid*).

Anything else that looks like receive supervision is listed as a candidate.
"""
import re

from .ber import name_values, to_jsonable

ABB615_LN = re.compile(r"^GSEGGIO\d*$", re.I)
COUNTER = re.compile(r"^int[il]n(\d+)$", re.I)
ABB615_COUNTERS = {
    1: "received messages", 2: "transmitted messages", 3: "received state changes",
    4: "received sequence numbers", 5: "received frames with test bit", 6: "state/sequence number errors",
    7: "receiver time-outs", 8: "received ConfRev mismatches", 9: "received frames with Needs Commissioning",
    10: "errors in received data set"}
RCV_LN = re.compile(r"RCV", re.I)
VALID_NAME = re.compile(r"^(comm_?valid\d*|data_?valid\d*|d_?valid\d*)$", re.I)
CANDIDATE_LN = re.compile(r"(GOOSE|GSE|RCV|SUBSCR|GOSUP)", re.I)


def _leaves(d, path=()):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _leaves(v, path + (k,))
    else:
        yield path, d


def _read_ln(cli, dom, ln, nameset, fcs=("ST", "MX", "SP")):
    out = {}
    for fc in fcs:
        item = f"{ln}${fc}"
        if item not in nameset:
            continue
        try:
            out[fc] = name_values(cli.get_type(dom, item), cli.read(dom, item))
        except Exception:
            pass
    return out


def read_vendor_supervision(cli, dom, names, log):
    nameset = set(names)
    lns = [n for n in names if "$" not in n]
    found = []
    for ln in lns:
        if ABB615_LN.match(ln):
            data = _read_ln(cli, dom, ln, nameset)
            st = data.get("ST") or {}
            alm = (st.get("Alm") or {}).get("stVal") if isinstance(st.get("Alm"), dict) else None
            counters = {}
            for fc in ("ST", "MX"):
                for k, v in (data.get(fc) or {}).items():
                    m = COUNTER.match(k)
                    if m and isinstance(v, dict) and "stVal" in v:
                        counters[int(m.group(1))] = v["stVal"]
            vals = {f"Alm (receiver alarm)": alm}
            for i in sorted(counters):
                vals[f"IntIn{i} – {ABB615_COUNTERS.get(i, '?')}"] = counters[i]
            ok = None if alm is None else (not alm)
            problems = []
            if alm:
                problems.append("GOOSE receiver alarm is active")
            for i, lbl in ((7, "receiver time-outs"), (8, "ConfRev mismatches"), (10, "data set errors"),
                           (9, "Needs Commissioning frames"), (6, "sequence errors")):
                if counters.get(i):
                    problems.append(f"{counters[i]} {lbl}")
            rx = counters.get(1)
            if alm and rx == 0:
                problems.append("nothing received at all (IntIn1 = 0) – typical for a missing VLAN on the switch port, "
                                "multicast filtering or a wrong destination MAC")
            summary = ("receiving all subscribed GOOSE" if ok else "GOOSE reception problem: " + ", ".join(problems)) \
                if ok is not None else "Alm not readable"
            if ok and rx == 0:
                summary = "no GOOSE received yet (IntIn1 = 0) – does this IED subscribe to anything?"
            found.append({"profile": "ABB 615/620 – GSEGGIO", "ld": dom, "ln": ln, "scope": "device",
                          "ok": ok, "summary": summary, "problems": problems, "values": vals,
                          "counters": {str(k): v for k, v in counters.items()}})
            log.append(f"{dom}/{ln}: ABB GOOSE diagnostics – {summary}")
        elif RCV_LN.search(ln):
            data = _read_ln(cli, dom, ln, nameset, ("ST", "MX"))
            vals, comm, dvalid, test = {}, [], [], []
            for fc, tree in data.items():
                for path, v in _leaves(tree):
                    # name of the data object (or attribute) that carries the validity flag
                    label = next((p for p in reversed(path) if VALID_NAME.match(p) or p.lower() == "test"), None)
                    if not label or not isinstance(v, bool):
                        continue
                    key = ".".join(path)
                    vals[key] = v
                    if label.lower().startswith("comm"):
                        comm.append(v)
                    elif label.lower() == "test":
                        test.append(v)
                    else:
                        dvalid.append(v)
            if not vals:
                continue
            problems = []
            if comm and not all(comm):
                problems.append("COMMVALID is low – publisher not received (time-out)")
            if dvalid and not all(dvalid):
                problems.append(f"{dvalid.count(False)} of {len(dvalid)} DATAVALID outputs low (bad quality or no data)")
            if any(test):
                problems.append("TEST is high – publisher is in test mode")
            ok = not any(p for p in problems if "TEST" not in p) if (comm or dvalid) else None
            summary = "communication and data valid" if ok and not problems else "; ".join(problems) or "no validity flags readable"
            found.append({"profile": "ABB 670 – GOOSE receive block", "ld": dom, "ln": ln, "scope": "block",
                          "ok": ok, "summary": summary, "problems": problems, "values": vals})
            log.append(f"{dom}/{ln}: ABB GOOSE receive block – {summary}")
        elif CANDIDATE_LN.search(ln) and not re.match(r"^(LGOS|LSVS)", ln, re.I):
            data = _read_ln(cli, dom, ln, nameset, ("ST",))
            vals = {".".join(p): to_jsonable(v) for p, v in _leaves(data.get("ST") or {})
                    if p and p[-1] in ("stVal", "general")}
            if vals:
                found.append({"profile": "candidate (unknown vendor node)", "ld": dom, "ln": ln, "scope": "unknown",
                              "ok": None, "summary": "looks GOOSE related – check its meaning in the device manual",
                              "problems": [], "values": vals})
    return found
