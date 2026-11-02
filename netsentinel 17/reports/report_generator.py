"""Builds the forensic PDF from REAL stored investigation data (no placeholder content)."""
from __future__ import annotations

import io
import json
from collections import Counter
from typing import Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, PolyLine, Wedge
from xml.sax.saxutils import escape

from database.db_manager import DBManager
from database.models import (CaptureMeta, CryptoRun, EvidenceItem, Flow, Packet, SimulationRecord,
                             VerificationRecord, utcnow)
from evidence import audit

NAVY, TEAL, RED, GREEN = colors.HexColor("#0b1f33"), colors.HexColor("#0e8c9c"), colors.HexColor("#c62828"), colors.HexColor("#2e7d32")


def collect(db: DBManager, incident_mgr, incident_id: int) -> Dict:
    inc = incident_mgr.get(incident_id)
    if inc is None:
        raise ValueError(f"Incident {incident_id} not found.")
    with db.session_scope() as s:
        cap_id = inc["capture"]["id"]
        proto = Counter(p for (p,) in s.query(Packet.protocol).filter(Packet.capture_id == cap_id))
        ips = {ip for (ip,) in s.query(Packet.src_ip).filter(Packet.capture_id == cap_id) if ip}
        ips |= {ip for (ip,) in s.query(Packet.dst_ip).filter(Packet.capture_id == cap_id) if ip}
        evidence = [{"code": e.code, "filename": e.filename, "type": e.evidence_type, "sha256": e.sha256,
                     "size": e.size_bytes, "status": e.status, "registered_at": e.registered_at,
                     "source": e.source} for e in s.query(EvidenceItem).filter_by(incident_id=incident_id).order_by(EvidenceItem.id)]
        ver = []
        for v in s.query(VerificationRecord).filter_by(incident_id=incident_id).order_by(VerificationRecord.id):
            ver.append({"evidence": f"EV{v.evidence_id:03d}", "subject": v.subject, "sim": v.simulation_id,
                        "sha": v.sha_match, "hmac": v.hmac_ok, "rsa": v.rsa_ok, "bits": v.changed_bits,
                        "pct": v.avalanche_pct, "verdict": v.verdict, "at": v.verified_at})
        sims = [{"id": r.id, "evidence": f"EV{r.evidence_id:03d}", "method": r.method, "file": r.modified_filename,
                 "sha256": r.modified_sha256, "at": r.created_at,
                 "summary": json.loads(r.details_json or "{}").get("summary", "")}
                for r in s.query(SimulationRecord).filter_by(incident_id=incident_id).order_by(SimulationRecord.id)]
        runs = {}
        for kind in ("benchmark", "performance_profile", "avalanche", "collision", "rsa_security"):
            r = s.query(CryptoRun).filter_by(kind=kind).order_by(CryptoRun.id.desc()).first()
            if r:
                runs[kind] = {"at": r.created_at, "data": json.loads(r.result_json)}
        chain_ok, bad, n = audit.verify_chain(s)
    return {"incident": inc, "protocols": dict(proto), "unique_ips": len(ips), "evidence": evidence,
            "verifications": ver, "simulations": sims, "crypto": runs, "audit": {"ok": chain_ok, "entries": n},
            "generated_at": utcnow()}


def _tbl(rows: List[List], widths=None, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("FONTSIZE", (0, 0), (-1, -1), 7.5), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#9aa7b4")),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6f9")])]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return t


# Native vector drawings keep the PDF self-contained; no Plotly/Kaleido dependency.
CHART_BLUE = colors.HexColor("#367FA3")
CHART_PURPLE = colors.HexColor("#7775B7")
CHART_GOLD = colors.HexColor("#D6A04A")
CHART_COLORS = [CHART_BLUE, CHART_PURPLE, CHART_GOLD]


def _bar_chart(title, labels, values, width=490, height=190, log=False, unit=""):
    import math
    fig = Drawing(width, height)
    fig.add(String(8, height-15, title, fontName="Helvetica-Bold", fontSize=10, fillColor=NAVY))
    left, bottom, top = 42, 37, height-30
    fig.add(Line(left, bottom, width-8, bottom, strokeColor=colors.HexColor("#9aa7b4")))
    if not values:
        return fig
    transformed = [math.log10(1+max(0,float(v))) if log else max(0,float(v)) for v in values]
    max_v = max(transformed) or 1
    slot = (width-left-12)/len(values)
    for i,(name,v,trans) in enumerate(zip(labels,values,transformed)):
        bar_w = min(52,slot*.65)
        x = left + slot*i+(slot-bar_w)/2
        h = (top-bottom-12)*trans/max_v
        fig.add(Rect(x,bottom,bar_w,max(0.7,h),fillColor=CHART_COLORS[i%len(CHART_COLORS)],strokeColor=None))
        fig.add(String(x+bar_w/2,bottom+h+5,f"{float(v):.2f}{unit}",textAnchor="middle",fontSize=7,fillColor=NAVY))
        fig.add(String(x+bar_w/2,18,str(name)[:17],textAnchor="middle",fontSize=7,fillColor=NAVY))
    if log:
        fig.add(String(width-7,height-14,"log-scaled bars",textAnchor="end",fontSize=7,fillColor=colors.grey))
    return fig


def _line_chart(title, labels, series, width=490, height=205, log=False):
    import math
    fig=Drawing(width,height)
    fig.add(String(8,height-14,title,fontName="Helvetica-Bold",fontSize=10,fillColor=NAVY))
    left,bottom,top,right=42,37,height-38,width-14
    fig.add(Line(left,bottom,right,bottom,strokeColor=colors.grey))
    fig.add(Line(left,bottom,left,top,strokeColor=colors.grey))
    values=[max(0,float(v)) for _,vals in series for v in vals]
    if not values or not labels: return fig
    f=lambda v: math.log10(1+max(0,float(v))) if log else max(0,float(v))
    vmax=max(f(v) for v in values) or 1
    for j,(name,vals) in enumerate(series):
        color=CHART_COLORS[j%3]
        points=[]
        for i,v in enumerate(vals):
            x=left+(right-left)*i/max(1,len(labels)-1)
            y=bottom+(top-bottom-9)*f(v)/vmax
            points.extend((x,y))
            fig.add(Rect(x-2,y-2,4,4,fillColor=color,strokeColor=None))
        if len(points)>=4: fig.add(PolyLine(points,strokeColor=color,strokeWidth=1.8))
        fig.add(Rect(left+j*148,height-29,9,6,fillColor=color,strokeColor=None))
        fig.add(String(left+13+j*148,height-29,str(name)[:21],fontSize=7,fillColor=NAVY))
    for i,name in enumerate(labels):
        if len(labels)>12 and i % max(1,(len(labels)+7)//8) != 0 and i != len(labels)-1:
            continue
        x=left+(right-left)*i/max(1,len(labels)-1)
        fig.add(String(x,19,str(name)[:12],textAnchor="middle",fontSize=7,fillColor=NAVY))
    if log: fig.add(String(right,8,"log scale",textAnchor="end",fontSize=6,fillColor=colors.grey))
    return fig


def _heatmap(title, labels, names, values, unit, width=490, height=153):
    import math
    fig=Drawing(width,height)
    fig.add(String(8,height-14,title,fontName="Helvetica-Bold",fontSize=10,fillColor=NAVY))
    left,top=112,height-34
    n=max(1,len(labels)); cellw=(width-left-12)/n; cellh=30
    maximum=max([float(v) for row in values for v in row] or [1]) or 1
    for j,(name,row) in enumerate(zip(names,values)):
        y=top-(j+1)*cellh
        fig.add(String(left-7,y+11,name[:21],textAnchor="end",fontSize=7,fillColor=NAVY))
        for i,v in enumerate(row):
            ratio=math.log1p(max(0,float(v)))/math.log1p(maximum)
            color=colors.Color(.86-.65*ratio,.93-.68*ratio,.98-.48*ratio)
            x=left+i*cellw
            fig.add(Rect(x+1,y+1,cellw-2,cellh-2,fillColor=color,strokeColor=colors.white))
            fig.add(String(x+cellw/2,y+11,f"{float(v):.1f}{unit}",textAnchor="middle",fontSize=7,
                           fillColor=colors.white if ratio>.66 else NAVY))
    for i,label in enumerate(labels):
        fig.add(String(left+(i+.5)*cellw,top+6,str(label),textAnchor="middle",fontSize=7,fillColor=NAVY))
    fig.add(String(left,8,"Cell shading uses a nonlinear scale; printed values are unmodified.",fontSize=7,fillColor=colors.grey))
    return fig


def _report_charts(d, f, P, h2, small):
    from collections import Counter
    inc=d["incident"]
    alerts=inc.get("alerts",[])
    counts=Counter(str(a.get("rule","Unknown")) for a in alerts)
    f.append(PageBreak())
    f.append(P("8. Investigation charts",h2))
    if counts:
        timeline=[]
        for a in sorted(alerts,key=lambda item: str(item.get("start") or ""))[:15]:
            timeline.append([str(a.get("start") or "unknown")[:19],str(a.get("rule") or "Unknown")[:28],
                             str(a.get("severity") or ""),str(a.get("source") or "")[:22]])
        if timeline:
            f.append(P("Incident timeline (chronological alerts)",small))
            f.append(_tbl([["Timestamp (UTC)","Detection","Severity","Source IP"]]+timeline,
                          [38*mm,65*mm,23*mm,44*mm]))
        names=list(counts)[:7]
        f.append(_bar_chart("Detected alerts by rule",names,[counts[n] for n in names]))
        f.append(P("Counts are derived from alerts associated with this incident.",small))
    else:
        f.append(P("No incident alerts available for charting.",small))
    f.append(PageBreak())
    f.append(P("9. Performance and security analysis charts",h2))
    c=d.get("crypto",{})
    profile=c.get("performance_profile",{}).get("data")
    if profile and profile.get("results"):
        r=profile["results"]
        keys=[k for k in ("sha256","hmac","rsa") if r.get(k)]
        names={"sha256":"SHA-256","hmac":"HMAC-SHA256","rsa":"RSA-2048 sign"}
        labels=[f"{v['size_bytes']/1024:g} KB" if v['size_bytes']<1048576 else f"{v['size_bytes']/1048576:g} MB" for v in r[keys[0]]]
        series=[(names[k],[x["median_ms"] for x in r[k]]) for k in keys]
        f.append(_line_chart("Scalability: execution time vs input size (ms)",labels,series,log=True))
        f.append(_bar_chart("Execution time at largest input (ms)",[names[k] for k in keys],[r[k][-1]["median_ms"] for k in keys],log=True))
        bulk=[k for k in ("sha256","hmac") if r.get(k)]
        f.append(_bar_chart("Bulk-data throughput (MB/s)",[names[k] for k in bulk],[r[k][-1].get("throughput_mb_s") or 0 for k in bulk]))
        f.append(P("RSA signing is measured separately; its rate is signatures/second, not bulk throughput.",small))
        for key,title,unit in (("cpu_percent_one_core","CPU utilization (one-core equivalent)","%"),
                               ("peak_python_kib","Peak Python-tracked memory"," KiB")):
            f.append(_heatmap(title,labels,[names[k] for k in keys],[[v[key] for v in r[k]] for k in keys],unit))
        f.append(P("CPU values are process CPU time / wall time. Memory is Python-tracked allocation, not total system RAM. "
                   "Benchmarks are independent of the selected incident.",small))
    elif "benchmark" in c:
        b=c["benchmark"]["data"]
        if b.get("sha256") and b.get("hmac"):
            f.append(_line_chart("Hashing time vs input size (ms)",
                     [x["label"].replace("generated ","") for x in b["sha256"]],
                     [("SHA-256",[x["median_ms"] for x in b["sha256"]]),
                      ("HMAC-SHA256",[x["median_ms"] for x in b["hmac"]])],log=True))
        f.append(P("Run Detailed Performance Comparison for CPU, memory, throughput and RSA scalability charts.",small))
    else:
        f.append(P("No performance measurements are available. Run the performance comparison before generating this report.",small))
    if "avalanche" in c:
        a=c["avalanche"]["data"]
        changed=int(a["differing_bits"])
        f.append(_bar_chart("SHA-256 avalanche: changed vs unchanged bits",["Changed","Unchanged"],[changed,256-changed]))
        trials=a.get("trial_changed_bits") or []
        if trials:
            f.append(_line_chart("SHA-256 avalanche across single-bit trials",[str(i+1) for i in range(len(trials))],
                                 [("Changed bits",trials)]))
    if "collision" in c:
        x=c["collision"]["data"]
        f.append(_bar_chart("Observed collisions: full vs truncated SHA-256",
                            ["SHA-256",f"Truncated {x['truncated']['bits']}-bit"],
                            [x["observed_collisions"],x["truncated"]["observed_collisions"]]))
        f.append(P("Observed collisions in a finite experiment do not establish a cryptographic security proof.",small))
    if "rsa_security" in c:
        tests=c["rsa_security"]["data"].get("tests",[])
        if tests:
            f.append(_bar_chart("RSA-2048 signature verification checks",
                      [str(t["test"])[:15] for t in tests],[1 if t["passed"] else 0 for t in tests]))
            f.append(P("Bar height 1 means the observed result matched the expected verification outcome; "
                       "it does not mean every signature was accepted.",small))
    if not any(k in c for k in ("avalanche","collision","rsa_security")):
        f.append(P("No security experiments are available. Run Security Experiments before generating this report.",small))


def build_pdf(d: Dict) -> bytes:
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=NAVY, fontSize=19)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=TEAL, fontSize=12.5, spaceBefore=12)
    P = lambda t, st=body: Paragraph(escape(str(t)), st)
    inc, cap = d["incident"], d["incident"]["capture"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"NetSentinel Network Forensic Analysis Report {inc['code']}",
                            author="NetSentinel")
    W = A4[0] - 32 * mm
    f = []

    f += [P("NetSentinel Network Forensic Analysis Report", h1),
          P(f"{inc['code']}: {inc['title']}"), P(f"Generated (UTC): {d['generated_at']:%Y-%m-%d %H:%M:%S}", small),
          P("This PDF is accompanied by a DETACHED RSA-2048-PSS (SHA-256) signature file. It is not an embedded PDF signature.", small)]

    f += [P("1. Incident summary", h2), _tbl([
        ["Field", "Value"], ["Incident", inc["code"]], ["Classification", inc["classification"]],
        ["Basis", inc["classification_reason"]], ["Risk score", f"{inc['risk_score']:.0f}/100 ({inc['risk_level']})"],
        ["Source IP", inc["source_ip"]], ["Target IP", inc["target_ip"]], ["Window", f"{inc['start']} to {inc['end']}"],
        ["Detected threats", ", ".join(inc["detected_threats"])],
        ["Suspicious domains", ", ".join(inc["suspicious_domains"]) or "none"],
        ["Summary", Paragraph(escape(inc["summary"] or ""), small)]], [38 * mm, W - 38 * mm])]

    f += [P("2. Traffic analysis", h2), _tbl([
        ["Capture file", "SHA-256", "Packets", "Flows", "Unique IPs"],
        [cap["filename"], Paragraph(cap["sha256"], small), cap["packets"], cap["flows"], d["unique_ips"]]],
        [38 * mm, 70 * mm, 20 * mm, 20 * mm, W - 148 * mm]), Spacer(1, 4),
        _tbl([["Protocol", "Packets"]] + [[k or "unknown", v] for k, v in sorted(d["protocols"].items(), key=lambda kv: -kv[1])[:12]],
             [60 * mm, 30 * mm])]

    f += [P("3. Threat findings", h2), _tbl(
        [["Rule", "Severity", "Source", "Target", "Description"]] +
        [[Paragraph(escape(a["rule"]), small), a["severity"], a["source"], f"{a['target']}:{a['port']}" if a["port"] else a["target"],
          Paragraph(escape(a["description"]), small)] for a in inc["alerts"]],
        [38 * mm, 18 * mm, 24 * mm, 28 * mm, W - 108 * mm])]

    f += [P("4. Evidence register", h2)]
    if d["evidence"]:
        f += [_tbl([["ID", "File", "Type", "SHA-256 (reference)", "Status"]] +
                   [[e["code"], Paragraph(escape(e["filename"]), small), e["type"], Paragraph(e["sha256"], small), e["status"]] for e in d["evidence"]],
                   [14 * mm, 40 * mm, 14 * mm, W - 86 * mm, 18 * mm])]
    else:
        f += [P("No evidence has been registered for this incident.")]

    f += [P("5. Integrity verification results", h2)]
    if d["verifications"]:
        f += [_tbl([["Evidence", "Subject", "SHA-256", "HMAC", "RSA-PSS", "Bits changed", "Verdict"]] +
                   [[v["evidence"], Paragraph(escape(v["subject"] + (f" (SIM{v['sim']:03d}, SIMULATED)" if v["sim"] else "")), small),
                     "match" if v["sha"] else "MISMATCH", "valid" if v["hmac"] else "INVALID",
                     "valid" if v["rsa"] else "INVALID", f"{v['bits']}/256 ({v['pct']:.1f}%)", v["verdict"]]
                    for v in d["verifications"]], [16 * mm, 44 * mm, 18 * mm, 16 * mm, 18 * mm, 28 * mm, W - 140 * mm])]
    else:
        f += [P("No verification has been run yet.")]

    f += [P("6. Tampering analysis (test modifications)", h2)]
    if d["simulations"]:
        f += [P("Changes were applied to copies; original evidence was preserved.", small),
              _tbl([["Sim", "Evidence", "Method", "What changed"]] +
                   [[f"SIM{x['id']:03d}", x["evidence"], x["method"], Paragraph(escape(x["summary"]), small)] for x in d["simulations"]],
                   [16 * mm, 18 * mm, 40 * mm, W - 74 * mm])]
    else:
        f += [P("No tampering simulations were performed.")]

    f += [P("7. Cryptographic performance and security findings", h2)]
    c = d["crypto"]
    if "benchmark" in c:
        b = c["benchmark"]["data"]
        rows = [["Operation", "Input", "Median (ms)"]]
        rows += [["SHA-256", x["label"], f"{x['median_ms']:.4f}"] for x in b["sha256"]]
        rows += [["HMAC-SHA256", x["label"], f"{x['median_ms']:.4f}"] for x in b["hmac"]]
        r = b["rsa"]
        rows += [["RSA-2048-PSS sign", f"{r['message_size']} B", f"{r['sign']['median_ms']:.3f}"],
                 ["RSA-2048-PSS verify", f"{r['message_size']} B", f"{r['verify']['median_ms']:.3f}"],
                 ["RSA-2048 key generation", "(separate)", f"{r['keygen']['median_ms']:.1f}"]]
        f += [P(f"Benchmarks ({c['benchmark']['at']:%Y-%m-%d %H:%M} UTC, {b['repeats']} timed runs each, median reported):", small),
              _tbl(rows, [45 * mm, 60 * mm, 30 * mm])]
    else:
        f += [P("Performance benchmarks were not run.")]
    if "avalanche" in c:
        a = c["avalanche"]["data"]
        f += [Spacer(1, 4), P(f"SHA-256 avalanche: flipping 1 input bit changed {a['differing_bits']}/256 digest bits "
                              f"({a['avalanche_pct']:.1f}%); mean over {a['trials']} flips = {a['mean_pct']:.1f}% (ideal ~50%).")]
    if "collision" in c:
        k = c["collision"]["data"]
        f += [P(f"Collision experiment: {k['inputs_tested']:,} distinct random inputs gave {k['unique_hashes']:,} unique SHA-256 "
                f"hashes ({k['observed_collisions']} collisions). Zero collisions in a small sample does not prove collision "
                f"resistance; generic collision search on full SHA-256 needs about 2^128 work. A {k['truncated']['bits']}-bit "
                f"truncation gave {k['truncated']['observed_collisions']} collisions in {k['truncated']['inputs']:,} inputs "
                f"(birthday paradox demonstration).")]
    if "rsa_security" in c:
        r = c["rsa_security"]["data"]
        f += [P("RSA-2048 signature behaviour (integrity/verification behaviour, not a proof of resistance to factoring):", small),
              _tbl([["Test", "Expected", "Observed", "Pass"]] +
                   [[t["test"], t["expected"], t["observed"], "yes" if t["passed"] else "NO"] for t in r["tests"]],
                   [80 * mm, 25 * mm, 25 * mm, 15 * mm])]

    _report_charts(d, f, P, h2, small)
    ok = d["audit"]["ok"]
    f += [P("10. Conclusions", h2),
          P(f"Incident {inc['code']} was classified as '{inc['classification']}' with risk {inc['risk_score']:.0f}/100. "
            f"{len(d['evidence'])} evidence item(s) are registered; {len(d['verifications'])} integrity verification(s) and "
            f"{len(d['simulations'])} simulated tampering attempt(s) are recorded. "
            f"The hash-chained audit trail ({d['audit']['entries']} entries) is {'intact' if ok else 'BROKEN'}. "
            "SQLite is not tamper-proof by itself: the HMAC secret and RSA private key must stay outside an attacker's control "
            "for these protections to hold.")]
    def _footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#657588"))
        canvas.drawString(16*mm, 11*mm, "NetSentinel | Forensic Analysis")
        canvas.drawRightString(A4[0]-16*mm, 11*mm, f"Page {document.page}")
        canvas.restoreState()
    doc.build(f, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
