"""Page 1 - Network Investigation: upload a PCAP, detect threats, list incidents."""
from __future__ import annotations

import os

import networkx as nx
import pandas as pd
import html
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from sqlalchemy import func

from config import DEMO_DIR
from core.ingest_service import analyze_upload
from database.models import Alert, CaptureMeta, Flow, Incident, Packet
from evidence.integrity import sha256_hex
from ui.components import guard, incident_picker, metric, plot, table
from ui.state import request_incident, request_page
from ui.theme import AMBER, SEVERITY_COLORS, TEAL, style_fig

THREAT_TYPES = ["Port Scan", "SSH Brute Force", "Suspicious DNS"]


def threat_label(rule_name: str) -> str:
    """Short, student-friendly name for a detection rule."""
    r = (rule_name or "").lower()
    if "port scan" in r:
        return "Port Scan"
    if "ssh" in r or "brute" in r:
        return "SSH Brute Force"
    if "dns" in r or "typosquat" in r:
        return "Suspicious DNS"
    return rule_name or "Other"


def _ingest(svc, filename: str, data: bytes) -> None:
    with st.spinner("Analyzing packets and running the threat detectors..."):
        res = analyze_upload(svc, filename, data)
    st.session_state["_pending_capture"] = res["capture_id"]
    incs = svc.incidents.list(res["capture_id"])
    if incs:
        request_incident(incs[0]["id"])
    if res["duplicate"]:
        st.session_state["_flash"] = ("info", "This capture was already analyzed; showing the existing results.")
    else:
        c = res["counts"]
        st.session_state["_flash"] = ("success",
            f"Analyzed {res['packets']} packets. Port scans: {c['port_scan']}, SSH brute force: "
            f"{c['ssh_bruteforce']}, suspicious DNS: {c['dns_typosquat']}, incidents created: {c['incidents']}.")
    st.rerun()


def _attack_graph(alerts, incidents):
    """Source -> target -> service graph (kept under Advanced Packet Details)."""
    G = nx.DiGraph()
    for a in alerts:
        risk = incidents.get(a.incident_id, "LOW")
        src, tgt = a.source_ip or "unknown", a.target_ip or "unknown"
        G.add_node(src, kind="source", risk=risk); G.add_node(tgt, kind="target", risk=risk)
        G.add_edge(src, tgt, rule=a.rule_name)
        if a.target_port:
            port = f"{tgt}:{a.target_port}"
            G.add_node(port, kind="service", risk=risk); G.add_edge(tgt, port, rule=a.rule_name)
    pos = nx.spring_layout(G, seed=7, k=0.9)
    ex, ey = [], []
    for u, v in G.edges():
        ex += [pos[u][0], pos[v][0], None]; ey += [pos[u][1], pos[v][1], None]
    nodes = list(G.nodes())
    fig = go.Figure([
        go.Scatter(x=ex, y=ey, mode="lines", line=dict(width=1.2, color="#3b516e"), hoverinfo="none"),
        go.Scatter(x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text", text=nodes,
                   textposition="top center", textfont=dict(size=10),
                   marker=dict(size=[26 if G.nodes[n]["kind"] == "source" else 18 for n in nodes],
                               color=[SEVERITY_COLORS.get(G.nodes[n]["risk"], TEAL) for n in nodes],
                               line=dict(width=1, color="#e8f1fb")),
                   hovertext=[f"{n} ({G.nodes[n]['kind']}, {G.nodes[n]['risk']})" for n in nodes], hoverinfo="text")])
    fig.update_layout(showlegend=False, title="Attack graph: source, target and service",
                      xaxis=dict(visible=False), yaxis=dict(visible=False))
    return style_fig(fig, 340)


def _bar(df: pd.DataFrame, x: str, y: str, title: str, color: str, xtitle: str, ytitle: str):
    fig = px.bar(df, x=x, y=y, title=title, text=y, color_discrete_sequence=[color])
    fig.update_traces(textposition="outside", cliponaxis=False)
    fig.update_layout(xaxis_title=xtitle, yaxis_title=ytitle, bargap=0.45)
    return style_fig(fig, 280)


def _upload_section(svc, has_capture: bool) -> None:
    box = st.expander("Analyze a different capture", expanded=False) if has_capture else st.container()
    with box:
        c1, c2 = st.columns([3, 2])
        with c1:
            up = st.file_uploader("Upload a PCAP / PCAPNG file", type=["pcap", "pcapng"], key="pcap_upload")
            if up is not None and st.button("Analyze capture", type="primary"):
                with guard("analyze the capture"):
                    _ingest(svc, up.name, up.getvalue())
        with c2:
            st.markdown("**No PCAP file?**")
            demo = DEMO_DIR / "attack_demo.pcap"
            st.caption("Use the bundled demo capture (port scan, SSH brute force, suspicious DNS).")
            if demo.is_file() and st.button("Load bundled demo capture"):
                with guard("load the demo capture"):
                    _ingest(svc, demo.name, demo.read_bytes())


def render(svc):
    st.markdown("""<div class="ns-hero"><div class="ns-hero-icons">🛡️ &nbsp; ◈</div><div class="ns-hero-title">NETSENTINEL</div><div class="ns-hero-sub">Automated Network Forensics Platform</div></div>""", unsafe_allow_html=True)
    st.title("Network Investigation")
    st.caption("Upload a PCAP file to find suspicious network activity.")

    if "_flash" in st.session_state:
        kind, msg = st.session_state.pop("_flash")
        getattr(st, kind)(msg)

    with svc.db.session_scope() as s:
        caps = s.query(CaptureMeta).order_by(CaptureMeta.id.desc()).all()
        cap_opts = {c.id: f"#{c.id}  {c.filename}  ({c.ingested_at:%Y-%m-%d %H:%M})" for c in caps}

    _upload_section(svc, bool(cap_opts))
    if not cap_opts:
        st.info("No capture has been analyzed yet. Upload a PCAP above or load the bundled demo capture.")
        return

    if "_pending_capture" in st.session_state:
        st.session_state["network_capture_id"] = st.session_state.pop("_pending_capture")
    if st.session_state.get("network_capture_id") not in cap_opts:
        st.session_state["network_capture_id"] = next(iter(cap_opts))
    if len(cap_opts) > 1:
        cid = st.selectbox("Capture", list(cap_opts), format_func=lambda i: cap_opts[i], key="network_capture_id")
    else:
        cid = st.session_state["network_capture_id"]

    with svc.db.session_scope() as s:
        cap = s.get(CaptureMeta, cid)
        total_packets = cap.total_packets
        cap_path, cap_sha = cap.filepath, cap.file_sha256
        protocols = dict(s.query(Packet.protocol, func.count()).filter(Packet.capture_id == cid).group_by(Packet.protocol).all())
        ips = {ip for (ip,) in s.query(Packet.src_ip).filter(Packet.capture_id == cid).distinct() if ip}
        ips |= {ip for (ip,) in s.query(Packet.dst_ip).filter(Packet.capture_id == cid).distinct() if ip}
        alerts = s.query(Alert).filter(Alert.capture_id == cid).order_by(Alert.window_start).all()
        for a in alerts:
            s.expunge(a)
        inc_risk = {i.id: i.risk_level for i in s.query(Incident).filter(Incident.capture_id == cid)}
    incidents = svc.incidents.list(cid)
    top_risk = max([i["risk_score"] for i in incidents], default=0)

    # ---- four metrics ---------------------------------------------------------
    cols = st.columns(4)
    risk_tone = "red" if top_risk >= 70 else "amber" if top_risk >= 40 else "green"
    for col, (label, value, tone) in zip(cols, [
            ("Total Packets", f"{total_packets:,}", ""),
            ("Unique IP Addresses", len(ips), ""),
            ("Threats Detected", len(alerts), "red" if alerts else "green"),
            ("Overall Risk Score", f"{top_risk:.0f} / 100", risk_tone)]):
        with col:
            metric(label, value, tone)
    st.write("")

    # ---- two measured summary charts ------------------------------------------
    left, right = st.columns(2)
    with left:
        proto = pd.DataFrame({"Protocol": [(k or "Other") for k in protocols], "Packets": list(protocols.values())})
        plot(_bar(proto.sort_values("Packets", ascending=False), "Protocol", "Packets", "Protocol Distribution",
                  TEAL, "Protocol", "Number of packets"), "proto_chart")
    with right:
        counts = {t: 0 for t in THREAT_TYPES}
        for a in alerts:
            name = threat_label(a.rule_name)
            counts[name] = counts.get(name, 0) + 1
        threats = pd.DataFrame({"Threat": list(counts), "Detections": list(counts.values())})
        active = threats[threats["Detections"] > 0]
        if not active.empty:
            fig = go.Figure(go.Pie(labels=active["Threat"], values=active["Detections"],
                                   hole=0.32, sort=False,
                                   marker=dict(colors=[TEAL, AMBER, "#5479BD", "#A57DB7"][:len(active)]),
                                   textinfo="percent+label", hovertemplate="%{label}: %{value} alerts<extra></extra>"))
            fig.update_layout(title="Attack Distribution", showlegend=False)
            plot(style_fig(fig, 280), "threat_pie")
        else:
            st.info("No attack alerts detected for this capture.")

    # ---- traffic time-series from recorded packet timestamps ------------------
    st.subheader("Network Traffic Over Time")
    with svc.db.session_scope() as s:
        timestamps = [t for (t,) in s.query(Packet.timestamp).filter(Packet.capture_id == cid)
                      .order_by(Packet.timestamp).all() if t is not None]
    if timestamps:
        times = pd.to_datetime(pd.Series(timestamps), errors="coerce", utc=True)
        times = times.dropna()
        if not times.empty:
            span = (times.max() - times.min()).total_seconds()
            # Adapt bucket width to capture duration; avoid creating empty years of buckets.
            bucket = "1s" if span <= 120 else ("1min" if span <= 7200 else "1h")
            traffic = pd.Series(1, index=pd.DatetimeIndex(times)).resample(bucket).sum()
            fig = go.Figure(go.Scatter(x=traffic.index, y=traffic.values,
                                       mode="lines+markers", line=dict(color=TEAL, width=2.5),
                                       marker=dict(size=5), fill="tozeroy",
                                       fillcolor="rgba(22,119,131,0.09)",
                                       hovertemplate="%{x}<br>%{y} packets<extra></extra>"))
            fig.update_layout(title="Packet Volume by Time", xaxis_title="Capture time (UTC)",
                              yaxis_title="Packets per interval", showlegend=False)
            fig.update_yaxes(rangemode="tozero")
            plot(style_fig(fig, 300), "traffic_over_time")
            st.caption(f"Packet counts grouped into {bucket} intervals using capture timestamps.")
    else:
        st.caption("No valid packet timestamps available for the traffic chart.")

    # ---- chronological timeline from recorded PCAP alerts ---------------------
    st.subheader("Incident Timeline")
    if alerts:
        for a in sorted(alerts, key=lambda x: x.window_start):
            when = a.window_start.strftime("%Y-%m-%d %H:%M:%S") if hasattr(a.window_start, "strftime") else str(a.window_start)
            source = a.source_ip or "Unknown source"
            target = a.target_ip or "Unknown target"
            st.markdown(f'<div class="ns-timeline"><div class="time">{html.escape(str(when))}</div><div class="event">{html.escape(str(threat_label(a.rule_name)))} · {html.escape(str(a.severity))}</div><div class="route">{html.escape(str(source))} → {html.escape(str(target))}</div></div>', unsafe_allow_html=True)
    else:
        st.caption("No suspicious events detected in this capture.")

    # ---- incident table + selector -------------------------------------------
    st.subheader("Incidents")
    if not incidents:
        st.info("This capture produced no incidents.")
        pick = None
    else:
        by_inc = {}
        for a in alerts:
            by_inc.setdefault(a.incident_id, [])
            name = threat_label(a.rule_name)
            if name not in by_inc[a.incident_id]:
                by_inc[a.incident_id].append(name)
        table([{"Incident": i["code"], "Threat": ", ".join(by_inc.get(i["id"], [])) or "-",
                "Source IP": i["source_ip"], "Risk": f"{i['risk_level']} ({i['risk_score']:.0f})"} for i in incidents])
        pick = incident_picker(svc, "network", "Select an incident to investigate", capture_id=cid)
        d = svc.incidents.get(pick)
        st.caption(f"{d['code']}: {d['classification']}. {d['source_ip']} to {d['target_ip']}.")
        if st.button("Continue to Evidence Vault", type="primary"):
            request_page(1); st.rerun()

    # ---- everything else, in ONE optional section (tabs, not nested expanders) ---
    with st.expander("Advanced Packet Details", expanded=False):
        t_alerts, t_packets, t_flows, t_graph, t_integrity = st.tabs(
            ["Alerts", "Packets", "Flows", "Attack graph", "Integrity check"])
        with t_alerts:
            if pick is None:
                st.caption("No incident selected.")
            else:
                table([{"Threat": threat_label(a["rule"]), "Severity": a["severity"], "Source": a["source"],
                        "Target": f"{a['target']}:{a['port']}" if a["port"] else a["target"], "Start": a["start"],
                        "What was seen": a["description"]} for a in d["alerts"]])
        with t_packets:
            f1, f2, f3 = st.columns(3)
            pf = f1.multiselect("Protocol", sorted(k for k in protocols if k))
            ipf = f2.text_input("IP contains")
            only_inc = f3.checkbox("Only the selected incident", value=False, disabled=pick is None)
            if only_inc and pick is not None:
                table(svc.incidents.related_packets(pick))
            else:
                with svc.db.session_scope() as s:
                    q = s.query(Packet).filter(Packet.capture_id == cid)
                    if pf:
                        q = q.filter(Packet.protocol.in_(pf))
                    if ipf:
                        q = q.filter(Packet.src_ip.like(f"%{ipf}%") | Packet.dst_ip.like(f"%{ipf}%"))
                    rows = [{"Frame": p.frame_number, "Time": p.timestamp, "Src": f"{p.src_ip}:{p.src_port or ''}",
                             "Dst": f"{p.dst_ip}:{p.dst_port or ''}", "Proto": p.protocol,
                             "Flags": "".join(c for c, on in zip("SARFP", (p.tcp_syn, p.tcp_ack, p.tcp_rst, p.tcp_fin, p.tcp_psh)) if on),
                             "DNS": p.dns_query_name, "Bytes": p.frame_len} for p in q.order_by(Packet.timestamp).limit(500)]
                st.caption("Showing up to 500 packets.")
                table(rows)
        with t_flows:
            with svc.db.session_scope() as s:
                rows = [{"Src": f"{f.src_ip}:{f.src_port or ''}", "Dst": f"{f.dst_ip}:{f.dst_port or ''}", "Proto": f.protocol,
                         "Packets": f.packet_count, "Bytes": f.byte_count, "SYN": f.syn_count, "RST": f.rst_count,
                         "Start": f.start_time, "End": f.end_time}
                        for f in s.query(Flow).filter(Flow.capture_id == cid).order_by(Flow.start_time).limit(500)]
            table(rows)
        with t_graph:
            if alerts:
                plot(_attack_graph(alerts, inc_risk), "attack_graph")
            else:
                st.info("No threats were detected, so there is no attack graph.")
        with t_integrity:
            st.caption("Re-hash the stored capture and re-check the HMAC of every stored row.")
            if st.button("Run integrity check"):
                with guard("check database integrity"):
                    if os.path.exists(cap_path):
                        with open(cap_path, "rb") as fh:
                            same = sha256_hex(fh.read()) == cap_sha
                        (st.success if same else st.error)("Stored PCAP SHA-256 matches the ingestion baseline." if same
                                                           else "Stored PCAP SHA-256 does NOT match the ingestion baseline.")
                    else:
                        st.error("The stored original capture file is missing from disk.")
                    rep = svc.db.verify_integrity()
                    (st.success if rep["ok"] else st.error)(f"Row-level HMAC check: {rep['checked']:,} rows verified, {len(rep['failed'])} failed.")
