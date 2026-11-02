"""Session-state helpers and the sidebar (page navigation + the active incident).

Widgets cannot be modified after instantiation within a run, so programmatic changes (e.g. "go to the
Evidence Vault") are written to _pending_* keys and applied at the top of the next run, before the widgets
exist. The active incident lives in session_state['active_incident_id'] and is changed with the incident
dropdown on each page. Durable data lives in SQLite, not in session state.
"""
from __future__ import annotations

import streamlit as st

from ui.components import ensure_active_incident

# "1 - Name" rather than "1. Name": Streamlit renders radio labels as Markdown and would swallow "1. " as a list marker.
PAGES = ["1 - Network Investigation", "2 - Evidence Vault", "3 - Tampering & Verification",
         "4 - Cryptographic Key Vault", "5 - Comparison & Reports"]


def request_incident(incident_id: int) -> None:
    st.session_state["_pending_incident"] = incident_id


def request_page(index: int) -> None:
    st.session_state["_pending_nav"] = PAGES[index]


def active_incident_id():
    return st.session_state.get("active_incident_id")


def render_sidebar(svc) -> str:
    st.sidebar.markdown("### NetSentinel")
    st.sidebar.caption("Network forensics and evidence integrity")

    if "_pending_nav" in st.session_state:
        st.session_state["nav"] = st.session_state.pop("_pending_nav")
    if "_pending_incident" in st.session_state:
        st.session_state["active_incident_id"] = st.session_state.pop("_pending_incident")

    page = st.sidebar.radio("Investigation workflow", PAGES, key="nav")

    st.sidebar.divider()
    active = ensure_active_incident(svc)
    inc = svc.incidents.get(active) if active else None
    if inc is None:
        st.sidebar.caption("No incident yet. Analyze a PCAP on page 1.")
    else:
        ev = svc.evidence.list_for_incident(inc["id"])
        bad = sum(1 for e in ev if e["status"] == "Compromised")
        st.sidebar.caption(f"Active incident: {inc['code']} ({inc['risk_level']} risk)")
        st.sidebar.caption(f"Evidence: {len(ev)} registered" + (f", {bad} modified" if bad else ""))
    return page
