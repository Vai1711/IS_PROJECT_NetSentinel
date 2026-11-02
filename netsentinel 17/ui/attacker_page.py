"""Page 3 - Attacker Simulator (controlled tampering of disposable copies)."""
from __future__ import annotations

import io
import wave

import streamlit as st
from PIL import Image

from evidence.pcap_tools import analyze_capture_bytes
from evidence.tampering import METHODS, text_diff_html
from ui.components import (guard, image_with_marker, incident_picker, plot, select_valid, table, waveform_fig,
                           zoom_region)
from ui.state import request_page


def _params_ui(etype, method, data: bytes):
    """Method-specific controls. Returns kwargs for the tampering function."""
    p = {}
    if etype == "Image":
        w, h = Image.open(io.BytesIO(data)).size
        if method == "Change one pixel":
            c1, c2 = st.columns(2)
            p["x"] = c1.number_input("Pixel X", 0, w - 1, w // 2); p["y"] = c2.number_input("Pixel Y", 0, h - 1, h // 2)
        elif method == "Add text overlay":
            p["text"] = st.text_input("Overlay text", "TAMPERED")
        else:
            p["percent"] = st.slider("Percent removed (right and bottom)", 5, 50, 15)
    elif etype == "Audio":
        with wave.open(io.BytesIO(data)) as wv:
            n = wv.getnframes() * wv.getnchannels()
        if method == "Modify one sample":
            p["index"] = st.number_input("Sample index", 0, max(0, n - 1), n // 2)
        elif method == "Add noise":
            p["std"] = st.slider("Noise strength", 50, 3000, 300)
        else:
            p["percent"] = st.slider("Percent trimmed from the end", 1, 50, 10)
    elif etype == "Text":
        if method == "Replace a URL":
            p["replacement"] = st.text_input("Replacement URL", "https://secure-update.example.invalid/login")
    else:
        if method == "Flip one bit":
            default = 62 if analyze_capture_bytes(data)["format"] == "pcap" and len(data) > 62 else len(data) // 2
            c1, c2 = st.columns(2)
            p["byte_offset"] = c1.number_input("File byte offset", 0, len(data) - 1, default)
            p["bit"] = c2.slider("Bit index in byte", 0, 7, 0)
        elif method == "Modify a packet field":
            p["field_name"] = st.selectbox("Packet field", ["IP TTL", "IP source address", "TCP/UDP destination port"])
        else:
            p["keep_percent"] = st.slider("Percent of file kept", 10, 95, 70)
    return p


def _show_result(ev, sim, original: bytes):
    """Original and modified copy side by side. No verification verdict is shown here."""
    etype = ev["type"]
    with open(sim["modified_path"], "rb") as fh:
        modified = fh.read()
    d = sim["details"]
    st.markdown(f"**{sim['method']}**: {sim['summary']}")
    c1, c2 = st.columns(2)
    if etype == "Image":
        with c1:
            st.caption("Original"); st.image(original)
        with c2:
            st.caption("Modified copy" + (" (changed pixel outlined in red)" if "x" in d else ""))
            st.image(image_with_marker(modified, d["x"], d["y"]) if "x" in d else modified)
        if "x" in d:
            z1, z2 = st.columns(2)
            with z1:
                st.caption("Original pixel, zoomed"); st.image(zoom_region(original, d["x"], d["y"]), width=160)
            with z2:
                st.caption("Modified pixel, zoomed"); st.image(zoom_region(modified, d["x"], d["y"]), width=160)
    elif etype == "Audio":
        with c1:
            st.caption("Original"); st.audio(original, format="audio/wav"); plot(waveform_fig(original, "Original waveform"), "wf_o")
        with c2:
            st.caption("Modified copy"); st.audio(modified, format="audio/wav"); plot(waveform_fig(modified, "Modified waveform"), "wf_m")
    elif etype == "Text":
        ha, hb = text_diff_html(original.decode("utf-8", "replace"), modified.decode("utf-8", "replace"))
        with c1:
            st.caption("Original"); st.markdown(ha, unsafe_allow_html=True)
        with c2:
            st.caption("Modified copy (changes highlighted)"); st.markdown(hb, unsafe_allow_html=True)
    else:
        if "packet_number" in d:
            table([{"Packet": d["packet_number"], "Field": d["field"], "Original value": d["old"], "New value": d["new"]}])
        parse = d.get("parse") or analyze_capture_bytes(modified)
        if not parse["valid_header"] or not parse["complete"]:
            st.warning(f"The modified copy is no longer a complete capture. {parse['note']}")


def render(svc, embedded=False):
    if not embedded:
        st.title("Tampering Analysis")
    st.caption("Changes are applied to a copy; the original is preserved.")

    incident_id = incident_picker(svc, "attacker", "Step 1: Select incident")
    evidence = svc.evidence.list_for_incident(incident_id) if incident_id else []
    if not evidence:
        st.info("No registered evidence is available. Please complete Network Investigation and Evidence Registration first.")
        return

    c1, c2 = st.columns(2)
    with c1:
        eid = select_valid("Step 2: Select evidence", [e["id"] for e in evidence], "atk_ev",
                           lambda i: next(f"{e['code']}  {e['filename']}  ({e['type']})" for e in evidence if e["id"] == i))
    ev = next(e for e in evidence if e["id"] == eid)
    with c2:
        method = st.selectbox("Step 3: Select tampering method", list(METHODS[ev["type"]]), key=f"atk_m_{ev['type']}")
    original = svc.evidence.read_original(eid)
    params = _params_ui(ev["type"], method, original)

    if st.button("Simulate Tampering", type="primary"):
        with guard("simulate tampering"):
            sim = svc.simulator.simulate(eid, method, params)
            st.session_state["last_sim"] = sim["id"]
            st.session_state["defender_pick"] = (eid, sim["id"])

    sid = st.session_state.get("last_sim")
    if sid:
        with guard("display the simulation"):
            sim = svc.simulator.get(sid)
            if sim["evidence_id"] == eid:
                st.success("Modified copy created. Open the Verify Integrity & Compare tab to check it.")
                
                st.divider()
                _show_result(ev, sim, original)
