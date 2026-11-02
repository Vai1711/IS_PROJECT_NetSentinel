"""Page 4 - Defender Verification: check evidence against its protected reference record."""
from __future__ import annotations

import pandas as pd
from pathlib import Path
import streamlit as st

from ui.components import (banner, bit_grid_fig, guard, incident_picker, kv, metric, plot, select_valid, short_hash,
                           table)


def _show_result(r: dict) -> None:
    if r["verdict"] == "MISSING":
        banner("amber", "EVIDENCE FILE MISSING: it cannot be verified")
        return
    res = r["result"]
    if r["verdict"] == "VERIFIED":
        banner("green", "EVIDENCE VERIFIED")
    elif r["verdict"] == "REFERENCE_COMPROMISED":
        banner("red", "REFERENCE RECORD COMPROMISED")
        st.caption("The stored signature or HMAC of the original record no longer validates.")
    else:
        banner("red", "TAMPERING DETECTED")

    table([{"Security Check": "SHA-256", "Result": "Match" if res.sha_match else "Mismatch"},
           {"Security Check": "HMAC-SHA256", "Result": "Valid" if res.hmac_ok else "Invalid"},
           {"Security Check": "RSA-2048", "Result": "Valid" if res.rsa_ok else "Invalid"}])

    # compact numerical comparison; bit grid is available in advanced details
    st.markdown("**Hash comparison**")
    left, right = st.columns([2, 3])
    with left:
        metric("Changed hash bits", f"{res.changed_bits} / 256", "red" if res.changed_bits else "green")
        st.write("")
        metric("Percent changed", f"{res.avalanche_pct:.1f}%", "red" if res.changed_bits else "green")
        st.caption(f"Original:  {short_hash(res.original_sha256)}")
        st.caption(f"Current:   {short_hash(res.candidate_sha256)}")
    with right:
        st.caption("The hash comparison uses all 256 bits. A changed hash is evidence of a mismatch.")

    with st.expander("Full hashes", expanded=False):
        st.markdown(kv("Original SHA-256", res.original_sha256) + kv("Current SHA-256", res.candidate_sha256),
                    unsafe_allow_html=True)


def render(svc, embedded=False):
    if not embedded:
        st.title("Integrity Verification")
    st.caption("Compare evidence with its protected reference record.")

    incident_id = incident_picker(svc, "defender", "Step 1: Select incident")
    if incident_id is None:
        st.info("No incident exists yet. Complete Network Investigation and Evidence Registration first.")
        return
    evidence = svc.evidence.list_for_incident(incident_id)
    if not evidence:
        st.info("No evidence is registered for this incident yet. Register evidence in the Evidence Vault first.")
        return

    # Pre-select the copy the attacker just created (written before the widgets exist).
    pick = st.session_state.pop("defender_pick", None)
    if pick and any(e["id"] == pick[0] for e in evidence):
        st.session_state["def_ev"], st.session_state["def_ver"] = pick

    c1, c2 = st.columns(2)
    with c1:
        eid = select_valid("Step 2: Select evidence", [e["id"] for e in evidence], "def_ev",
                           lambda i: next(f"{e['code']}  {e['filename']}  ({e['type']})" for e in evidence if e["id"] == i))
    sims = svc.simulator.list_for_evidence(eid)
    options = [None] + [s["id"] for s in sims]
    labels = {None: "Original evidence (untouched)",
              **{s["id"]: f"SIM{s['id']:03d}: {s['method']} (simulated copy)" for s in sims}}
    with c2:
        sid = select_valid("Version to check", options, "def_ver", labels.get)

    if st.button("Verify Integrity", type="primary"):
        with guard("verify the evidence"):
            st.session_state["last_ver"] = {"eid": eid, "sid": sid, **svc.verifier.verify(eid, sid)}

    r = st.session_state.get("last_ver")
    if r and r["eid"] == eid and r["sid"] == sid:
        _show_result(r)
        if r["verdict"] != "MISSING" and sid is not None:
            original = svc.evidence.get(eid)
            simulation = svc.simulator.get(sid)
            result = r["result"]
            original_size = len(svc.evidence.read_original(eid))
            modified_size = Path(simulation["modified_path"]).stat().st_size
            st.subheader("Before vs. After")
            table([
                {"Property":"Filename", "Original":original["filename"], "Modified":simulation["modified_filename"]},
                {"Property":"File size", "Original":f"{original_size:,} bytes", "Modified":f"{modified_size:,} bytes"},
                {"Property":"SHA-256", "Original":short_hash(result.original_sha256), "Modified":short_hash(result.candidate_sha256)},
                {"Property":"Hash comparison", "Original":"Reference", "Modified":"Match" if result.sha_match else "Mismatch"},
                {"Property":"HMAC verification", "Original":"Protected reference", "Modified":"Valid" if result.hmac_ok else "Invalid"},
                {"Property":"RSA verification", "Original":"Signed reference", "Modified":"Valid" if result.rsa_ok else "Invalid"},
                {"Property":"Integrity status", "Original":"Reference", "Modified":r["verdict"].replace("_", " ").title()},
            ])


    # ---- compact history -------------------------------------------------------------------
    st.subheader("Simulation history")
    hist = svc.verifier.attack_history(incident_id)
    if hist:
        df = pd.DataFrame(hist)[["Evidence", "Tampering Method", "Hash Result", "HMAC Result", "Signature Result", "Bits Changed"]]
        df = df.rename(columns={"Tampering Method": "Method", "Hash Result": "SHA-256", "HMAC Result": "HMAC",
                                "Signature Result": "RSA", "Bits Changed": "Bits changed"})
        table(df)
    else:
        st.info("No tampering has been simulated yet. You can still verify the untouched original above.")

    ctrl = svc.verifier.control_history(incident_id)
    if ctrl:
        with st.expander(f"Checks of untouched originals ({len(ctrl)})", expanded=False):
            table(ctrl)
