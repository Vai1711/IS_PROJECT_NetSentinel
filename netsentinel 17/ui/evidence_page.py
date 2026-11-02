"""Page 2 - Evidence Vault: attach evidence to an incident and protect it."""
from __future__ import annotations

import streamlit as st

from config import ALLOWED_EXTENSIONS
from database.models import AuditEvent
from evidence import audit, demo_key_vault as kv_demo
from ui.components import display_status, guard, incident_picker, kv, short_hash, table
from ui.state import request_page


# ---------------------------------------------------------------------------- Key Vault
# Session keys: kv_unlocked (bool), kv_error (bool), kv_pin (masked input), kv_keys (DemoKeys), kv_pdf (bytes).
# Demo keys live only in session state (memory). They are never shown in a widget, saved, logged or stored.
def _kv_try_unlock() -> None:
    ok = kv_demo.check_pin(st.session_state.get("kv_pin", ""))
    st.session_state["kv_unlocked"] = ok
    st.session_state["kv_error"] = not ok
    st.session_state["kv_pin"] = ""                      # never keep the typed PIN


def _kv_discard() -> None:
    st.session_state.pop("kv_keys", None)
    st.session_state.pop("kv_pdf", None)


def _kv_lock() -> None:
    _kv_discard()                                        # locking also wipes the demo keys
    st.session_state["kv_unlocked"] = False
    st.session_state["kv_error"] = False


def _kv_generate() -> None:
    keys = kv_demo.generate_demo_keys()
    st.session_state["kv_keys"] = keys
    st.session_state["kv_pdf"] = kv_demo.build_keys_pdf(keys)


def _key_vault_tab() -> None:
    if not st.session_state.get("kv_unlocked", False):          # locked by default
        st.subheader("Cryptographic Key Vault")
        st.write("Enter the vault PIN to generate test keys.")
        st.text_input("Vault PIN", type="password", key="kv_pin", max_chars=16)
        st.button("Unlock", on_click=_kv_try_unlock)
        if st.session_state.get("kv_error"):
            st.error("Incorrect PIN. The vault stays locked.")
        st.caption("PIN access is for local testing, not production key security.")
        return

    st.subheader("Cryptographic Key Vault")
    keys = st.session_state.get("kv_keys")
    c1, c2, c3 = st.columns(3)
    c1.button("Generate New Keys", type="primary", on_click=_kv_generate)
    c2.button("Discard Keys", on_click=_kv_discard, disabled=keys is None)
    c3.button("Lock Vault", on_click=_kv_lock)
    if keys is None:
        st.caption("No demo keys yet. Click Generate New Keys.")
    else:
        table([{"Key": "RSA Public Key", "Purpose": "Signature verification",
                "Details": f"RSA-{keys.key_size}, public exponent {keys.public_exponent}"},
               {"Key": "RSA Private Key", "Purpose": "Digital signing", "Details": f"RSA-{keys.key_size}"},
               {"Key": "HMAC Secret Key", "Purpose": "Message authentication", "Details": f"{kv_demo.HMAC_KEY_BITS}-bit random key"}])
        st.caption(f"Generated {keys.generated_at}. The full keys appear only in the PDF.")
        st.download_button("Download Keys PDF", st.session_state["kv_pdf"],
                           "netsentinel_test_keys.pdf", "application/pdf", type="primary")
    st.caption("Test keys are separate from operational evidence and report keys, "
               "are kept only in memory, and are never saved or used for evidence.")


def _advanced_details(svc, incident_id, evidence) -> None:
    """Single expander (never nested) with tabs: hashes/signatures, audit trail, educational key vault."""
    with st.expander("Advanced Cryptographic Details", expanded=False):
        t_keys, t_audit = st.tabs(["Hashes and signatures", "Audit trail"])
        with t_keys:
            if not evidence:
                st.caption("No evidence registered yet.")
            for e in evidence:
                full = svc.evidence.get(e["id"])
                st.markdown(f"**{e['code']}**  {e['filename']}")
                st.markdown(kv("SHA-256", e["sha256"]) + kv("HMAC-SHA256 (file)", full["file_hmac"])
                            + kv("RSA-2048 signature (base64, first 64 characters)", e["signature_b64"][:64] + "...")
                            + kv("Signed manifest", e["manifest_json"]), unsafe_allow_html=True)
                st.divider()
        with t_audit:
            if incident_id is None:
                st.caption("No incident selected.")
            else:
                with svc.db.session_scope() as s:
                    ok, bad_id, n = audit.verify_chain(s)
                    rows = [{"#": a.id, "Time (UTC)": a.ts, "Event": a.event_type,
                             "Evidence": f"EV{a.evidence_id:03d}" if a.evidence_id else "", "Detail": a.detail}
                            for a in s.query(AuditEvent).filter(AuditEvent.incident_id == incident_id).order_by(AuditEvent.id.desc()).limit(200)]
                (st.success if ok else st.error)(f"Audit chain {'intact' if ok else f'BROKEN at entry #{bad_id}'} ({n} entries).")
                table(rows)


def render(svc):
    st.title("Evidence Vault")
    st.caption("Attach evidence to an incident and protect it with SHA-256, HMAC and an RSA signature.")

    incident_id = incident_picker(svc, "vault", "Step 1: Select incident")
    if incident_id is None:
        st.info("No incident exists yet. Analyze a PCAP in Network Investigation first; evidence is attached to a detected incident.")
        _advanced_details(svc, None, [])
        return
    inc = svc.incidents.get(incident_id)
    evidence = svc.evidence.list_for_incident(incident_id)
    registered_pcap = any(e["source"] == "capture" for e in evidence)

    # ---- step 2: choose the file -------------------------------------------------
    st.markdown("**Step 2: Upload evidence** (image, audio, text or PCAP)")
    exts = sorted(e.lstrip(".") for t in ALLOWED_EXTENSIONS for e in ALLOWED_EXTENSIONS[t])
    files = st.file_uploader("Evidence file", type=exts, accept_multiple_files=True,
                             key=f"ev_upload_{incident_id}_{len(evidence)}", label_visibility="collapsed")
    if not registered_pcap:
        if st.button(f"Or use this incident's PCAP ({inc['capture']['filename']})"):
            with guard("register the PCAP"):
                e = svc.evidence.register_capture_file(incident_id, inc["capture"]["filepath"], inc["capture"]["filename"])
                st.session_state["_flash_vault"] = f"{e['code']} registered and secured: {e['filename']}"
                st.rerun()

    # ---- step 3: register ----------------------------------------------------------
    st.markdown("**Step 3: Secure the evidence**")
    if st.button("Register & Secure Evidence", type="primary"):
        if not files:
            st.warning("Choose at least one file in Step 2 first.")
        else:
            done = []
            for f in files:
                with guard(f"register {f.name}"):
                    done.append(svc.evidence.register(incident_id, f.name, f.getvalue())["code"])
            if done:
                st.session_state["_flash_vault"] = "Registered and secured: " + ", ".join(done)
                st.rerun()
    if "_flash_vault" in st.session_state:
        st.success(st.session_state.pop("_flash_vault"))

    # ---- step 4: registered evidence --------------------------------------------------
    st.markdown("**Step 4: Registered evidence**")
    evidence = svc.evidence.list_for_incident(incident_id)
    if not evidence:
        st.info("No evidence registered for this incident yet.")
        _advanced_details(svc, incident_id, [])
        return
    table([{"ID": e["code"], "File": e["filename"], "Type": e["type"], "Incident": e["incident_code"],
            "Status": display_status(e["status"]), "SHA-256": short_hash(e["sha256"], 12)} for e in evidence])
    st.caption("Sealed = protected on registration.  Verified = checked and unchanged.  Modified = a check found a change.")

    _advanced_details(svc, incident_id, evidence)

    if st.button("Continue to Attacker Simulator", type="primary"):
        request_page(2); st.rerun()
