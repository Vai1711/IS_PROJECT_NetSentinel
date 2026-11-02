"""Cryptographic Key Vault: disposable keys, separate from operational secrets."""
import streamlit as st
from ui.evidence_page import _key_vault_tab
def render(svc):
 st.title("Cryptographic Key Vault")
 st.caption("Generate and inspect test keys independently of stored evidence.")
 _key_vault_tab()
