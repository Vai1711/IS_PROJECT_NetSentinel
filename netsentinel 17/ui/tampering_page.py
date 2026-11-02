"""Tampering and verification share one investigation page."""
import streamlit as st
from ui import attacker_page,defender_page

def render(svc):
 st.title("Tampering & Verification")
 st.caption("Modify a copy of registered evidence, then compare it with the protected original.")
 t1,t2=st.tabs(["Modify Evidence","Verify Integrity & Compare"])
 with t1:
  attacker_page.render(svc,embedded=True)
 with t2:
  defender_page.render(svc,embedded=True)
