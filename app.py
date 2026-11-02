"""NetSentinel — run: python -m streamlit run app.py"""
from __future__ import annotations
import logging
import streamlit as st
st.set_page_config(page_title="NetSentinel",layout="wide",page_icon=":shield:")
from services import build_services
from ui import analysis_page,evidence_page,network_page,theme,tampering_page,key_vault_page
from ui.state import PAGES,render_sidebar
@st.cache_resource
def get_services():
 svc=build_services()
 logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(name)s: %(message)s",handlers=[logging.FileHandler(svc.settings.data_dir / "netsentinel.log"),logging.StreamHandler()],force=True)
 return svc
def main():
 theme.inject()
 svc=get_services()
 page=render_sidebar(svc)
 if page==PAGES[0]: network_page.render(svc)
 elif page==PAGES[1]: evidence_page.render(svc)
 elif page==PAGES[2]: tampering_page.render(svc)
 elif page==PAGES[3]: key_vault_page.render(svc)
 else: analysis_page.render(svc)
main()
