"""Restrained light theme shared by all investigation pages."""
import streamlit as st
TEAL, RED, GREEN, AMBER, NAVY = "#167783", "#C13D3D", "#27805B", "#B0781D", "#203044"
SEVERITY_COLORS = {"LOW": GREEN, "MEDIUM": AMBER, "HIGH": "#D26934", "CRITICAL": RED}
CSS = """<style>
.block-container {padding-top:1.5rem;padding-bottom:3rem;max-width:1250px;}
h1 {font-size:1.75rem!important;letter-spacing:0;}
.ns-hero {background:linear-gradient(110deg,#E6F4F5,#F2F5FF 65%,#FFF3E5);border:1px solid #C8DEE4;border-radius:13px;padding:23px 28px;margin:0 0 22px;text-align:center;}
.ns-hero-title {font-size:2.15rem;font-weight:800;letter-spacing:.10em;color:#19344D;}
.ns-hero-sub {font-size:.97rem;color:#4D6278;margin-top:5px;}
.ns-hero-icons {font-size:1.5rem;margin-bottom:5px;}
.ns-timeline {border-left:3px solid #248B98;padding:9px 16px;margin:4px 0 9px 9px;background:#F5FAFC;border-radius:0 9px 9px 0;}
.ns-timeline .time {color:#47647A;font-size:.78rem;font-weight:600;}
.ns-timeline .event {font-weight:700;color:#21384D;margin:3px 0;}
.ns-timeline .route {color:#50667B;font-size:.82rem;}
section[data-testid="stSidebar"] {background:#EDF2F5;border-right:1px solid #DCE4EA;}
.ns-card {background:#FFFFFF;border:1px solid #DCE4EA;border-radius:7px;padding:14px 16px;margin-bottom:10px;}
.ns-card h4 {margin:0 0 6px;font-size:.78rem;color:#536579;text-transform:uppercase;}
.ns-metric {background:#FFFFFF;border:1px solid #DCE4EA;border-left:3px solid #167783;border-radius:6px;padding:10px 14px;}
.ns-metric .l {font-size:.72rem;color:#536579;text-transform:uppercase;}
.ns-metric .v {font-size:1.5rem;font-weight:600;color:#203044;}
.ns-metric.red {border-left-color:#C13D3D;}.ns-metric.amber {border-left-color:#B0781D;}.ns-metric.green {border-left-color:#27805B;}
.ns-banner {border-radius:7px;padding:13px;font-weight:650;text-align:center;margin:10px 0;}
.ns-banner.red {background:#FFF1F1;border:1px solid #D6A0A0;color:#8D2929;}
.ns-banner.green {background:#EFF9F3;border:1px solid #99C7AB;color:#206341;}
.ns-banner.amber {background:#FFF8E8;border:1px solid #D6BB82;color:#795413;}
.ns-warn {background:#FFF8E8;border:1px solid #E6D5AC;border-radius:6px;padding:8px;color:#795413;}
.ns-pill {display:inline-block;border-radius:10px;padding:2px 9px;border:1px solid #DCE4EA;font-size:.75rem;}
.ns-pill.red {color:#9C3030;}.ns-pill.green {color:#24714D;}.ns-pill.amber {color:#855B14;}.ns-pill.teal {color:#167783;}
.ns-kv {font-family:ui-monospace,monospace;font-size:.8rem;color:#203044;word-break:break-all;}
.ns-step {color:#536579;font-size:.82rem;}
pre.ns-text {background:#F3F6F8;border:1px solid #DCE4EA;padding:10px;white-space:pre-wrap;color:#203044;}
mark.ns-del {background:#FFE1E1;color:#8D2929;}mark.ns-add {background:#FFF1C6;color:#73520C;}
#MainMenu,footer {visibility:hidden;}.stDeployButton,[data-testid="stAppDeployButton"] {display:none;}
</style>"""
def inject(): st.markdown(CSS,unsafe_allow_html=True)
def style_fig(fig,height=320):
 fig.update_layout(height=height,margin=dict(l=12,r=12,t=40,b=18),paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)',font=dict(color='#33485C',size=12),legend=dict(bgcolor='rgba(0,0,0,0)'),title_font=dict(size=14,color=NAVY))
 fig.update_xaxes(gridcolor='#E6ECF0',zerolinecolor='#E6ECF0')
 fig.update_yaxes(gridcolor='#E6ECF0',zerolinecolor='#E6ECF0')
 return fig
