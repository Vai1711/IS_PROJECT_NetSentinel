"""Small reusable UI helpers (Streamlit-version tolerant)."""
from __future__ import annotations

import contextlib
import html
import io
import logging
import wave
from typing import Iterator, Optional

import numpy as np
import plotly.graph_objects as go
import streamlit as st
from PIL import Image, ImageDraw

from evidence.evidence_manager import EvidenceError
from evidence.tampering import TamperingError
from ui.theme import RED, TEAL, style_fig

log = logging.getLogger(__name__)
# Streamlit >= 1.50 deprecates use_container_width in favour of width="stretch". Older releases (the pinned
# 1.36) have an integer `width` parameter with different meaning, so decide by version, not by signature.
_NEW_WIDTH_API = tuple(int(x) for x in st.__version__.split(".")[:2]) >= (1, 50)
_DF_WIDTH = _PLOT_WIDTH = _NEW_WIDTH_API


def table(data, **kw) -> None:
    kw.setdefault("hide_index", True)
    if _DF_WIDTH:
        st.dataframe(data, width="stretch", **kw)
    else:
        st.dataframe(data, use_container_width=True, **kw)


def plot(fig, key: str) -> None:
    if _PLOT_WIDTH:
        st.plotly_chart(fig, width="stretch", key=key)
    else:
        st.plotly_chart(fig, use_container_width=True, key=key)


def metric(label: str, value, tone: str = "") -> None:
    st.markdown(f"<div class='ns-metric {tone}'><div class='l'>{html.escape(str(label))}</div>"
                f"<div class='v'>{html.escape(str(value))}</div></div>", unsafe_allow_html=True)


def banner(kind: str, text: str) -> None:
    st.markdown(f"<div class='ns-banner {kind}'>{html.escape(text)}</div>", unsafe_allow_html=True)


def pill(text: str, tone: str = "teal") -> str:
    return f"<span class='ns-pill {tone}'>{html.escape(str(text))}</span>"


def card(title: str, body_html: str) -> None:
    st.markdown(f"<div class='ns-card'><h4>{html.escape(title)}</h4>{body_html}</div>", unsafe_allow_html=True)


def kv(label: str, value: str) -> str:
    return f"<div><span style='color:#7f95b0;font-size:.78rem'>{html.escape(label)}</span><br><span class='ns-kv'>{html.escape(str(value))}</span></div>"


def step_caption(text: str) -> None:
    st.markdown(f"<div class='ns-step'>{html.escape(text)}</div>", unsafe_allow_html=True)


def warn(text: str) -> None:
    st.markdown(f"<div class='ns-warn'>{html.escape(text)}</div>", unsafe_allow_html=True)


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


@contextlib.contextmanager
def guard(action: str) -> Iterator[None]:
    """Show expected problems as friendly messages; log unexpected ones in full (never silently swallowed)."""
    try:
        yield
    except (EvidenceError, TamperingError) as exc:
        st.error(str(exc))
    except Exception as exc:  # noqa: BLE001 - last-resort UI boundary, always logged
        log.exception("Unexpected error while trying to %s", action)
        st.error(f"Unexpected error while trying to {action}: {exc.__class__.__name__}: {exc}. Details were written to the log.")


# ------------------------------------------------------------------ shared page helpers
def short_hash(h: str, n: int = 16) -> str:
    """First n hex characters of a digest, for compact display (full value stays in the details)."""
    return f"{h[:n]}..." if h and len(h) > n else (h or "")


STATUS_LABEL = {"Compromised": "Modified"}


def display_status(status: str) -> str:
    """Evidence status as shown in the UI: Sealed / Verified / Modified (database value is unchanged)."""
    return STATUS_LABEL.get(status, status)


def select_valid(label: str, options: list, key: str, format_func=str):
    """selectbox whose stored session value is dropped first if it is no longer one of the options
    (happens when the incident or evidence list changes), which would otherwise raise an exception."""
    if st.session_state.get(key) not in options:
        st.session_state.pop(key, None)
    return st.selectbox(label, options, key=key, format_func=format_func)


def incident_picker(svc, page_key: str, label: str = "Incident", capture_id: Optional[int] = None):
    """Incident dropdown shared by all pages. The choice lives in session_state['active_incident_id'],
    so picking an incident on one page is remembered on the next one. Returns the incident id (or None)."""
    incidents = svc.incidents.list(capture_id)
    if not incidents:
        return None
    ids = [i["id"] for i in incidents]
    names = {i["id"]: f"{i['code']}  |  {i['title']}" for i in incidents}
    active = st.session_state.get("active_incident_id")
    if active not in ids:
        active = ids[0]
        st.session_state["active_incident_id"] = active
    wkey = f"incident_pick_{page_key}"
    st.session_state[wkey] = active          # keep this page's widget in step with the shared choice

    def _changed() -> None:
        st.session_state["active_incident_id"] = st.session_state[wkey]

    st.selectbox(label, ids, format_func=names.get, key=wkey, on_change=_changed)
    return st.session_state["active_incident_id"]


def ensure_active_incident(svc):
    """Active incident id; falls back to the first stored incident (e.g. after the app was restarted)."""
    ids = [i["id"] for i in svc.incidents.list()]
    active = st.session_state.get("active_incident_id")
    if active not in ids:
        active = ids[0] if ids else None
        st.session_state["active_incident_id"] = active
    return active


def bit_grid_fig(bits, title: str = "") -> go.Figure:
    """16 x 16 grid of the 256 SHA-256 digest bits; red cells are bits that changed."""
    z = [list(bits[r * 16:(r + 1) * 16]) for r in range(16)]
    fig = go.Figure(go.Heatmap(z=z, showscale=False, xgap=2, ygap=2, colorscale=[[0, "#14304a"], [1, RED]],
                               hovertemplate="bit %{y}x16+%{x}<extra></extra>"))
    fig.update_yaxes(visible=False, autorange="reversed", scaleanchor="x")
    fig.update_xaxes(visible=False)
    fig.update_layout(title=title)
    return style_fig(fig, 260)


# ------------------------------------------------------------------ media helpers
def waveform_fig(data: bytes, title: str, max_points: int = 2000) -> go.Figure:
    with wave.open(io.BytesIO(data)) as w:
        rate, ch = w.getframerate(), w.getnchannels()
        arr = np.frombuffer(w.readframes(w.getnframes()), dtype="<i2")
    if ch > 1:
        arr = arr[::ch]
    step = max(1, len(arr) // max_points)
    x = np.arange(0, len(arr), step) / rate
    fig = go.Figure(go.Scatter(x=x, y=arr[::step], mode="lines", line=dict(color=TEAL, width=1)))
    fig.update_layout(title=title, xaxis_title="seconds", yaxis_title="amplitude")
    return style_fig(fig, 220)


def image_with_marker(data: bytes, x: int, y: int) -> Image.Image:
    img = Image.open(io.BytesIO(data)).convert("RGB")
    ImageDraw.Draw(img).rectangle([x - 8, y - 8, x + 8, y + 8], outline=(255, 40, 40), width=2)
    return img


def zoom_region(data: bytes, x: int, y: int, radius: int = 6, scale: int = 16) -> Image.Image:
    img = Image.open(io.BytesIO(data)).convert("RGB")
    box = (max(0, x - radius), max(0, y - radius), min(img.width, x + radius + 1), min(img.height, y + radius + 1))
    c = img.crop(box)
    return c.resize((c.width * scale, c.height * scale), Image.NEAREST)
