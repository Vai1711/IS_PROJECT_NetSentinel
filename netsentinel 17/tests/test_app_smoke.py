"""Headless Streamlit runs of the five pages (Streamlit AppTest). File-upload widgets cannot be driven by
AppTest, so uploaded evidence is registered through the service layer; every other step is a real button click."""
import ast
import os
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from conftest import ROOT, make_png, make_text, make_wav, needs_tshark
from evidence.tampering import METHODS
from ui.state import PAGES


# ---------------------------------------------------------------------------- static check (no TShark needed)
def _is_expander(node) -> bool:
    return (isinstance(node, ast.With) and any(
        isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
        and i.context_expr.func.attr == "expander" for i in node.items))


def test_no_nested_expanders_anywhere():
    """Streamlit forbids an expander inside an expander. The original bug hid behind a function call
    (render -> expander -> _section_perf -> expander), so follow calls to functions in the same file."""
    problems = []
    for path in sorted((ROOT / "ui").glob("*.py")):
        tree = ast.parse(path.read_text())
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

        def has_expander(node, seen=()):
            for sub in ast.walk(node):
                if _is_expander(sub):
                    return True
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in funcs \
                        and sub.func.id not in seen and has_expander(funcs[sub.func.id], seen + (sub.func.id,)):
                    return True
            return False

        for node in ast.walk(tree):
            if _is_expander(node):
                for stmt in node.body:
                    if has_expander(stmt):
                        problems.append(f"{path.name}:{node.lineno}")
    assert not problems, f"nested expanders found: {problems}"


# ---------------------------------------------------------------------------- AppTest helpers
pytestmark_tshark = needs_tshark


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSENTINEL_DATA_DIR", str(tmp_path))
    st.cache_resource.clear()
    return AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)


def _goto(at, page):
    at.sidebar.radio[0].set_value(page).run()
    assert not at.exception, [e.value for e in at.exception]


def _click(at, label):
    matches = [b for b in at.button if b.label == label]
    assert matches, f"button {label!r} not found; available: {[b.label for b in at.button]}"
    matches[0].click().run()
    assert not at.exception, [e.value for e in at.exception]


def _banners(at):
    return [m.value for m in at.markdown if m.value.startswith("<div class='ns-banner")]


def _seed(app):
    """Load the demo capture through the UI, then register one evidence file of each type."""
    app.run()
    _click(app, "Load bundled demo capture")
    assert not app.error
    from services import build_services
    s = build_services(os.environ["NETSENTINEL_DATA_DIR"])      # second handle on the same data dir
    iid = app.session_state["active_incident_id"]
    cap = s.incidents.get(iid)["capture"]
    ev = {"PCAP": s.evidence.register_capture_file(iid, cap["filepath"], cap["filename"]),
          "Text": s.evidence.register(iid, "m.txt", make_text()),
          "Image": s.evidence.register(iid, "s.png", make_png()),
          "Audio": s.evidence.register(iid, "r.wav", make_wav())}
    return s, iid, ev


# ---------------------------------------------------------------------------- tests
@needs_tshark
def test_empty_state_guidance_messages(app):
    app.run()
    assert not app.exception
    for page, expected in [(PAGES[1], "No incident exists yet"), (PAGES[2], "No registered evidence is available"),
                           (PAGES[3], "No incident exists yet")]:
        _goto(app, page)
        assert any(expected in i.value for i in app.info), (page, [i.value for i in app.info])


@needs_tshark
def test_page1_shows_four_metrics_two_charts_and_incident_table(app):
    app.run()
    _click(app, "Load bundled demo capture")
    labels = [m.value.split("class='l'>")[1].split("<")[0] for m in app.markdown if m.value.startswith("<div class='ns-metric")]
    assert labels == ["Total Packets", "Unique IP Addresses", "Threats Detected", "Overall Risk Score"]
    assert len(app.get("plotly_chart")) == 3                      # protocol, threat, plus the graph kept under Advanced
    inc_table = app.dataframe[0].value
    assert list(inc_table.columns) == ["Incident", "Threat", "Source IP", "Risk"]
    assert len(inc_table) == 2


@needs_tshark
def test_vault_table_uses_simple_columns_and_statuses(app):
    s, iid, ev = _seed(app)
    _goto(app, PAGES[1])
    tbl = app.dataframe[0].value
    assert list(tbl.columns) == ["ID", "File", "Type", "Incident", "Status", "SHA-256"]
    assert set(tbl["Status"]) == {"Sealed"} and len(tbl) == 4
    assert all(len(h) < 20 for h in tbl["SHA-256"]), "full hashes must not be shown by default"
    sim = s.simulator.simulate(ev["Text"]["id"], "Replace a URL")
    s.verifier.verify(ev["Text"]["id"])                           # untouched original -> Verified
    s.verifier.verify(ev["Image"]["id"], s.simulator.simulate(ev["Image"]["id"], "Change one pixel")["id"])
    _goto(app, PAGES[1])
    assert set(app.dataframe[0].value["Status"]) <= {"Sealed", "Verified", "Modified"}


@needs_tshark
def test_every_tamper_method_then_defender_detects_it(app):
    """Page 3 -> page 4 for all 12 methods: attacker never shows a verdict, defender detects the change."""
    s, iid, ev = _seed(app)
    for etype, e in ev.items():
        for method in METHODS[etype]:
            _goto(app, PAGES[2])
            app.selectbox(key="atk_ev").set_value(e["id"]).run()
            app.selectbox(key=f"atk_m_{etype}").set_value(method).run()
            _click(app, "Simulate Tampering")
            assert not app.error, (etype, method)
            assert any("Evidence modified successfully. Open Defender Verification to check integrity." in x.value
                       for x in app.success), (etype, method)
            assert not any("TAMPERING DETECTED" in b for b in _banners(app)), "attacker page must not reveal the verdict"
            _goto(app, PAGES[3])
            _click(app, "Verify Integrity")
            assert any("TAMPERING DETECTED" in b for b in _banners(app)), (etype, method)
            assert [r["Result"] for r in app.dataframe[0].value.to_dict("records")] == ["Mismatch", "Invalid", "Invalid"]
    # untouched original passes (control)
    _goto(app, PAGES[3])
    app.selectbox(key="def_ver").set_value(None).run()
    _click(app, "Verify Integrity")
    assert any("EVIDENCE VERIFIED" in b for b in _banners(app))
    assert [r["Result"] for r in app.dataframe[0].value.to_dict("records")] == ["Match", "Valid", "Valid"]
    assert len(app.dataframe[1].value) == 12                      # compact simulation history


@needs_tshark
def test_page5_benchmark_security_and_signed_report(app):
    s, iid, ev = _seed(app)
    _goto(app, PAGES[4])
    assert len(app.get("plotly_chart")) == 0, "nothing may be benchmarked automatically"
    _click(app, "Run Benchmark")                                  # used to crash: nested expander
    assert len(app.get("plotly_chart")) == 3                      # exactly three performance graphs
    _click(app, "Run Security Experiments")
    tests = next(d.value for d in app.dataframe if "Test" in d.value.columns)
    assert list(tests["Result"]) == ["Valid", "Invalid", "Invalid"]
    _click(app, "Generate Signed PDF")
    assert any("generated and signed" in x.value for x in app.success)
    _click(app, "Verify Report Signature")
    assert any("SIGNATURE VALID" in b for b in _banners(app))
    assert len(app.get("download_button")) == 3                   # report, signature, public key
