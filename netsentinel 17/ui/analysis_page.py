"""Page 5 - Security Analysis & Reports: performance graphs, security experiments, signed report."""
from __future__ import annotations

import base64
import json
import math
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from crypto import benchmarks, rsa_security, sha_security
from database.models import CryptoRun, ReportRecord
from evidence.integrity import sha256_hex
from reports import report_generator, report_signer
from ui.components import (banner, bit_grid_fig, ensure_active_incident, guard, incident_picker, metric, plot,
                           short_hash, table)
from ui.theme import AMBER, RED, TEAL, style_fig

BENCH_SIZES = [1_024, 10_240, 102_400, 1_048_576, 10_485_760]     # 1 KB ... 10 MB
SIZE_LABELS = {1_024: "1 KB", 10_240: "10 KB", 102_400: "100 KB", 1_048_576: "1 MB", 10_485_760: "10 MB"}
BENCH_RUNS, RSA_RUNS = 15, 30
TEST_DATA = b"NetSentinel labelled TEST DATA: not forensic evidence. " * 20


# --------------------------------------------------------------------------- stored experiment results
def _latest(svc, kind):
    with svc.db.session_scope() as s:
        r = s.query(CryptoRun).filter_by(kind=kind).order_by(CryptoRun.id.desc()).first()
        return (json.loads(r.result_json), r.created_at) if r else (None, None)


def _save(svc, kind, data, incident_id):
    with svc.db.session_scope() as s:
        s.add(CryptoRun(kind=kind, incident_id=incident_id, result_json=json.dumps(data)))


# --------------------------------------------------------------------------- Section A: performance
def _line_fig(rows, title, y_title, color):
    labels = [SIZE_LABELS.get(r["size_bytes"], f"{r['size_bytes']:,} B") for r in rows]
    ys = [r["median_ms"] for r in rows]
    fig = go.Figure(go.Scatter(x=labels, y=ys, mode="lines+markers+text", line=dict(color=color, width=2),
                               text=[f"{y:.3f}" for y in ys], textposition="top center",
                               hovertemplate="%{x}: %{y:.4f} ms<extra></extra>"))
    fig.update_layout(title=title, xaxis_title="File size", yaxis_title=y_title, yaxis_type="log")
    fig.update_yaxes(dtick=1)                      # one tick per power of ten
    fig.update_xaxes(categoryorder="array", categoryarray=labels)
    return style_fig(fig, 320)


def _section_perf(svc, incident_id):
    st.caption("Real timings measured on this computer. Each point is the median of several runs.")
    if st.button("Run Benchmark", type="primary"):
        with guard("run the benchmark"), st.spinner("Timing SHA-256, HMAC-SHA256 and RSA-2048..."):
            res = benchmarks.run_all(svc.keys, BENCH_SIZES, BENCH_RUNS, [], RSA_RUNS)
            _save(svc, "benchmark", res, incident_id)
    res, at = _latest(svc, "benchmark")
    if not res:
        st.info("No benchmark has been run yet. Click Run Benchmark.")
        return
    st.caption(f"Latest run: {at:%Y-%m-%d %H:%M:%S} UTC, {res['repeats']} timed runs per point. Time axis is log scale.")

    latest_size = res["sha256"][-1]["size_bytes"]
    sha = next(x for x in res["sha256"] if x["size_bytes"] == latest_size)
    hm = next(x for x in res["hmac"] if x["size_bytes"] == latest_size)
    r = res["rsa"]
    names = ["SHA-256", "HMAC-SHA256", "RSA sign", "RSA verify"]
    timings = [sha["median_ms"], hm["median_ms"], r["sign"]["median_ms"], r["verify"]["median_ms"]]
    fig = go.Figure(go.Bar(x=names, y=timings, marker_color=TEAL,
                           text=[f"{v:.3f}" for v in timings], textposition="outside"))
    fig.update_layout(title="Cryptographic Execution Time", yaxis_title="Median time (ms)",
                      showlegend=False, bargap=0.45)
    plot(style_fig(fig, 340), "crypto_timing")
    st.caption(f"SHA-256/HMAC measured on {SIZE_LABELS.get(latest_size, str(latest_size)+' B')} input; "
               f"RSA operations use a {r['message_size']}-byte message. Values are measured, not estimated.")

    with st.expander("View Numeric Results", expanded=False):
        rows = [{"Algorithm": name, "File size": SIZE_LABELS.get(x["size_bytes"], f"{x['size_bytes']:,} B"),
                 "Median (ms)": round(x["median_ms"], 4), "Min (ms)": round(x["min_ms"], 4), "Max (ms)": round(x["max_ms"], 4)}
                for name, data in (("SHA-256", res["sha256"]), ("HMAC-SHA256", res["hmac"])) for x in data]
        rows += [{"Algorithm": f"RSA-2048 {name}", "File size": f"{r['message_size']} B message", "Median (ms)": round(r[key]["median_ms"], 4),
                  "Min (ms)": round(r[key]["min_ms"], 4), "Max (ms)": round(r[key]["max_ms"], 4)}
                 for name, key in (("signing", "sign"), ("verification", "verify"))]
        table(rows)


# --------------------------------------------------------------------------- Measured performance comparison
def _performance_comparison(svc, incident_id):
    st.subheader("Performance Comparison Across File Sizes")
    st.caption("SHA-256, HMAC-SHA256 and RSA-2048 (RSA-PSS signing, including hashing). "
               "All charts use measurements collected on this computer.")
    if st.button("Run Detailed Performance Comparison", key="run_profile"):
        with guard("profile cryptographic performance"), st.spinner("Measuring time, CPU and memory across five input sizes..."):
            result = benchmarks.profile_comparison(svc.keys, BENCH_SIZES, repeats=5)
            _save(svc, "performance_profile", result, incident_id)
    profile, at = _latest(svc, "performance_profile")
    if not profile:
        st.info("Click Run Detailed Performance Comparison to generate the four graphs.")
        return
    results = profile["results"]
    algos = [("sha256", "SHA-256", TEAL), ("hmac", "HMAC-SHA256", "#5269B8"),
             ("rsa", "RSA-2048 signing", AMBER)]
    labels = [SIZE_LABELS.get(row["size_bytes"], str(row["size_bytes"])) for row in results["sha256"]]

    # Grouped bars: timing across all file sizes, using a logarithmic y-axis.
    fig = go.Figure()
    for key, name, color in algos:
        fig.add_bar(name=name, x=labels, y=[r["median_ms"] for r in results[key]], marker_color=color)
    fig.update_layout(title="Execution Time by File Size", barmode="group", yaxis_title="Median execution time (ms, log scale)",
                      xaxis_title="Input size", yaxis_type="log")
    plot(style_fig(fig, 350), "profile_time")

    # Horizontal throughput: only the two bulk-data hash operations.
    # The largest size gives more meaningful throughput than tiny inputs.
    fig = go.Figure(go.Bar(
        y=["SHA-256", "HMAC-SHA256"],
        x=[results["sha256"][-1]["throughput_mb_s"], results["hmac"][-1]["throughput_mb_s"]],
        orientation="h", marker_color=[TEAL, "#5269B8"],
        text=[f"{results[k][-1]['throughput_mb_s']:.1f}" for k in ("sha256", "hmac")],
        textposition="outside"))
    fig.update_layout(title=f"Bulk-data Throughput ({labels[-1]} input)", xaxis_title="MB/s", showlegend=False)
    plot(style_fig(fig, 290), "profile_throughput")
    st.caption("RSA signing is excluded from bulk throughput: signatures/second is a more meaningful RSA metric. "
               f"Measured RSA signing rate at {labels[-1]}: {1000 / results['rsa'][-1]['median_ms']:.1f} signatures/s.")

    # Heatmap uses separately normalized values, not mixed CPU percentages and KiB.
    # Each cell still displays its original measurement and unit.
    cpu = [[r["cpu_percent_one_core"] for r in results[k]] for k, _, _ in algos]
    mem = [[r["peak_python_kib"] for r in results[k]] for k, _, _ in algos]
    names = [name for _, name, _ in algos]
    c1, c2 = st.columns(2)
    for col, values, heading, fmt, key in [
        (c1, cpu, "CPU Usage (one-core equivalent)", ".1f", "cpu"),
        (c2, mem, "Peak Python-tracked Memory", ".1f", "memory")]:
        max_val = max(max(row) for row in values) or 1
        # Nonlinear color mapping reveals low measurements without changing labels.
        # The colorbar represents the original units, not normalized percentages.
        scale = math.log1p(max_val)
        normalized = [[math.log1p(max(0, v)) / scale for v in row] for row in values]
        suffix = "%" if key == "cpu" else " KiB"
        color_ticks = [0, max_val * 0.01, max_val * 0.1, max_val]
        tick_vals = [math.log1p(v) / scale for v in color_ticks]
        fig = go.Figure(go.Heatmap(
            z=normalized, x=labels, y=names, zmin=0, zmax=1,
            colorscale=[[0, "#DCEAF6"], [0.25, "#B5D2EA"], [0.5, "#77A9D3"],
                        [0.75, "#3978B2"], [1, "#103A73"]],
            xgap=3, ygap=3,
            showscale=True,
            colorbar=dict(title="Low to high", thickness=10, len=0.8,
                          tickvals=tick_vals,
                          ticktext=[f"{v:.2g}{suffix}" for v in color_ticks]),
            text=[[f"{v:{fmt}}{suffix}" for v in row] for row in values],
            texttemplate="%{text}", hovertemplate="%{y}<br>%{x}: %{text}<extra></extra>"))
        fig.update_layout(title=heading, xaxis_title="Input size", yaxis_autorange="reversed")
        with col:
            plot(style_fig(fig, 290), f"profile_{key}")
    st.caption(profile["cpu_definition"] + ". " + profile["memory_definition"] + ".")

    fig = go.Figure()
    for key, name, color in algos:
        fig.add_trace(go.Scatter(x=labels, y=[r["median_ms"] for r in results[key]],
                                 mode="lines+markers", name=name, line=dict(color=color, width=2)))
    fig.update_layout(title="Scalability — Execution Time vs Input Size", xaxis_title="Input size",
                      yaxis_title="Median execution time (ms, log scale)", yaxis_type="log")
    plot(style_fig(fig, 360), "profile_scalability")
    st.caption("RSA-PSS includes SHA-256 hashing of each input. Measurements vary by machine and workload; "
               "the CPU and memory measurements are process-level estimates, not isolated hardware counters.")
    with st.expander("Detailed measurements and methodology"):
        table([{"Algorithm": name, "Input": SIZE_LABELS.get(r["size_bytes"], str(r["size_bytes"])),
                "Time (ms)": round(r["median_ms"], 4),
                "CPU (% of one core)": round(r["cpu_percent_one_core"], 1),
                "Peak Python memory (KiB)": round(r["peak_python_kib"], 1)}
               for key, name, _ in algos for r in results[key]])
        st.caption(f"{profile['repeats']} timed repetitions per point; median reported. "
                   "Memory profiling is performed in a separate pass to avoid skewing timing results.")


# --------------------------------------------------------------------------- Section B: security
def _bits_from_digests(a_hex: str, b_hex: str):
    return [int(c) for c in format(int(a_hex, 16) ^ int(b_hex, 16), "0256b")]


def _input_choice(svc, incident_id):
    """Test data or one registered evidence file. Returns (bytes, label, evidence dict | None)."""
    ev = svc.evidence.list_for_incident(incident_id) if incident_id else []
    opts = [None] + [e["id"] for e in ev]
    names = {None: "Test data", **{e["id"]: f"{e['code']}  {e['filename']}" for e in ev}}
    if st.session_state.get("sec_input") not in opts:
        st.session_state.pop("sec_input", None)
    pick = st.selectbox("Input for the experiments", opts, index=1 if ev else 0, format_func=names.get, key="sec_input")
    if pick is None:
        return TEST_DATA, "test data", None
    e = next(x for x in ev if x["id"] == pick)
    return svc.evidence.read_original(pick), f"{e['code']} {e['filename']}", e


def _run_security_experiments(svc, data, label, ev, incident_id):
    if len(data) > 1_048_576:
        data = data[:1_048_576]                      # keep the avalanche test quick on big files
    _save(svc, "avalanche", {"source": label, **sha_security.avalanche(data, 256)}, incident_id)
    _save(svc, "collision", sha_security.collision_test(100_000), incident_id)
    if ev:
        row = svc.evidence.get(ev["id"])
        res = rsa_security.rsa_security_demo(svc.keys, svc.evidence.read_original(ev["id"]), label,
                                             row["manifest_json"].encode(), base64.b64decode(row["signature_b64"]))
    else:
        res = rsa_security.rsa_security_demo(svc.keys, data, label)
    _save(svc, "rsa_security", res, incident_id)


def _section_security(svc, incident_id):
    st.caption("SHA-256 and RSA-2048 integrity tests.")
    data, label, ev = _input_choice(svc, incident_id)
    if st.button("Run Security Experiments", type="primary"):
        with guard("run the security experiments"), st.spinner("Running experiments..."):
            _run_security_experiments(svc, data, label, ev, incident_id)

    a, _ = _latest(svc, "avalanche")
    k, _ = _latest(svc, "collision")
    r, _ = _latest(svc, "rsa_security")
    if not (a or k or r):
        st.info("No experiment has been run yet. Click Run Security Experiments.")
        return

    # ---- SHA-256 avalanche effect
    st.subheader("SHA-256 avalanche effect")
    st.caption("How much does the hash change after modifying one bit?")
    if a:
        c1, c2 = st.columns([2, 3])
        with c1:
            metric("Hash bits changed", f"{a['differing_bits']} / 256")
            st.write("")
            metric("Percentage changed", f"{a['avalanche_pct']:.1f}%")
            st.caption(f"Average over {a['trials']} random single-bit changes: {a['mean_pct']:.1f}% (ideal: about 50%). Input: {a['source']}.")
        with c2:
            plot(bit_grid_fig(_bits_from_digests(a["original_digest"], a["modified_digest"]), "Red = hash bit changed"), "av_grid")

        avalanche_fig = go.Figure(go.Bar(x=["Changed", "Unchanged"], y=[a["differing_bits"], 256 - a["differing_bits"]], marker_color=[TEAL, "#B7C9D8"], text=[a["differing_bits"], 256-a["differing_bits"]], textposition="outside"))
        avalanche_fig.update_layout(title="SHA-256 Output Bit Comparison", yaxis_title="Bits", yaxis_range=[0, 280], showlegend=False)
        plot(style_fig(avalanche_fig, 270), "avalanche_comparison")

        # Individual measured one-bit-flip trials (not estimated values).
        trial_counts = a.get("trial_changed_bits", [])
        if trial_counts:
            st.markdown("**Avalanche Effect Across Trials**")
            trials_fig = go.Figure()
            trials_fig.add_trace(go.Scatter(x=list(range(1, len(trial_counts) + 1)),
                                            y=trial_counts, mode="lines", name="Changed bits",
                                            line=dict(color=TEAL, width=1.6),
                                            hovertemplate="Trial %{x}: %{y} bits<extra></extra>"))
            trials_fig.add_hline(y=128, line_dash="dash", line_color=AMBER,
                                 annotation_text="Expected average: 128 bits",
                                 annotation_position="top right")
            trials_fig.update_layout(title="SHA-256 Avalanche Effect by Trial",
                                     xaxis_title="Single-bit change trial",
                                     yaxis_title="Changed hash bits (out of 256)",
                                     showlegend=False)
            trials_fig.update_yaxes(range=[0, 256])
            plot(style_fig(trials_fig, 310), "avalanche_trials")
        else:
            st.caption("Run Security Experiments again to generate the per-trial avalanche line graph.")

    # ---- SHA-256 collision resistance
    st.subheader("SHA-256 collision resistance")
    if k:
        m1, m2, m3 = st.columns(3)
        with m1:
            metric("Inputs tested", f"{k['inputs_tested']:,}")
        with m2:
            metric("Unique hashes", f"{k['unique_hashes']:,}")
        with m3:
            metric("Collisions found", k["observed_collisions"], "green" if k["observed_collisions"] == 0 else "red")
        t = k["truncated"]
        st.caption("Finding no collisions in a small test does not prove SHA-256 is collision resistant. "
                   f"For comparison, cutting the hash to {t['bits']} bits gave {t['observed_collisions']} collisions "
                   f"in {t['inputs']:,} inputs.")

        collision_fig = go.Figure(go.Bar(x=["Full SHA-256", f"Truncated ({t['bits']} bits)"], y=[k["observed_collisions"], t["observed_collisions"]], marker_color=[TEAL, AMBER], text=[k["observed_collisions"], t["observed_collisions"]], textposition="outside"))
        collision_fig.update_layout(title="Observed Hash Collisions", yaxis_title="Collision count", showlegend=False)
        plot(style_fig(collision_fig, 280), "collision_comparison")
        st.caption("These are observed collisions from different sample tests, not a proof of cryptographic security.")

    # ---- RSA-2048 signature security
    st.subheader("RSA-2048 signature security")
    if r:
        by_name = {t["test"]: t for t in r["tests"]}
        wanted = [("Original signature", "Original evidence, original signature"),
                  ("Modified evidence", "Evidence modified by one bit"),
                  ("Wrong public key", "Verification with an incorrect public key")]
        table([{"Test": shown, "Result": by_name[key]["observed"].capitalize(), "Expected": by_name[key]["expected"].capitalize(),
                "As expected": "Yes" if by_name[key]["passed"] else "NO"} for shown, key in wanted if key in by_name])
        rsa_cases = [(shown, by_name[key]) for shown, key in wanted if key in by_name]
        if rsa_cases:
            rsa_fig = go.Figure(go.Bar(x=[name for name, _ in rsa_cases], y=[1 if item["observed"].lower() in ("valid", "pass", "passed", "success") else 0 for _, item in rsa_cases], marker_color=[TEAL if item["passed"] else RED for _, item in rsa_cases], text=[str(item["observed"]).capitalize() for _, item in rsa_cases], textposition="outside"))
            rsa_fig.update_layout(title="RSA-2048 Verification Outcomes", yaxis_title="Signature valid (1=yes)", yaxis=dict(tickvals=[0, 1], range=[0, 1.25]), showlegend=False)
            plot(style_fig(rsa_fig, 280), "rsa_security_comparison")
        st.caption("A signature only verifies for the exact data and the matching key. "
                   "These tests show signatures detect changes; they do not prove RSA cannot be broken.")


# --------------------------------------------------------------------------- Section C: reports
def _latest_report(svc, incident_id):
    with svc.db.session_scope() as s:
        rec = (s.query(ReportRecord).filter_by(incident_id=incident_id).order_by(ReportRecord.id.desc()).first())
        if rec is None:
            return None
        pdf_p, sig_p = Path(rec.pdf_path), Path(rec.sig_path)
        if not (pdf_p.is_file() and sig_p.is_file()):
            return None
        return {"id": rec.id, "filename": pdf_p.name, "pdf": pdf_p.read_bytes(), "signature": sig_p.read_bytes(),
                "sha256": rec.pdf_sha256, "created_at": rec.created_at}


def _show_verification(out: dict) -> None:
    banner("green" if out["valid"] else "red",
           "SIGNATURE VALID: REPORT UNMODIFIED" if out["valid"] else "SIGNATURE INVALID: REPORT MODIFIED OR WRONG KEY")
    st.caption(out["reason"])


def _section_report(svc):
    incident_id = incident_picker(svc, "report", "Select incident")
    if incident_id is None:
        st.info("No incident exists yet. Analyze a PCAP in Network Investigation first; a report describes one incident.")
        return
    inc = svc.incidents.get(incident_id)

    st.caption("Generate a new report after running performance and security experiments to include their charts. Previously downloaded reports are not updated.")
    if st.button("Generate Signed PDF", type="primary"):
        with guard("generate the report"), st.spinner("Building and signing the report..."):
            data = report_generator.collect(svc.db, svc.incidents, incident_id)
            pdf = report_generator.build_pdf(data)
            report_signer.store_signed_report(svc.db, svc.keys, svc.settings.reports_dir, incident_id, inc["code"], pdf)
            st.session_state["_report_flash"] = f"Report for {inc['code']} generated and signed."
            st.rerun()
    if "_report_flash" in st.session_state:
        st.success(st.session_state.pop("_report_flash"))

    rep = _latest_report(svc, incident_id)
    if rep is None:
        st.info(f"No report has been generated for {inc['code']} yet.")
    else:
        st.caption(f"Latest report: {rep['filename']}  |  SHA-256 {short_hash(rep['sha256'])}")
        c1, c2 = st.columns(2)
        with c1:
            st.download_button("Download Report", rep["pdf"], rep["filename"], "application/pdf", type="primary")
        with c2:
            if st.button("Verify Report Signature"):
                with guard("verify the report"):
                    _show_verification(report_signer.verify_report(rep["pdf"], rep["signature"], svc.keys.public_pem))

    with st.expander("Check a report from files (PDF + signature)", expanded=False):
        st.caption("Upload a report PDF and its .sig file. Change one byte of the PDF to see the signature fail.")
        pdf = st.file_uploader("Report PDF", type=["pdf"], key="vr_pdf")
        sig = st.file_uploader("Signature (.sig)", key="vr_sig")
        pem = st.file_uploader("Public key (.pem), optional: defaults to this app's key", type=["pem"], key="vr_pem")
        if st.button("Verify uploaded report"):
            if not pdf or not sig:
                st.error("Please provide both the PDF and its .sig file.")
            else:
                with guard("verify the uploaded report"):
                    _show_verification(report_signer.verify_report(pdf.getvalue(), sig.getvalue(),
                                                                pem.getvalue() if pem else svc.keys.public_pem))
        if rep is not None:
            d1, d2 = st.columns(2)
            d1.download_button("Download signature (.sig)", rep["signature"], rep["filename"] + ".sig", "application/octet-stream")
            d2.download_button("Download public key (.pem)", svc.keys.public_pem, "netsentinel_rsa_public.pem", "application/x-pem-file")


# --------------------------------------------------------------------------- page
def render(svc):
    st.title("Comparison & Reports")
    st.caption("Measured cryptographic comparisons and signed forensic reports.")
    incident_id = ensure_active_incident(svc)
    tab_a, tab_b, tab_c = st.tabs(["Performance", "Integrity Tests", "Forensic Reports"])
    with tab_a:
        _section_perf(svc, incident_id)
        st.divider()
        _performance_comparison(svc, incident_id)
    with tab_b:
        _section_security(svc, incident_id)
    with tab_c:
        _section_report(svc)
