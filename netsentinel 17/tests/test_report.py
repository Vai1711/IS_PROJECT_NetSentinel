import json

import pytest
from reportlab import rl_config

from conftest import make_text, needs_tshark
from crypto.keys import KeyStore
from database.models import CryptoRun
from reports import report_generator, report_signer

pytestmark = needs_tshark


@pytest.fixture()
def report(ingested, monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)       # so text is searchable in the raw bytes
    svc, inc = ingested["svc"], ingested["multistage"]["id"]
    e = svc.evidence.register(inc, "rep.txt", make_text())
    sim = svc.simulator.simulate(e["id"], "Replace a URL")
    svc.verifier.verify(e["id"], sim["id"]); svc.verifier.verify(e["id"])
    with svc.db.session_scope() as s:
        s.add(CryptoRun(kind="avalanche", result_json=json.dumps(
            {"differing_bits": 130, "avalanche_pct": 50.8, "trials": 10, "mean_pct": 50.1})))
    data = report_generator.collect(svc.db, svc.incidents, inc)
    pdf = report_generator.build_pdf(data)
    return svc, inc, pdf, report_signer.store_signed_report(svc.db, svc.keys, svc.settings.reports_dir, inc, "INC", pdf)


def test_report_contains_real_investigation_data(report):
    svc, inc, pdf, _ = report
    assert pdf.startswith(b"%PDF")
    for needle in (b"NetSentinel Forensic Report", b"Confirmed malicious activity", b"10.0.0.66", b"Hydra SSH Brute-Force",
                   b"SIMULATED", b"Replace a URL", b"TAMPERED", b"avalanche", b"Evidence register"):
        assert needle in pdf, needle
    assert svc.keys.private_path.read_bytes()[:30] not in pdf and svc.keys.hmac_key not in pdf   # no secrets in the report


def test_H_signature_verifies_and_fails_after_modification(report):
    svc, _, pdf, rep = report
    ok = report_signer.verify_report(pdf, rep["signature"], rep["public_pem"])
    assert ok["valid"] is True and ok["sha256"] == rep["sha256"]
    assert report_signer.verify_report(pdf + b"\n%tampered", rep["signature"], rep["public_pem"])["valid"] is False
    flipped = bytearray(rep["signature"]); flipped[10] ^= 1
    assert report_signer.verify_report(pdf, bytes(flipped), rep["public_pem"])["valid"] is False


def test_report_signature_rejected_with_wrong_public_key(report, tmp_path):
    _, _, pdf, rep = report
    other = KeyStore(tmp_path / "k")
    assert report_signer.verify_report(pdf, rep["signature"], other.public_pem)["valid"] is False
    assert report_signer.verify_report(pdf, rep["signature"], b"not a pem")["valid"] is False


def test_stored_report_files_match_database(report):
    from pathlib import Path
    svc, _, pdf, rep = report
    assert Path(rep["pdf_path"]).read_bytes() == pdf
    assert report_signer.verify_report(pdf, Path(rep["sig_path"]).read_bytes(), svc.keys.public_pem)["valid"]
