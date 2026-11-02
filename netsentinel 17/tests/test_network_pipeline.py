from pathlib import Path

import pytest

from conftest import DEMO_PCAP, needs_tshark
from core.incident_manager import classify
from core.ingest_service import analyze_upload
from database.models import Alert, Flow, Packet
from evidence.evidence_manager import EvidenceError

pytestmark = needs_tshark


def test_pcap_parsing_and_sqlite_ingestion(ingested):
    svc, res = ingested["svc"], ingested["result"]
    assert (res["packets"], res["flows"]) == (70, 41)
    with svc.db.session_scope() as s:
        assert s.query(Packet).filter_by(capture_id=res["capture_id"]).count() == 70
        assert s.query(Flow).filter_by(capture_id=res["capture_id"]).count() == 41


def test_flows_are_bidirectional_and_account_for_every_packet(ingested):
    svc, cid = ingested["svc"], ingested["result"]["capture_id"]
    with svc.db.session_scope() as s:
        flows = s.query(Flow).filter_by(capture_id=cid).all()
        assert sum(f.packet_count for f in flows) == 70
        keys = {frozenset([(f.src_ip, f.src_port), (f.dst_ip, f.dst_port)]) for f in flows}
        # a bidirectional key would otherwise show up twice (A->B and B->A)
        multi = [f for f in flows if f.packet_count > 1]
        assert multi, "expected conversations with more than one packet"
        for f in multi:
            pkts = s.query(Packet).filter(Packet.capture_id == cid, Packet.protocol.isnot(None),
                                          ((Packet.src_ip == f.src_ip) & (Packet.dst_ip == f.dst_ip)) |
                                          ((Packet.src_ip == f.dst_ip) & (Packet.dst_ip == f.src_ip))).count()
            assert pkts >= f.packet_count


def test_threat_detection_finds_the_three_attack_patterns(ingested):
    svc, cid = ingested["svc"], ingested["result"]["capture_id"]
    with svc.db.session_scope() as s:
        rules = {a.rule_name for a in s.query(Alert).filter_by(capture_id=cid)}
    assert rules == {"Nmap Port Scan", "Hydra SSH Brute-Force", "DNS Typosquatting / Lookalike Domain"}


def test_incident_creation_and_classification(ingested):
    ph, ms = ingested["phishing"], ingested["multistage"]
    d = ingested["svc"].incidents.get(ph["id"])
    assert d["suspicious_domains"] == ["paypa1.com"]
    assert ph["classification"] == "Suspicious pattern"          # one detection stage
    assert ms["classification"] == "Confirmed malicious activity"  # scan + brute force corroborate
    assert classify(1)[0] != classify(2)[0]


def test_original_capture_is_preserved_on_disk(ingested):
    d = ingested["svc"].incidents.get(ingested["phishing"]["id"])
    assert Path(d["capture"]["filepath"]).read_bytes() == DEMO_PCAP.read_bytes()


def test_duplicate_upload_reuses_existing_capture(ingested):
    res = analyze_upload(ingested["svc"], "again.pcap", DEMO_PCAP.read_bytes())
    assert res["duplicate"] and res["capture_id"] == ingested["result"]["capture_id"]


def test_non_pcap_upload_rejected(ingested):
    with pytest.raises(EvidenceError):
        analyze_upload(ingested["svc"], "notes.pcap", b"this is not a capture at all, just text" * 5)
