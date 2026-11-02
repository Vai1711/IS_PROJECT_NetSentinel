import base64
import json
import os
import stat

import pytest
from sqlalchemy.exc import IntegrityError

from conftest import make_png, make_text, make_wav, needs_tshark
from database.models import EvidenceItem, SimulationRecord
from evidence import audit
from evidence.evidence_manager import EvidenceError, sanitize_filename
from evidence.integrity import hamming_bits, sha256_hex


def test_A_register_original_and_verify_successfully(svc, incident_id):
    e = svc.evidence.register(incident_id, "shot.png", make_png((1, 2, 3)))
    assert e["code"].startswith("EV") and e["incident_code"] == f"INC{incident_id:03d}"
    r = svc.verifier.verify(e["id"])
    res = r["result"]
    assert r["verdict"] == "VERIFIED" and res.sha_match and res.hmac_ok and res.rsa_ok and res.reference_ok
    assert res.changed_bits == 0
    assert svc.evidence.get(e["id"])["status"] == "Verified"


def test_B_one_byte_modified_copy_has_sha256_mismatch(svc, incident_id):
    data = make_text()
    e = svc.evidence.register(incident_id, "msg.txt", data)
    tampered = bytearray(data); tampered[5] ^= 1
    res = svc.integrity.verify(bytes(tampered), _ref(svc, e["id"]))
    assert not res.sha_match and sha256_hex(bytes(tampered)) != e["sha256"]


def test_C_hmac_fails_for_modified_evidence(svc, incident_id):
    data = make_wav(seed=11)
    e = svc.evidence.register(incident_id, "rec.wav", data)
    assert svc.integrity.hmac_hex(data) == e["file_hmac"]
    assert svc.integrity.hmac_hex(data[:-2] + b"\x00\x01") != e["file_hmac"]
    res = svc.integrity.verify(data[:-2] + b"\x00\x01", _ref(svc, e["id"]))
    assert res.hmac_ok is False


def test_D_rsa_fails_for_modified_evidence(svc, incident_id):
    data = make_png((9, 9, 9))
    e = svc.evidence.register(incident_id, "s2.png", data)
    assert svc.integrity.verify(data, _ref(svc, e["id"])).rsa_ok is True
    res = svc.integrity.verify(data + b"x", _ref(svc, e["id"]))
    assert res.rsa_ok is False and res.verdict == "TAMPERED"


def test_E_original_unchanged_after_simulation(svc, incident_id):
    e = svc.evidence.register(incident_id, "s3.png", make_png((50, 50, 50)))
    path = e["stored_path"]
    before = open(path, "rb").read()
    mtime = os.stat(path).st_mtime_ns
    ref_before = svc.evidence.get(e["id"])
    for m in ("Change one pixel", "Add text overlay", "Crop part of the image"):
        sim = svc.simulator.simulate(e["id"], m)
        assert sim["modified_path"] != path
    assert open(path, "rb").read() == before and os.stat(path).st_mtime_ns == mtime
    after = svc.evidence.get(e["id"])
    for k in ("sha256", "file_hmac", "manifest_json", "manifest_hmac", "signature_b64"):
        assert ref_before[k] == after[k]                      # reference values never regenerated
    assert not os.access(path, os.W_OK) or os.getuid() == 0   # read-only (root bypasses the check)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o444


def test_F_incident_can_have_multiple_evidence_files(svc, incident_id):
    ids = [svc.evidence.register(incident_id, n, d)["id"] for n, d in
           [("a.png", make_png((7, 7, 7))), ("b.wav", make_wav(seed=21)), ("c.txt", make_text())]]
    listed = {e["id"] for e in svc.evidence.list_for_incident(incident_id)}
    assert set(ids) <= listed and len(listed) >= 3


def test_G_tampering_records_linked_to_correct_incident(ingested):
    svc = ingested["svc"]
    other = ingested["multistage"]["id"]
    e = svc.evidence.register(other, "other.txt", make_text())
    sim = svc.simulator.simulate(e["id"], "Modify an IP address")
    assert sim["incident_id"] == other
    with svc.db.session_scope() as s:
        assert s.get(SimulationRecord, sim["id"]).incident_id == s.get(EvidenceItem, e["id"]).incident_id == other
    assert all(h["Evidence"].startswith(e["code"]) for h in svc.verifier.attack_history(other) if h["Tampering Method"] == "Modify an IP address")


def test_reference_compromise_is_detected(svc, incident_id):
    e = svc.evidence.register(incident_id, "ref.txt", make_text())
    with svc.db.session_scope() as s:
        row = s.get(EvidenceItem, e["id"])
        body = json.loads(row.manifest_json); body["filename"] = "forged.txt"
        row.manifest_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
    r = svc.verifier.verify(e["id"])
    assert r["verdict"] == "REFERENCE_COMPROMISED"


def test_unreferenced_edit_of_stored_file_is_caught(svc, incident_id):
    e = svc.evidence.register(incident_id, "disk.txt", make_text())
    os.chmod(e["stored_path"], 0o644)
    with open(e["stored_path"], "ab") as fh:
        fh.write(b" edited")
    assert svc.verifier.verify(e["id"])["verdict"] == "TAMPERED"
    assert svc.evidence.get(e["id"])["status"] == "Compromised"


def test_wrong_public_key_signature_rejected(svc, incident_id, tmp_path):
    from crypto.keys import KeyStore
    e = svc.evidence.register(incident_id, "wk.txt", make_text())
    other = KeyStore(tmp_path / "other")
    sig = base64.b64decode(e["signature_b64"])
    assert other.verify(e["manifest_json"].encode(), sig) is False
    assert svc.keys.verify(e["manifest_json"].encode(), sig) is True


# ---- input validation ---------------------------------------------------------
def test_path_traversal_filename_is_neutralised(svc, incident_id):
    assert sanitize_filename("../../etc/passwd.txt") == "passwd.txt"
    assert sanitize_filename("..\\..\\evil name?.TXT") == "evil_name_.txt"
    e = svc.evidence.register(incident_id, "../../../../tmp/escape.txt", make_text())
    real = os.path.realpath(e["stored_path"])
    assert real.startswith(str(svc.settings.original_dir.resolve()) + os.sep)
    assert e["filename"] == "escape.txt"


@pytest.mark.parametrize("name,data", [("x.exe", b"MZ"), ("x.png", b"not an image"), ("x.wav", b"RIFFxxxx"),
                                       ("x.txt", b"\xff\xfe\xfa"), ("x.pcap", b"nope" * 20), ("empty.txt", b"")])
def test_invalid_uploads_rejected(svc, incident_id, name, data):
    with pytest.raises(EvidenceError):
        svc.evidence.register(incident_id, name, data)


def test_size_limit_enforced(svc, incident_id, monkeypatch):
    import evidence.evidence_manager as em
    monkeypatch.setitem(em.UPLOAD_LIMITS, "Text", 10)
    with pytest.raises(EvidenceError, match="limited"):
        svc.evidence.register(incident_id, "big.txt", b"a" * 50)


def test_duplicate_file_rejected_for_same_incident(svc, incident_id):
    d = make_text()
    svc.evidence.register(incident_id, "d1.txt", d)
    with pytest.raises(EvidenceError, match="already registered"):
        svc.evidence.register(incident_id, "d2.txt", d)


def test_evidence_requires_real_incident_and_foreign_keys_enforced(svc):
    with pytest.raises(EvidenceError, match="does not exist"):
        svc.evidence.register(9999, "n.txt", make_text())
    with pytest.raises(IntegrityError):
        with svc.db.session_scope() as s:
            s.add(EvidenceItem(incident_id=9999, filename="f", evidence_type="Text", stored_path="p", size_bytes=1,
                               sha256="a", file_hmac="b", manifest_json="{}", manifest_hmac="c", signature_b64="d"))


def test_audit_trail_records_events_and_detects_edits(fresh):
    with fresh.db.session_scope() as s:
        for i in range(4):
            audit.log_event(s, "EVIDENCE_REGISTERED", f"event {i}")
    with fresh.db.session_scope() as s:
        assert audit.verify_chain(s) == (True, None, 4)
    from database.models import AuditEvent
    with fresh.db.session_scope() as s:
        s.query(AuditEvent).filter_by(id=2).one().detail = "rewritten history"
    with fresh.db.session_scope() as s:
        ok, bad, _ = audit.verify_chain(s)
    assert ok is False and bad == 2


def _ref(svc, evidence_id):
    from evidence.evidence_manager import reference_from_row
    with svc.db.session_scope() as s:
        return reference_from_row(s.get(EvidenceItem, evidence_id))
