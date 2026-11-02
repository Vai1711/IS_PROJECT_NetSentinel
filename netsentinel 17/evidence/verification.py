"""Defender verification: compares a candidate file with the PROTECTED reference record."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

from config import Settings
from database.db_manager import DBManager
from database.models import EvidenceItem, SimulationRecord, VerificationRecord
from evidence import audit
from evidence.evidence_manager import EvidenceError, reference_from_row
from evidence.integrity import IntegrityEngine

log = logging.getLogger(__name__)


class Verifier:
    def __init__(self, db: DBManager, engine: IntegrityEngine, settings: Settings):
        self.db, self.engine, self.settings = db, engine, settings

    def verify(self, evidence_id: int, simulation_id: Optional[int] = None) -> Dict:
        with self.db.session_scope() as s:
            ev = s.get(EvidenceItem, evidence_id)
            if ev is None:
                raise EvidenceError(f"Evidence {evidence_id} not found.")
            sim = None
            if simulation_id is not None:
                sim = s.get(SimulationRecord, simulation_id)
                if sim is None or sim.evidence_id != evidence_id:
                    raise EvidenceError("That simulated copy does not belong to the selected evidence.")
                path = Path(sim.modified_path).resolve()
                if self.settings.simulated_dir.resolve() not in path.parents:
                    raise EvidenceError("Simulated copy is outside the simulation directory.")
            else:
                path = Path(ev.stored_path)
            subject = "simulated copy" if sim else "original"
            ref = reference_from_row(ev)
            if not path.is_file():
                rec = VerificationRecord(
                    incident_id=ev.incident_id, evidence_id=ev.id, simulation_id=simulation_id, subject=subject,
                    original_sha256=ev.sha256, candidate_sha256="0" * 64, sha_match=False, hmac_ok=False,
                    rsa_ok=False, reference_ok=True, changed_bits=0, avalanche_pct=0.0, verdict="MISSING")
                s.add(rec)
                if not sim:
                    ev.status = "Compromised"
                audit.log_event(s, "VERIFICATION_FAILED", f"{ev.code} {subject}: file missing from disk",
                                incident_id=ev.incident_id, evidence_id=ev.id)
                s.flush()
                return {"id": rec.id, "verdict": "MISSING", "subject": subject, "message": "Evidence file is missing."}

            res = self.engine.verify(path.read_bytes(), ref)
            rec = VerificationRecord(
                incident_id=ev.incident_id, evidence_id=ev.id, simulation_id=simulation_id, subject=subject,
                original_sha256=res.original_sha256, candidate_sha256=res.candidate_sha256,
                sha_match=res.sha_match, hmac_ok=res.hmac_ok, rsa_ok=res.rsa_ok, reference_ok=res.reference_ok,
                changed_bits=res.changed_bits, avalanche_pct=res.avalanche_pct, verdict=res.verdict)
            s.add(rec)
            if not sim:
                ev.status = "Verified" if res.verdict == "VERIFIED" else "Compromised"
            audit.log_event(
                s, "VERIFICATION_PASSED" if res.verdict == "VERIFIED" else "VERIFICATION_FAILED",
                f"{ev.code} {subject}: {res.verdict} (sha={'match' if res.sha_match else 'MISMATCH'}, "
                f"hmac={'ok' if res.hmac_ok else 'FAIL'}, rsa={'ok' if res.rsa_ok else 'INVALID'}, "
                f"{res.changed_bits}/256 digest bits differ)", incident_id=ev.incident_id, evidence_id=ev.id)
            s.flush()
            return {"id": rec.id, "verdict": res.verdict, "subject": subject, "result": res,
                    "evidence_code": ev.code, "candidate_path": str(path)}

    # ------------------------------------------------------------------ history
    def attack_history(self, incident_id: int) -> List[Dict]:
        """One row per stored simulation, joined with its LATEST real verification (if any)."""
        rows = []
        with self.db.session_scope() as s:
            for sim in s.query(SimulationRecord).filter_by(incident_id=incident_id).order_by(SimulationRecord.id):
                ver = (s.query(VerificationRecord).filter_by(simulation_id=sim.id)
                       .order_by(VerificationRecord.id.desc()).first())
                ev = s.get(EvidenceItem, sim.evidence_id)
                rows.append({
                    "Evidence": f"{ev.code} ({ev.evidence_type})", "Tampering Method": sim.method,
                    "Hash Result": "Not yet verified" if ver is None else ("Match" if ver.sha_match else "Mismatch"),
                    "HMAC Result": "Not yet verified" if ver is None else ("Valid" if ver.hmac_ok else "Invalid"),
                    "Signature Result": "Not yet verified" if ver is None else ("Valid" if ver.rsa_ok else "Invalid"),
                    "Bits Changed": None if ver is None else ver.changed_bits,
                    "Simulated At": sim.created_at, "Verified At": None if ver is None else ver.verified_at,
                })
        return rows

    def control_history(self, incident_id: int) -> List[Dict]:
        with self.db.session_scope() as s:
            q = (s.query(VerificationRecord).filter_by(incident_id=incident_id, subject="original")
                 .order_by(VerificationRecord.id))
            return [{"Evidence": f"EV{v.evidence_id:03d}", "Subject": "Untouched original", "Verdict": v.verdict,
                     "Hash": "Match" if v.sha_match else "Mismatch", "HMAC": "Valid" if v.hmac_ok else "Invalid",
                     "Signature": "Valid" if v.rsa_ok else "Invalid", "Verified At": v.verified_at} for v in q]
