"""Wires the application services together for one data directory."""
from __future__ import annotations

from dataclasses import dataclass

from config import Settings, load_settings
from core.incident_manager import IncidentManager
from crypto.keys import KeyStore
from database.db_manager import DBManager
from detection.engine import DetectionEngine
from evidence.evidence_manager import EvidenceManager
from evidence.integrity import IntegrityEngine
from evidence.tampering import TamperingSimulator
from evidence.verification import Verifier
from ingestion.parser import PcapParser


@dataclass
class Services:
    settings: Settings
    db: DBManager
    keys: KeyStore
    integrity: IntegrityEngine
    incidents: IncidentManager
    evidence: EvidenceManager
    simulator: TamperingSimulator
    verifier: Verifier

    def parser(self) -> PcapParser:
        return PcapParser(self.db)

    def detector(self) -> DetectionEngine:
        return DetectionEngine(self.db)


def build_services(data_dir=None) -> Services:
    st = load_settings(data_dir)
    keys = KeyStore(st.keys_dir)
    # Reuse a key file inside keys_dir for the row-level HMAC seals of packets/flows/alerts.
    db = DBManager(db_path=str(st.db_path), key_path=str(st.keys_dir / "database.hmackey"))
    integ = IntegrityEngine(keys)
    em = EvidenceManager(db, integ, st)
    return Services(st, db, keys, integ, IncidentManager(db), em, TamperingSimulator(db, em, st),
                    Verifier(db, integ, st))
