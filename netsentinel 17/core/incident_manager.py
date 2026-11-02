"""Incident queries and classification, built on the detection engine's Incident/Alert rows."""
from __future__ import annotations

import json
import re
from typing import Dict, List, Optional

from database.db_manager import DBManager
from database.models import Alert, CaptureMeta, Incident, Packet


def incident_code(incident_id: int) -> str:
    return f"INC{incident_id:03d}"


def classify(stage_count: int) -> tuple:
    """Suspicious pattern vs confirmed malicious.

    A single heuristic hit is only a suspicious PATTERN. We call an incident 'Confirmed malicious
    activity' only when two or more independent detection stages from the same source corroborate
    each other (e.g. port scan followed by SSH brute force). Traffic analysis alone can never prove
    intent, so this is corroboration-based, not a proof.
    """
    if stage_count >= 2:
        return "Confirmed malicious activity", "Corroborated by %d independent detection stages." % stage_count
    return "Suspicious pattern", "Single detection stage: a heuristic indicator that needs analyst confirmation."


class IncidentManager:
    def __init__(self, db: DBManager):
        self.db = db

    def list(self, capture_id: Optional[int] = None) -> List[Dict]:
        with self.db.session_scope() as s:
            q = s.query(Incident)
            if capture_id is not None:
                q = q.filter(Incident.capture_id == capture_id)
            return [self._brief(i) for i in q.order_by(Incident.host_risk_score.desc(), Incident.id)]

    @staticmethod
    def _brief(i: Incident) -> Dict:
        cls, why = classify(i.stage_count)
        return {"id": i.id, "code": incident_code(i.id), "title": i.title, "capture_id": i.capture_id,
                "source_ip": i.primary_source_ip, "target_ip": i.primary_target_ip, "stages": i.stage_count,
                "risk_score": i.host_risk_score, "risk_level": i.risk_level, "start": i.start_time,
                "end": i.end_time, "classification": cls, "classification_reason": why, "summary": i.summary}

    def get(self, incident_id: int) -> Optional[Dict]:
        with self.db.session_scope() as s:
            inc = s.get(Incident, incident_id)
            if inc is None:
                return None
            d = self._brief(inc)
            cap = s.get(CaptureMeta, inc.capture_id)
            d["capture"] = {"id": cap.id, "filename": cap.filename, "filepath": cap.filepath,
                            "sha256": cap.file_sha256, "packets": cap.total_packets, "flows": cap.total_flows,
                            "start": cap.capture_start, "end": cap.capture_end}
            alerts = s.query(Alert).filter_by(incident_id=inc.id).order_by(Alert.window_start).all()
            d["alerts"] = []
            domains = []
            for a in alerts:
                ev = json.loads(a.evidence_json or "{}")
                if "queried_domain" in ev:
                    domains.append(ev["queried_domain"])
                d["alerts"].append({"id": a.id, "rule": a.rule_name, "module": a.module, "severity": a.severity,
                                    "source": a.source_ip, "target": a.target_ip, "port": a.target_port,
                                    "start": a.window_start, "end": a.window_end, "description": a.description,
                                    "evidence": ev})
            d["suspicious_domains"] = domains
            d["detected_threats"] = sorted({a["rule"] for a in d["alerts"]})
            return d

    def related_packets(self, incident_id: int, limit: int = 200) -> List[Dict]:
        with self.db.session_scope() as s:
            inc = s.get(Incident, incident_id)
            if inc is None:
                return []
            q = s.query(Packet).filter(Packet.capture_id == inc.capture_id)
            ips = [x for x in (inc.primary_source_ip, inc.primary_target_ip) if x]
            if ips:
                q = q.filter(Packet.src_ip.in_(ips) | Packet.dst_ip.in_(ips))
            if inc.start_time and inc.end_time:
                import datetime as dt
                pad = dt.timedelta(seconds=120)
                q = q.filter(Packet.timestamp >= inc.start_time - pad, Packet.timestamp <= inc.end_time + pad)
            return [{"Frame": p.frame_number, "Time": p.timestamp, "Src": f"{p.src_ip}:{p.src_port or ''}",
                     "Dst": f"{p.dst_ip}:{p.dst_port or ''}", "Proto": p.protocol, "DNS": p.dns_query_name,
                     "Bytes": p.frame_len} for p in q.order_by(Packet.timestamp).limit(limit)]
