"""Append-only, hash-chained audit trail.

Each entry stores prev_hash and entry_hash = SHA-256(prev_hash | timestamp | type | ids | detail).
Editing or deleting any earlier row breaks every later hash, which `verify_chain` reports.
(Like all unsigned chains, an attacker able to rewrite the WHOLE table and recompute the
chain could still forge it; the periodic RSA-signed report is the external anchor.)
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from database.models import AuditEvent, utcnow

GENESIS = "0" * 64


def _entry_hash(prev: str, ts, event_type: str, incident_id, evidence_id, detail: str) -> str:
    payload = f"{prev}|{ts.isoformat()}|{event_type}|{incident_id}|{evidence_id}|{detail}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_event(session: Session, event_type: str, detail: str,
              incident_id: Optional[int] = None, evidence_id: Optional[int] = None) -> AuditEvent:
    last = session.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
    prev = last.entry_hash if last else GENESIS
    ts = utcnow()
    ev = AuditEvent(ts=ts, incident_id=incident_id, evidence_id=evidence_id, event_type=event_type,
                    detail=detail, prev_hash=prev,
                    entry_hash=_entry_hash(prev, ts, event_type, incident_id, evidence_id, detail))
    session.add(ev)
    session.flush()
    return ev


def verify_chain(session: Session) -> Tuple[bool, Optional[int], int]:
    """Returns (ok, first_bad_id, entries_checked)."""
    prev, n = GENESIS, 0
    for ev in session.query(AuditEvent).order_by(AuditEvent.id).all():
        n += 1
        expected = _entry_hash(prev, ev.ts, ev.event_type, ev.incident_id, ev.evidence_id, ev.detail)
        if ev.prev_hash != prev or ev.entry_hash != expected:
            return False, ev.id, n
        prev = ev.entry_hash
    return True, None, n
