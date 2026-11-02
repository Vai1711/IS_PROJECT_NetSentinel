"""Detached RSA-2048-PSS-SHA256 signing and verification of report bytes.

This produces a DETACHED signature (report.pdf + report.pdf.sig + public key). It is NOT an
embedded PDF digital signature (PAdES) and PDF viewers will not show it as "signed".
"""
from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature  # noqa: F401  (documented behaviour)

from crypto.keys import KeyStore, load_public_pem, verify_with_public_key
from database.db_manager import DBManager
from database.models import ReportRecord
from evidence import audit
from evidence.integrity import sha256_hex

log = logging.getLogger(__name__)


def sign_report(keys: KeyStore, pdf_bytes: bytes) -> bytes:
    return keys.sign(pdf_bytes)


def verify_report(pdf_bytes: bytes, signature: bytes, public_pem: bytes) -> Dict:
    """Verify with ANY public key (so a third party can check using only the PDF, .sig and .pem)."""
    try:
        pub = load_public_pem(public_pem)
    except ValueError as exc:
        return {"valid": False, "reason": f"Public key could not be read: {exc}", "sha256": sha256_hex(pdf_bytes)}
    ok = verify_with_public_key(pub, pdf_bytes, signature)
    return {"valid": ok, "sha256": sha256_hex(pdf_bytes),
            "reason": "Signature matches the report bytes." if ok else
                      "Signature does NOT match: the report was modified, or the wrong signature/public key was supplied."}


def store_signed_report(db: DBManager, keys: KeyStore, reports_dir: Path, incident_id: int,
                        incident_label: str, pdf_bytes: bytes) -> Dict:
    sig = sign_report(keys, pdf_bytes)
    digest = sha256_hex(pdf_bytes)
    with db.session_scope() as s:
        rec = ReportRecord(incident_id=incident_id, pdf_path="pending", sig_path="pending", pdf_sha256=digest,
                           signature_b64=base64.b64encode(sig).decode())
        s.add(rec)
        s.flush()
        stem = f"{incident_label}_report_{rec.id:03d}"
        pdf_path, sig_path = reports_dir / f"{stem}.pdf", reports_dir / f"{stem}.pdf.sig"
        pdf_path.write_bytes(pdf_bytes)
        sig_path.write_bytes(sig)
        rec.pdf_path, rec.sig_path = str(pdf_path), str(sig_path)
        audit.log_event(s, "REPORT_SIGNED", f"{pdf_path.name} sha256={digest[:16]}... signed with RSA-2048-PSS",
                        incident_id=incident_id)
        rid = rec.id
    return {"id": rid, "pdf_path": str(pdf_path), "sig_path": str(sig_path), "pdf": pdf_bytes,
            "signature": sig, "sha256": digest, "public_pem": keys.public_pem, "filename": pdf_path.name}
