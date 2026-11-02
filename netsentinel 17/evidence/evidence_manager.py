"""Registers, stores and reads original forensic evidence.

Security properties implemented here
------------------------------------
* filenames are reduced to a safe basename (no path traversal), extension must match the type
* type is validated by content (magic bytes / decoder), not just by extension
* per-type size limits; uploaded files are only ever read as bytes, never executed
* originals are written exclusively (never overwritten) and made read-only
* every registration is bound to a real incident row (FK) and written to the audit trail
"""
from __future__ import annotations

import io
import logging
import os
import re
import wave
from pathlib import Path
from typing import Dict, List, Optional

from PIL import Image

from config import ALLOWED_EXTENSIONS, UPLOAD_LIMITS, Settings
from database.db_manager import DBManager
from database.models import EvidenceItem, Incident, utcnow
from evidence import audit
from evidence.integrity import IntegrityEngine, ReferenceRecord
from evidence.pcap_tools import analyze_capture_bytes

import base64

log = logging.getLogger(__name__)


class EvidenceError(ValueError):
    """User-facing validation/registration problem (message is safe to show)."""


def incident_code(incident_id: int) -> str:
    return f"INC{incident_id:03d}"


def sanitize_filename(name: str) -> str:
    base = Path(str(name).replace("\\", "/")).name          # drop any directory components
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    stem = stem[:80] or "file"
    return f"{stem}.{ext.lower()}" if ext else stem


def detect_type(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    for etype, exts in ALLOWED_EXTENSIONS.items():
        if ext in exts:
            return etype
    allowed = ", ".join(sorted(e for s in ALLOWED_EXTENSIONS.values() for e in s))
    raise EvidenceError(f"Unsupported file type '{ext or filename}'. Allowed: {allowed}.")


def validate_content(evidence_type: str, data: bytes) -> None:
    if not data:
        raise EvidenceError("The file is empty.")
    limit = UPLOAD_LIMITS[evidence_type]
    if len(data) > limit:
        raise EvidenceError(f"{evidence_type} files are limited to {limit // (1024 * 1024)} MB.")
    if evidence_type == "PCAP":
        info = analyze_capture_bytes(data)
        if not info["valid_header"]:
            raise EvidenceError("This does not look like a valid PCAP/PCAPNG capture.")
    elif evidence_type == "Image":
        try:
            with Image.open(io.BytesIO(data)) as im:
                im.verify()
        except Exception as exc:  # PIL raises many types for bad images
            raise EvidenceError(f"This is not a readable PNG/JPEG image ({exc.__class__.__name__}).") from exc
    elif evidence_type == "Audio":
        try:
            with wave.open(io.BytesIO(data)) as w:
                if w.getsampwidth() != 2:
                    raise EvidenceError("Only 16-bit PCM WAV audio is supported.")
        except (wave.Error, EOFError) as exc:
            raise EvidenceError(f"This is not a readable PCM WAV file ({exc}).") from exc
    elif evidence_type == "Text":
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvidenceError("Text evidence must be UTF-8 encoded.") from exc


def reference_from_row(row: EvidenceItem) -> ReferenceRecord:
    return ReferenceRecord(
        sha256=row.sha256, size=row.size_bytes, file_hmac=row.file_hmac,
        manifest_json=row.manifest_json, manifest_hmac=row.manifest_hmac,
        signature=base64.b64decode(row.signature_b64),
    )


class EvidenceManager:
    def __init__(self, db: DBManager, engine: IntegrityEngine, settings: Settings):
        self.db, self.engine, self.settings = db, engine, settings

    # ------------------------------------------------------------------
    def register(self, incident_id: int, filename: str, data: bytes, source: str = "upload") -> Dict:
        safe = sanitize_filename(filename)
        etype = detect_type(safe)
        validate_content(etype, data)

        dest: Optional[Path] = None
        with self.db.session_scope() as s:
            inc = s.get(Incident, incident_id)
            if inc is None:
                raise EvidenceError(f"Incident {incident_id} does not exist.")
            sha = self.engine.seal(data, {}).sha256
            dup = s.query(EvidenceItem).filter_by(incident_id=incident_id, sha256=sha).first()
            if dup is not None:
                raise EvidenceError(f"This exact file is already registered as {dup.code} ({dup.filename}).")

            row = EvidenceItem(
                incident_id=incident_id, filename=safe, evidence_type=etype, source=source,
                stored_path="pending", size_bytes=len(data), sha256="pending", file_hmac="pending",
                manifest_json="{}", manifest_hmac="pending", signature_b64="pending",
            )
            s.add(row)
            s.flush()                                   # assigns the id -> evidence code
            registered_at = utcnow()
            row.registered_at = registered_at
            meta = {"evidence_id": row.code, "incident_id": incident_code(incident_id),
                    "filename": safe, "evidence_type": etype,
                    "registered_at": registered_at.isoformat(timespec="seconds") + "Z"}
            seal = self.engine.seal(data, meta)
            row.sha256, row.file_hmac = seal.sha256, seal.file_hmac
            row.manifest_json, row.manifest_hmac = seal.manifest_json, seal.manifest_hmac
            row.signature_b64 = seal.signature_b64

            folder = self._safe_dir(self.settings.original_dir, incident_code(incident_id))
            dest = folder / f"{row.code}_{safe}"
            try:
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)   # never overwrite
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
            except OSError as exc:
                raise EvidenceError(f"Could not store the evidence file: {exc}") from exc
            row.stored_path = str(dest)
            audit.log_event(s, "EVIDENCE_REGISTERED",
                            f"{row.code} {safe} ({etype}, {len(data)} bytes) sha256={seal.sha256[:16]}... "
                            f"sealed with HMAC-SHA256 + RSA-2048-PSS",
                            incident_id=incident_id, evidence_id=row.id)
            result = self.describe(row)
        log.info("Registered %s for %s", result["code"], incident_code(incident_id))
        return result

    def register_capture_file(self, incident_id: int, capture_path: str, display_name: str) -> Dict:
        p = Path(capture_path)
        if not p.is_file():
            raise EvidenceError("The original capture file is no longer on disk, so it cannot be registered.")
        return self.register(incident_id, display_name, p.read_bytes(), source="capture")

    # ------------------------------------------------------------------
    @staticmethod
    def _safe_dir(base: Path, *parts: str) -> Path:
        target = base.joinpath(*parts).resolve()
        if base.resolve() not in target.parents and target != base.resolve():
            raise EvidenceError("Refusing to write outside the evidence directory.")
        target.mkdir(parents=True, exist_ok=True)
        return target

    @staticmethod
    def describe(row: EvidenceItem) -> Dict:
        return {
            "id": row.id, "code": row.code, "incident_id": row.incident_id,
            "incident_code": incident_code(row.incident_id), "filename": row.filename,
            "type": row.evidence_type, "source": row.source, "size": row.size_bytes,
            "sha256": row.sha256, "file_hmac": row.file_hmac, "manifest_hmac": row.manifest_hmac,
            "manifest_json": row.manifest_json, "signature_b64": row.signature_b64,
            "registered_at": row.registered_at, "status": row.status, "stored_path": row.stored_path,
        }

    def list_for_incident(self, incident_id: int) -> List[Dict]:
        with self.db.session_scope() as s:
            rows = s.query(EvidenceItem).filter_by(incident_id=incident_id).order_by(EvidenceItem.id).all()
            return [self.describe(r) for r in rows]

    def get(self, evidence_id: int) -> Dict:
        with self.db.session_scope() as s:
            row = s.get(EvidenceItem, evidence_id)
            if row is None:
                raise EvidenceError(f"Evidence {evidence_id} not found.")
            return self.describe(row)

    def read_original(self, evidence_id: int) -> bytes:
        info = self.get(evidence_id)
        path = Path(info["stored_path"])
        if not path.is_file():
            raise EvidenceError(f"The stored original of {info['code']} is missing from disk.")
        return path.read_bytes()
