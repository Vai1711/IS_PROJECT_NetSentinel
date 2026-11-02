"""Upload -> permanent capture file -> parse -> detect. Keeps the ORIGINAL capture on disk."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, Optional

from database.models import CaptureMeta
from evidence.evidence_manager import EvidenceError, sanitize_filename
from evidence.integrity import sha256_hex
from evidence.pcap_tools import analyze_capture_bytes
from config import UPLOAD_LIMITS

log = logging.getLogger(__name__)


def analyze_upload(svc, filename: str, data: bytes) -> Dict:
    """Validate, store permanently, ingest and run detection. Returns a result dict."""
    safe = sanitize_filename(filename)
    if Path(safe).suffix.lower() not in (".pcap", ".pcapng"):
        raise EvidenceError("Please upload a .pcap or .pcapng capture.")
    if len(data) > UPLOAD_LIMITS["PCAP"]:
        raise EvidenceError("Capture files are limited to 100 MB.")
    if not analyze_capture_bytes(data)["valid_header"]:
        raise EvidenceError("This does not look like a valid PCAP/PCAPNG capture.")

    digest = sha256_hex(data)
    with svc.db.session_scope() as s:
        existing = s.query(CaptureMeta).filter_by(file_sha256=digest).first()
        if existing is not None:
            return {"capture_id": existing.id, "duplicate": True, "counts": None,
                    "packets": existing.total_packets, "flows": existing.total_flows}

    dest = svc.settings.captures_dir / f"{digest[:12]}_{safe}"
    if not dest.exists():
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    capture = svc.parser().ingest(str(dest), filename=safe)
    counts = svc.detector().run_all(capture.id)
    log.info("Ingested %s: %d packets, %d flows, %s", safe, capture.total_packets, capture.total_flows, counts)
    return {"capture_id": capture.id, "duplicate": False, "counts": counts,
            "packets": capture.total_packets, "flows": capture.total_flows}
