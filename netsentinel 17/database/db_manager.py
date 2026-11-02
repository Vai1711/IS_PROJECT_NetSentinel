"""
database/db_manager.py

SQLite initialization, transaction helpers, and the tamper-evidence layer
for NetSentinel.

Tamper-evidence design
-----------------------
Each forensic row (Packet, Flow, Alert, Incident, CaptureMeta) stores an
`hmac_tag` computed as:

    HMAC-SHA256(secret_key, canonical_string(row_fields))

`canonical_string` sorts fields by name and joins them with a fixed
separator so the tag is deterministic regardless of dict ordering. The
secret key is generated once per database (stored in a local key file,
never inside the DB itself) so an attacker who only has write access to
the SQLite file cannot forge valid tags without also obtaining the key
file.

`DBManager.verify_integrity()` recomputes every row's tag and compares it
(constant-time) against the stored tag, returning a structured report of
any row that fails verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Type

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session

from .models import Base, CaptureMeta, Packet, Flow, Alert, Incident

DEFAULT_DB_PATH = "netsentinel.db"
DEFAULT_KEY_PATH = "netsentinel.hmackey"

# Columns excluded from the HMAC canonicalization for each model: the tag
# column itself, autoincrement PKs (assigned by SQLite, not evidence), and
# ORM-only relationship attributes are never SQLAlchemy Columns so they're
# excluded automatically.
_EXCLUDED_COLUMNS = {"hmac_tag", "id"}


def _row_canonical_string(model_cls, field_values: dict) -> str:
    """Build a deterministic string from a row's field values."""
    parts = []
    for key in sorted(field_values.keys()):
        if key in _EXCLUDED_COLUMNS:
            continue
        parts.append(f"{key}={field_values[key]!r}")
    return "|".join(parts)


def _extract_fields(obj) -> dict:
    mapper = obj.__mapper__
    return {col.key: getattr(obj, col.key) for col in mapper.columns}


class DBManager:
    """Owns the SQLite engine/session and all tamper-evidence operations."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, key_path: str = DEFAULT_KEY_PATH):
        self.db_path = db_path
        self.key_path = key_path
        self._secret_key = self._load_or_create_key(key_path)

        self.engine = create_engine(f"sqlite:///{db_path}", future=True)

        # SQLite PRAGMAs are PER CONNECTION. The original code ran PRAGMA foreign_keys=ON on one
        # throw-away connection, so foreign keys were not enforced on the pooled connections that
        # actually served queries. Apply it to every new connection instead.
        @event.listens_for(self.engine, "connect")
        def _set_pragmas(dbapi_conn, _record):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)

    # ------------------------------------------------------------------
    # setup helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_or_create_key(key_path: str) -> bytes:
        p = Path(key_path)
        if p.exists():
            return p.read_bytes()
        key = secrets.token_bytes(32)
        p.write_bytes(key)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return key

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Provide a transactional scope around a series of operations."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------
    # file hashing
    # ------------------------------------------------------------------
    @staticmethod
    def sha256_file(filepath: str, chunk_size: int = 1024 * 1024) -> str:
        """Compute the SHA-256 baseline hash of a capture file on disk."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()

    # ------------------------------------------------------------------
    # HMAC tagging
    # ------------------------------------------------------------------
    def compute_hmac(self, obj) -> str:
        """Compute the HMAC-SHA256 tag for an ORM instance's current field values."""
        fields = _extract_fields(obj)
        canonical = _row_canonical_string(type(obj), fields)
        canonical = f"{obj.__tablename__}::{canonical}"
        return hmac.new(self._secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def seal(self, obj) -> None:
        """Compute and set the hmac_tag field on a row before insert."""
        obj.hmac_tag = self.compute_hmac(obj)

    def verify_row(self, obj) -> bool:
        expected = self.compute_hmac(obj)
        stored = obj.hmac_tag or ""
        return hmac.compare_digest(expected, stored)

    def verify_integrity(self, session: Optional[Session] = None) -> dict:
        """
        Recompute and check the HMAC tag of every forensic row in the
        database. Returns a report:

            {
                "ok": bool,
                "checked": int,
                "failed": [
                    {"table": "packets", "id": 42, "reason": "hmac_mismatch"},
                    ...
                ],
            }
        """
        owns_session = session is None
        session = session or self.SessionLocal()
        failed: List[dict] = []
        checked = 0
        try:
            for model_cls in (CaptureMeta, Packet, Flow, Alert, Incident):
                for row in session.query(model_cls).all():
                    checked += 1
                    if not self.verify_row(row):
                        failed.append(
                            {
                                "table": model_cls.__tablename__,
                                "id": row.id,
                                "reason": "hmac_mismatch",
                            }
                        )
        finally:
            if owns_session:
                session.close()

        return {"ok": len(failed) == 0, "checked": checked, "failed": failed}

    def verify_capture_file(self, capture_meta: CaptureMeta, filepath: str) -> bool:
        """Re-hash the on-disk capture file and compare against the stored baseline."""
        try:
            current_hash = self.sha256_file(filepath)
        except FileNotFoundError:
            return False
        return hmac.compare_digest(current_hash, capture_meta.file_sha256)

    # ------------------------------------------------------------------
    # generic insert helpers (used by ingestion/detection modules)
    # ------------------------------------------------------------------
    def add_sealed(self, session: Session, obj) -> None:
        """
        Insert an object and seal (HMAC) it in one call.

        Column defaults (e.g. Boolean/False, nullable-with-default columns)
        are only materialized onto the in-memory instance by SQLAlchemy at
        flush time - sealing before that point would compute a tag over
        `None` placeholders that later read back as their real default
        values, breaking verification. So we add + flush first (INSERT with
        defaults applied), then compute the tag against the now-complete
        row and flush again (UPDATE of just hmac_tag).
        """
        obj.hmac_tag = obj.hmac_tag or "PENDING"  # satisfy NOT NULL for the first INSERT
        session.add(obj)
        session.flush()
        self.seal(obj)
        session.flush()

    def bulk_add_sealed(self, session: Session, objs: Sequence) -> None:
        if not objs:
            return
        for obj in objs:
            obj.hmac_tag = obj.hmac_tag or "PENDING"  # satisfy NOT NULL for the first INSERT
        session.add_all(objs)
        session.flush()
        for obj in objs:
            self.seal(obj)
        session.flush()

    def reseal(self, obj) -> None:
        """Recompute and overwrite hmac_tag after mutating a row's fields."""
        obj.hmac_tag = self.compute_hmac(obj)
