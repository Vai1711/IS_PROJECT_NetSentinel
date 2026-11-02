"""
database/models.py

SQLAlchemy ORM models for the NetSentinel forensics platform.

Tables
------
CaptureMeta : one row per ingested .pcap/.pcapng file (SHA-256 baseline, counts)
Packet      : one row per parsed packet (L2-L7 metadata)
Flow        : one row per bidirectional 5-tuple conversation
Alert       : one row per detection-engine finding
Incident    : one row per correlated group of alerts (multi-stage attack)

Every row that represents forensic evidence (Packet, Flow, Alert, Incident)
carries an `hmac_tag` column. The tag is computed over a canonical
representation of the row's own columns using a secret key held only by the
`DBManager` (see database/db_manager.py). This lets an examiner detect if a
row has been edited, deleted-and-reinserted, or otherwise tampered with
after ingestion.
"""

from __future__ import annotations

import datetime as _dt
from typing import Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    ForeignKey,
    DateTime,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow() -> _dt.datetime:
    """Naive UTC timestamp (datetime.utcnow() is deprecated)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


class CaptureMeta(Base):
    """Metadata about the ingested capture file itself."""

    __tablename__ = "capture_meta"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(512), nullable=False)
    filepath = Column(String(1024), nullable=False)
    file_sha256 = Column(String(64), nullable=False, index=True)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    total_packets = Column(Integer, nullable=False, default=0)
    total_flows = Column(Integer, nullable=False, default=0)
    capture_start = Column(DateTime, nullable=True)
    capture_end = Column(DateTime, nullable=True)
    ingested_at = Column(DateTime, nullable=False, default=utcnow)
    # HMAC over (filename, file_sha256, file_size_bytes) - the tamper-evident
    # "baseline seal" for the whole capture record.
    hmac_tag = Column(String(64), nullable=False)

    packets = relationship("Packet", back_populates="capture", cascade="all, delete-orphan")
    flows = relationship("Flow", back_populates="capture", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="capture", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="capture", cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<CaptureMeta id={self.id} filename={self.filename!r} sha256={self.file_sha256[:12]}...>"


class Packet(Base):
    """One parsed packet, L2-L7 fields flattened for fast SQL querying."""

    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(Integer, ForeignKey("capture_meta.id"), nullable=False, index=True)

    frame_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    frame_len = Column(Integer, nullable=False, default=0)

    # Layer 2
    src_mac = Column(String(17), nullable=True)
    dst_mac = Column(String(17), nullable=True)
    eth_type = Column(String(16), nullable=True)

    # Layer 3
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    ip_proto = Column(String(16), nullable=True)  # TCP / UDP / ICMP / OTHER
    ttl = Column(Integer, nullable=True)

    # Layer 4
    src_port = Column(Integer, nullable=True, index=True)
    dst_port = Column(Integer, nullable=True, index=True)

    # TCP flags (booleans, decoded individually for rule matching)
    tcp_syn = Column(Boolean, nullable=False, default=False)
    tcp_ack = Column(Boolean, nullable=False, default=False)
    tcp_rst = Column(Boolean, nullable=False, default=False)
    tcp_fin = Column(Boolean, nullable=False, default=False)
    tcp_psh = Column(Boolean, nullable=False, default=False)
    tcp_urg = Column(Boolean, nullable=False, default=False)
    tcp_flags_raw = Column(String(8), nullable=True)  # e.g. "0x002"

    # Application layer
    protocol = Column(String(32), nullable=True, index=True)  # highest-layer protocol name
    dns_query_name = Column(String(255), nullable=True, index=True)
    dns_is_response = Column(Boolean, nullable=False, default=False)
    http_host = Column(String(255), nullable=True)

    is_malformed = Column(Boolean, nullable=False, default=False)
    raw_summary = Column(Text, nullable=True)

    hmac_tag = Column(String(64), nullable=False)

    capture = relationship("CaptureMeta", back_populates="packets")

    __table_args__ = (
        Index("ix_packets_src_dst", "src_ip", "dst_ip"),
        Index("ix_packets_capture_time", "capture_id", "timestamp"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Packet #{self.frame_number} {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}>"


class Flow(Base):
    """Bidirectional 5-tuple conversation aggregated from packets."""

    __tablename__ = "flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(Integer, ForeignKey("capture_meta.id"), nullable=False, index=True)

    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)  # TCP / UDP / ICMP / OTHER

    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    packet_count = Column(Integer, nullable=False, default=0)
    byte_count = Column(Integer, nullable=False, default=0)

    syn_count = Column(Integer, nullable=False, default=0)
    ack_count = Column(Integer, nullable=False, default=0)
    rst_count = Column(Integer, nullable=False, default=0)
    fin_count = Column(Integer, nullable=False, default=0)

    hmac_tag = Column(String(64), nullable=False)

    capture = relationship("CaptureMeta", back_populates="flows")

    __table_args__ = (
        UniqueConstraint(
            "capture_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "start_time",
            name="uq_flow_5tuple_window",
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Flow {self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}>"


class Alert(Base):
    """A single detection-engine finding."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(Integer, ForeignKey("capture_meta.id"), nullable=False, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)

    rule_name = Column(String(128), nullable=False, index=True)
    module = Column(String(64), nullable=False)  # e.g. "Pentesting Detection", "Social Engineering"
    severity = Column(String(16), nullable=False, default="MEDIUM")  # LOW/MEDIUM/HIGH/CRITICAL

    source_ip = Column(String(45), nullable=True, index=True)
    target_ip = Column(String(45), nullable=True, index=True)
    target_port = Column(Integer, nullable=True)

    description = Column(Text, nullable=False)
    evidence_json = Column(Text, nullable=True)  # JSON-encoded supporting evidence

    detected_at = Column(DateTime, nullable=False, default=utcnow)
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)

    hmac_tag = Column(String(64), nullable=False)

    capture = relationship("CaptureMeta", back_populates="alerts")
    incident = relationship("Incident", back_populates="alerts")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.rule_name} {self.source_ip}->{self.target_ip} sev={self.severity}>"


class Incident(Base):
    """A correlated group of alerts representing one multi-stage attack story."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_id = Column(Integer, ForeignKey("capture_meta.id"), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    primary_source_ip = Column(String(45), nullable=True, index=True)
    primary_target_ip = Column(String(45), nullable=True, index=True)

    stage_count = Column(Integer, nullable=False, default=0)
    host_risk_score = Column(Float, nullable=False, default=0.0)  # 0-100
    risk_level = Column(String(16), nullable=False, default="LOW")  # LOW/MEDIUM/HIGH/CRITICAL

    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)

    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    hmac_tag = Column(String(64), nullable=False)

    capture = relationship("CaptureMeta", back_populates="incidents")
    alerts = relationship("Alert", back_populates="incident")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.title} risk={self.host_risk_score}>"


# ---------------------------------------------------------------------------
# Evidence-integrity layer (Evidence Vault / Attacker Simulator / Defender)
# ---------------------------------------------------------------------------

class EvidenceItem(Base):
    """Original forensic evidence file registered against an incident.

    `sha256`, `file_hmac`, `manifest_json`, `manifest_hmac` and `signature_b64`
    are the PROTECTED REFERENCE VALUES. They are written once at registration
    and never regenerated, not even after a tampering simulation.
    """

    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    evidence_type = Column(String(16), nullable=False)  # PCAP / Image / Audio / Text
    source = Column(String(16), nullable=False, default="upload")  # upload / capture
    stored_path = Column(String(1024), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    file_hmac = Column(String(64), nullable=False)
    manifest_json = Column(Text, nullable=False)
    manifest_hmac = Column(String(64), nullable=False)
    signature_b64 = Column(Text, nullable=False)
    registered_at = Column(DateTime, nullable=False, default=utcnow)
    status = Column(String(16), nullable=False, default="Sealed")  # Sealed / Verified / Compromised

    incident = relationship("Incident")

    @property
    def code(self) -> str:
        return f"EV{self.id:03d}"


class SimulationRecord(Base):
    """A SIMULATED tampering attempt, always on a disposable copy."""

    __tablename__ = "simulation_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence_items.id"), nullable=False, index=True)
    method = Column(String(64), nullable=False)
    params_json = Column(Text, nullable=True)
    details_json = Column(Text, nullable=True)
    modified_path = Column(String(1024), nullable=False)
    modified_filename = Column(String(255), nullable=False)
    modified_sha256 = Column(String(64), nullable=False)
    modified_size = Column(Integer, nullable=False)
    is_simulated = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    evidence = relationship("EvidenceItem")


class VerificationRecord(Base):
    """Outcome of one real SHA-256 / HMAC / RSA verification run."""

    __tablename__ = "verification_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence_items.id"), nullable=False, index=True)
    simulation_id = Column(Integer, ForeignKey("simulation_records.id"), nullable=True, index=True)
    subject = Column(String(32), nullable=False)  # "original" / "simulated copy"
    original_sha256 = Column(String(64), nullable=False)
    candidate_sha256 = Column(String(64), nullable=False)
    sha_match = Column(Boolean, nullable=False)
    hmac_ok = Column(Boolean, nullable=False)
    rsa_ok = Column(Boolean, nullable=False)
    reference_ok = Column(Boolean, nullable=False)
    changed_bits = Column(Integer, nullable=False)
    avalanche_pct = Column(Float, nullable=False)
    verdict = Column(String(32), nullable=False)  # VERIFIED / TAMPERED / REFERENCE_COMPROMISED / MISSING
    verified_at = Column(DateTime, nullable=False, default=utcnow)


class AuditEvent(Base):
    """Append-only, hash-chained audit trail (each entry commits to the previous one)."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, default=utcnow)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence_items.id"), nullable=True, index=True)
    event_type = Column(String(48), nullable=False)
    detail = Column(Text, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)


class CryptoRun(Base):
    """Stored result of a Security Analysis experiment (so graphs/reports reuse real data)."""

    __tablename__ = "crypto_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    kind = Column(String(32), nullable=False, index=True)  # benchmark / avalanche / collision / rsa_security
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)


class ReportRecord(Base):
    """A generated, RSA-PSS-signed forensic PDF report."""

    __tablename__ = "report_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False, index=True)
    pdf_path = Column(String(1024), nullable=False)
    sig_path = Column(String(1024), nullable=False)
    pdf_sha256 = Column(String(64), nullable=False)
    signature_b64 = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
