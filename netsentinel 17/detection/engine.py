"""
detection/engine.py

Deterministic, rule-based threat detection over the ingested Packet/Flow
tables, plus incident correlation and host risk scoring.

Module 1 - Pentesting Detection
    - Nmap Port Scan Rule
    - Hydra SSH Brute-Force Rule

Module 9 - Social Engineering / Phishing Detection
    - DNS Typosquatting / Lookalike Detector

Incident Correlation
    - Groups alerts that share a source IP within a configurable time
      window into a single Incident.
    - Computes a 0-100 Host Risk Score.

All rules operate on data already persisted by ingestion/parser.py.
"""

from __future__ import annotations

import datetime as _dt
import difflib
import json
import logging

from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from database.db_manager import DBManager
from database.models import Packet, Alert, Incident


logger = logging.getLogger("netsentinel.detection")


# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

PORT_SCAN_DISTINCT_PORTS = 20
PORT_SCAN_WINDOW_SECONDS = 10

SSH_BRUTE_PORT = 22
SSH_BRUTE_MIN_ATTEMPTS = 5
SSH_BRUTE_WINDOW_SECONDS = 10

PHISHING_TARGET_DOMAINS = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
]

PHISHING_SIM_LOW = 0.75
PHISHING_SIM_HIGH = 1.0

CORRELATION_WINDOW_SECONDS = 300

SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 45,
    "CRITICAL": 70,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tcp_flag_combo(pkt: Packet) -> str:
    """
    Return a short label for TCP probe combinations useful for
    identifying common Nmap-style scans.
    """

    if (
        pkt.tcp_syn
        and not pkt.tcp_ack
        and not pkt.tcp_fin
        and not pkt.tcp_rst
        and not pkt.tcp_psh
        and not pkt.tcp_urg
    ):
        return "SYN"

    if not any(
        [
            pkt.tcp_syn,
            pkt.tcp_ack,
            pkt.tcp_fin,
            pkt.tcp_rst,
            pkt.tcp_psh,
            pkt.tcp_urg,
        ]
    ):
        return "NULL"

    if (
        pkt.tcp_fin
        and not pkt.tcp_syn
        and not pkt.tcp_ack
        and not pkt.tcp_rst
        and not pkt.tcp_psh
        and not pkt.tcp_urg
    ):
        return "FIN"

    if (
        pkt.tcp_fin
        and pkt.tcp_psh
        and pkt.tcp_urg
        and not pkt.tcp_syn
        and not pkt.tcp_ack
        and not pkt.tcp_rst
    ):
        return "XMAS"

    return ""


def _sliding_windows(
    events: List[_dt.datetime],
    window_seconds: int,
) -> List[List[int]]:
    """
    Return groups of event indexes whose timestamps fall inside the
    specified time window.
    """

    groups: List[List[int]] = []

    n = len(events)

    if n == 0:
        return groups

    start = 0

    for end in range(n):

        while (
            start <= end
            and events[end] - events[start]
            > _dt.timedelta(seconds=window_seconds)
        ):
            start += 1

        groups.append(
            list(range(start, end + 1))
        )

    return groups


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:

    def __init__(
        self,
        db_manager: DBManager,
    ):
        self.db = db_manager

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run_all(
        self,
        capture_id: int,
    ) -> Dict[str, int]:

        counts = {
            "port_scan": 0,
            "ssh_bruteforce": 0,
            "dns_typosquat": 0,
            "incidents": 0,
        }

        with self.db.session_scope() as session:

            counts["port_scan"] = (
                self._detect_port_scans(
                    session,
                    capture_id,
                )
            )

            counts["ssh_bruteforce"] = (
                self._detect_ssh_bruteforce(
                    session,
                    capture_id,
                )
            )

            counts["dns_typosquat"] = (
                self._detect_dns_typosquatting(
                    session,
                    capture_id,
                )
            )

            session.flush()

            counts["incidents"] = (
                self._correlate_incidents(
                    session,
                    capture_id,
                )
            )

        return counts

    # ------------------------------------------------------------------
    # Module 1a: Nmap Port Scan
    # ------------------------------------------------------------------

    def _detect_port_scans(
        self,
        session: Session,
        capture_id: int,
    ) -> int:

        packets: List[Packet] = (
            session.query(Packet)
            .filter(
                Packet.capture_id == capture_id,
                Packet.src_ip.isnot(None),
                Packet.ip_proto == "TCP",
            )
            .order_by(
                Packet.src_ip,
                Packet.timestamp,
            )
            .all()
        )

        by_src: Dict[
            str,
            List[Packet],
        ] = defaultdict(list)

        for p in packets:

            # Ignore normal server response packets.
            #
            # SYN+ACK represents a response to a connection request,
            # rather than an initiating scan probe.
            if p.tcp_syn and p.tcp_ack:
                continue

            # Pure ACK/RST response packets should also not create
            # port-scan evidence.
            if (
                p.tcp_ack
                and not p.tcp_syn
                and not p.tcp_fin
                and not p.tcp_psh
                and not p.tcp_urg
            ):
                continue

            by_src[p.src_ip].append(p)

        created = 0

        for src_ip, pkts in by_src.items():

            pkts.sort(
                key=lambda p: p.timestamp
            )

            timestamps = [
                p.timestamp
                for p in pkts
            ]

            windows = _sliding_windows(
                timestamps,
                PORT_SCAN_WINDOW_SECONDS,
            )

            last_alert_end = -1

            for idx_group in windows:

                if not idx_group:
                    continue

                window_pkts = [
                    pkts[i]
                    for i in idx_group
                ]

                distinct_ports = {
                    p.dst_port
                    for p in window_pkts
                    if p.dst_port is not None
                }

                abnormal_flags = {}

                for p in window_pkts:

                    if p.dst_port is None:
                        continue

                    combo = _tcp_flag_combo(p)

                    if combo:
                        abnormal_flags[
                            p.dst_port
                        ] = combo

                triggers_by_count = (
                    len(distinct_ports)
                    > PORT_SCAN_DISTINCT_PORTS
                )

                # Three or more scan-like TCP probes to different ports
                # provide enough evidence for the lab demonstration.
                triggers_by_flags = (
                    len(abnormal_flags) >= 3
                )

                if not (
                    triggers_by_count
                    or triggers_by_flags
                ):
                    continue

                start_idx = idx_group[0]
                end_idx = idx_group[-1]

                # Avoid duplicate alerts from overlapping windows.
                if start_idx <= last_alert_end:
                    continue

                last_alert_end = end_idx

                target_ips = sorted(
                    {
                        p.dst_ip
                        for p in window_pkts
                        if p.dst_ip
                    }
                )

                reason = []

                if triggers_by_count:

                    reason.append(
                        f"{len(distinct_ports)} distinct ports "
                        f"in {PORT_SCAN_WINDOW_SECONDS}s"
                    )

                if triggers_by_flags:

                    combo_summary = ", ".join(
                        sorted(
                            set(
                                abnormal_flags.values()
                            )
                        )
                    )

                    reason.append(
                        "abnormal TCP flag probes "
                        f"({combo_summary})"
                    )

                alert = Alert(
                    capture_id=capture_id,

                    rule_name="Nmap Port Scan",

                    module="Pentesting Detection",

                    severity=(
                        "HIGH"
                        if (
                            triggers_by_count
                            and triggers_by_flags
                        )
                        else "MEDIUM"
                    ),

                    source_ip=src_ip,

                    target_ip=(
                        target_ips[0]
                        if len(target_ips) == 1
                        else None
                    ),

                    target_port=None,

                    description=(
                        f"{src_ip} probed "
                        f"{len(distinct_ports)} distinct ports "
                        f"across {len(target_ips)} host(s): "
                        f"{'; '.join(reason)}."
                    ),

                    evidence_json=json.dumps(
                        {
                            "distinct_ports": sorted(
                                [
                                    port
                                    for port in distinct_ports
                                    if port is not None
                                ]
                            ),

                            "target_ips": target_ips,

                            "abnormal_flag_ports": {
                                str(k): v
                                for k, v
                                in abnormal_flags.items()
                            },
                        }
                    ),

                    window_start=(
                        timestamps[start_idx]
                    ),

                    window_end=(
                        timestamps[end_idx]
                    ),
                )

                self.db.add_sealed(
                    session,
                    alert,
                )

                created += 1

        return created

    # ------------------------------------------------------------------
    # Module 1b: Hydra SSH Brute Force
    # ------------------------------------------------------------------

    def _detect_ssh_bruteforce(
        self,
        session: Session,
        capture_id: int,
    ) -> int:

        packets: List[Packet] = (
            session.query(Packet)
            .filter(
                Packet.capture_id == capture_id,
                Packet.src_ip.isnot(None),
                Packet.dst_ip.isnot(None),
                Packet.dst_port == SSH_BRUTE_PORT,
                Packet.ip_proto == "TCP",
            )
            .order_by(
                Packet.src_ip,
                Packet.timestamp,
            )
            .all()
        )

        by_pair: Dict[
            Tuple[str, str],
            List[Packet],
        ] = defaultdict(list)

        for p in packets:

            by_pair[
                (p.src_ip, p.dst_ip)
            ].append(p)

        created = 0

        for (
            src_ip,
            dst_ip,
        ), pkts in by_pair.items():

            pkts.sort(
                key=lambda p: p.timestamp
            )

            # ----------------------------------------------------------
            # Primary signal:
            #
            # A TCP SYN directed to destination port 22 represents
            # initiation of an SSH connection attempt.
            # ----------------------------------------------------------

            syn_attempts = [
                p
                for p in pkts
                if (
                    p.tcp_syn
                    and not p.tcp_ack
                )
            ]

            # ----------------------------------------------------------
            # Fallback:
            #
            # If TCP flags could not be extracted for a particular
            # TShark/PyShark combination, distinct source ports still
            # provide evidence of rapid repeated SSH connections.
            # ----------------------------------------------------------

            if (
                len(syn_attempts)
                >= SSH_BRUTE_MIN_ATTEMPTS
            ):

                attempt_packets = (
                    syn_attempts
                )

            else:

                attempt_packets = []

                seen_source_ports = set()

                for p in pkts:

                    if p.src_port is None:
                        continue

                    if (
                        p.src_port
                        in seen_source_ports
                    ):
                        continue

                    seen_source_ports.add(
                        p.src_port
                    )

                    attempt_packets.append(p)

            if (
                len(attempt_packets)
                < SSH_BRUTE_MIN_ATTEMPTS
            ):
                continue

            timestamps = [
                p.timestamp
                for p in attempt_packets
            ]

            windows = _sliding_windows(
                timestamps,
                SSH_BRUTE_WINDOW_SECONDS,
            )

            last_alert_end = -1

            for idx_group in windows:

                if (
                    len(idx_group)
                    < SSH_BRUTE_MIN_ATTEMPTS
                ):
                    continue

                start_idx = idx_group[0]
                end_idx = idx_group[-1]

                if (
                    start_idx
                    <= last_alert_end
                ):
                    continue

                last_alert_end = end_idx

                window_start = (
                    timestamps[start_idx]
                )

                window_end = (
                    timestamps[end_idx]
                )

                # RST/FIN packets are supporting evidence.
                #
                # They are not required because the primary indicator
                # is repeated connection initiation to SSH.
                rst_fin_count = sum(
                    1
                    for p in pkts
                    if (
                        p.tcp_rst
                        or p.tcp_fin
                    )
                    and (
                        window_start
                        <= p.timestamp
                        <= window_end
                    )
                )

                source_ports = [
                    attempt_packets[i].src_port
                    for i in idx_group
                    if (
                        attempt_packets[i].src_port
                        is not None
                    )
                ]

                alert = Alert(
                    capture_id=capture_id,

                    rule_name=(
                        "Hydra SSH Brute-Force"
                    ),

                    module=(
                        "Pentesting Detection"
                    ),

                    severity="HIGH",

                    source_ip=src_ip,

                    target_ip=dst_ip,

                    target_port=(
                        SSH_BRUTE_PORT
                    ),

                    description=(
                        f"{src_ip} initiated "
                        f"{len(idx_group)} rapid SSH "
                        f"connection attempts to "
                        f"{dst_ip}:22 within "
                        f"{SSH_BRUTE_WINDOW_SECONDS}s "
                        f"({rst_fin_count} RST/FIN "
                        f"terminations observed), "
                        f"consistent with automated "
                        f"SSH brute-forcing."
                    ),

                    evidence_json=json.dumps(
                        {
                            "ssh_attempts_in_window":
                                len(idx_group),

                            "rst_fin_count":
                                rst_fin_count,

                            "source_ports":
                                source_ports,
                        }
                    ),

                    window_start=window_start,
                    window_end=window_end,
                )

                self.db.add_sealed(
                    session,
                    alert,
                )

                created += 1

        return created

    # ------------------------------------------------------------------
    # Module 9: DNS Typosquatting
    # ------------------------------------------------------------------

    def _detect_dns_typosquatting(
        self,
        session: Session,
        capture_id: int,
    ) -> int:

        packets: List[Packet] = (
            session.query(Packet)
            .filter(
                Packet.capture_id == capture_id,
                Packet.dns_query_name.isnot(None),
                Packet.dns_is_response.is_(False),
            )
            .all()
        )

        created = 0
        seen = set()

        for p in packets:

            query = (
                p.dns_query_name
                or ""
            ).rstrip(".").lower()

            if (
                not query
                or query in seen
            ):
                continue

            best_match: Optional[str] = None
            best_ratio = 0.0

            for target in (
                PHISHING_TARGET_DOMAINS
            ):

                if query == target:

                    best_match = None
                    best_ratio = 1.0

                    break

                ratio = (
                    difflib.SequenceMatcher(
                        None,
                        query,
                        target,
                    ).ratio()
                )

                if ratio > best_ratio:

                    best_ratio = ratio
                    best_match = target

            if (
                best_match is not None
                and PHISHING_SIM_LOW
                <= best_ratio
                < PHISHING_SIM_HIGH
            ):

                seen.add(query)

                alert = Alert(
                    capture_id=capture_id,

                    rule_name=(
                        "DNS Typosquatting / "
                        "Lookalike Domain"
                    ),

                    module=(
                        "Social Engineering Detection"
                    ),

                    severity=(
                        "CRITICAL"
                        if best_ratio >= 0.9
                        else "HIGH"
                    ),

                    source_ip=p.src_ip,

                    target_ip=p.dst_ip,

                    target_port=53,

                    description=(
                        f"DNS query for '{query}' "
                        f"is {best_ratio:.0%} similar "
                        f"to legitimate domain "
                        f"'{best_match}' - likely a "
                        f"phishing / typosquatting "
                        f"lookalike."
                    ),

                    evidence_json=json.dumps(
                        {
                            "queried_domain":
                                query,

                            "closest_legit_domain":
                                best_match,

                            "similarity":
                                round(
                                    best_ratio,
                                    4,
                                ),
                        }
                    ),

                    window_start=p.timestamp,
                    window_end=p.timestamp,
                )

                self.db.add_sealed(
                    session,
                    alert,
                )

                created += 1

        return created

    # ------------------------------------------------------------------
    # Incident Correlation
    # ------------------------------------------------------------------

    def _correlate_incidents(
        self,
        session: Session,
        capture_id: int,
    ) -> int:

        alerts: List[Alert] = (
            session.query(Alert)
            .filter(
                Alert.capture_id == capture_id,
                Alert.incident_id.is_(None),
            )
            .order_by(
                Alert.source_ip,
                Alert.window_start,
            )
            .all()
        )

        by_src: Dict[
            str,
            List[Alert],
        ] = defaultdict(list)

        for alert in alerts:

            if alert.source_ip:

                by_src[
                    alert.source_ip
                ].append(alert)

        created = 0

        for (
            src_ip,
            src_alerts,
        ) in by_src.items():

            src_alerts.sort(
                key=lambda a:
                    a.window_start
                    or a.detected_at
            )

            chains = (
                self._chain_by_time(
                    src_alerts,
                    CORRELATION_WINDOW_SECONDS,
                )
            )

            for chain in chains:

                if not chain:
                    continue

                target_ips = sorted(
                    {
                        alert.target_ip
                        for alert in chain
                        if alert.target_ip
                    }
                )

                start_time = min(
                    (
                        alert.window_start
                        or alert.detected_at
                    )
                    for alert in chain
                )

                end_time = max(
                    (
                        alert.window_end
                        or alert.detected_at
                    )
                    for alert in chain
                )

                (
                    risk_score,
                    risk_level,
                ) = self._score_host_risk(
                    chain
                )

                rule_names = [
                    alert.rule_name
                    for alert in chain
                ]

                incident = Incident(
                    capture_id=capture_id,

                    title=(
                        self._build_incident_title(
                            src_ip,
                            rule_names,
                        )
                    ),

                    primary_source_ip=src_ip,

                    primary_target_ip=(
                        target_ips[0]
                        if len(target_ips) == 1
                        else None
                    ),

                    stage_count=len(chain),

                    host_risk_score=(
                        risk_score
                    ),

                    risk_level=risk_level,

                    start_time=start_time,
                    end_time=end_time,

                    summary=(
                        self._build_incident_summary(
                            src_ip,
                            chain,
                            target_ips,
                        )
                    ),
                )

                self.db.add_sealed(
                    session,
                    incident,
                )

                session.flush()

                for alert in chain:

                    alert.incident_id = (
                        incident.id
                    )

                    self.db.reseal(
                        alert
                    )

                created += 1

        return created

    @staticmethod
    def _chain_by_time(
        alerts: List[Alert],
        window_seconds: int,
    ) -> List[List[Alert]]:

        chains: List[
            List[Alert]
        ] = []

        current: List[Alert] = []

        last_time: Optional[
            _dt.datetime
        ] = None

        for alert in alerts:

            timestamp = (
                alert.window_start
                or alert.detected_at
            )

            if (
                last_time is not None
                and timestamp - last_time
                > _dt.timedelta(
                    seconds=window_seconds
                )
            ):

                chains.append(current)

                current = []

            current.append(alert)

            last_time = timestamp

        if current:
            chains.append(current)

        return chains

    @staticmethod
    def _score_host_risk(
        chain: Sequence[Alert],
    ) -> Tuple[float, str]:

        score = 0.0

        rule_types = set()

        for alert in chain:

            score += (
                SEVERITY_WEIGHTS.get(
                    alert.severity,
                    15,
                )
            )

            rule_types.add(
                alert.rule_name
            )

        # Additional risk for multiple attack stages.
        if len(rule_types) > 1:

            score += (
                15
                * (
                    len(rule_types)
                    - 1
                )
            )

        score = min(
            100.0,
            round(
                score,
                1,
            ),
        )

        if score >= 75:
            level = "CRITICAL"

        elif score >= 50:
            level = "HIGH"

        elif score >= 25:
            level = "MEDIUM"

        else:
            level = "LOW"

        return score, level

    @staticmethod
    def _build_incident_title(
        src_ip: str,
        rule_names: List[str],
    ) -> str:

        unique_rules = list(
            dict.fromkeys(
                rule_names
            )
        )

        if len(unique_rules) == 1:

            return (
                f"{unique_rules[0]} "
                f"from {src_ip}"
            )

        return (
            f"Multi-stage attack from "
            f"{src_ip} "
            f"({' -> '.join(unique_rules)})"
        )

    @staticmethod
    def _build_incident_summary(
        src_ip: str,
        chain: Sequence[Alert],
        target_ips: List[str],
    ) -> str:

        stages = "; ".join(
            f"[{alert.rule_name}] "
            f"{alert.description}"
            for alert in chain
        )

        targets = (
            ", ".join(target_ips)
            if target_ips
            else "multiple/unknown hosts"
        )

        return (
            f"Source {src_ip} against "
            f"{targets}. "
            f"Stages ({len(chain)}): "
            f"{stages}"
        )