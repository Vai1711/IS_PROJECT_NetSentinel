"""
ingestion/parser.py

Parses a .pcap/.pcapng file with PyShark (TShark backend), extracting
Layer 2-7 metadata per packet, aggregates packets into bidirectional
5-tuple flows, and bulk-inserts everything into the tamper-evident
SQLite database via DBManager.

Falls back gracefully on malformed / non-IP frames: such packets are
still recorded (is_malformed=True) rather than dropped, since a missing
frame can itself be forensically significant.
"""

from __future__ import annotations

import datetime as _dt
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import pyshark

from database.db_manager import DBManager
from database.models import CaptureMeta, Packet, Flow


logger = logging.getLogger("netsentinel.ingestion")

FlowKey = Tuple[str, str, Optional[int], Optional[int], str]


def _epoch_to_dt(epoch_str: str) -> _dt.datetime:
    try:
        return _dt.datetime.fromtimestamp(float(epoch_str), _dt.timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return _dt.datetime.utcnow()


def _safe_int(value, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _flag_value(value) -> bool:
    """
    Safely interpret an individual PyShark/TShark flag field.

    Depending on the TShark/PyShark version, a flag can appear as
    "1", "0", True, False, etc.
    """
    if value is None:
        return False

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "set",
    }


def _parse_tcp_flag_mask(value) -> Optional[int]:
    """
    Convert TShark's tcp.flags value into an integer bitmask.

    Common examples:
        0x0002 -> SYN
        0x0012 -> SYN + ACK
        0x0004 -> RST
        0x0010 -> ACK

    Returns None if the value cannot be interpreted.
    """
    if value is None:
        return None

    try:
        text = str(value).strip()

        if not text:
            return None

        if text.lower().startswith("0x"):
            return int(text, 16)

        return int(text, 0)

    except (TypeError, ValueError):
        return None


def _normalized_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: str,
) -> FlowKey:
    """
    Normalize direction so that A->B and B->A packets land in the same
    flow bucket.

    We sort by (ip, port) tuple so the key is direction-independent.
    """
    a = (src_ip, src_port or -1)
    b = (dst_ip, dst_port or -1)

    if a <= b:
        return (src_ip, dst_ip, src_port, dst_port, protocol)

    return (dst_ip, src_ip, dst_port, src_port, protocol)


@dataclass
class _FlowAccumulator:
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    start_time: _dt.datetime
    end_time: _dt.datetime

    packet_count: int = 0
    byte_count: int = 0

    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0

    def absorb(self, pkt: Packet) -> None:
        self.start_time = min(self.start_time, pkt.timestamp)
        self.end_time = max(self.end_time, pkt.timestamp)

        self.packet_count += 1
        self.byte_count += pkt.frame_len or 0

        self.syn_count += int(bool(pkt.tcp_syn))
        self.ack_count += int(bool(pkt.tcp_ack))
        self.rst_count += int(bool(pkt.tcp_rst))
        self.fin_count += int(bool(pkt.tcp_fin))


class PcapParser:
    """Parses one capture file end-to-end and persists it to the DB."""

    def __init__(
        self,
        db_manager: DBManager,
        tshark_path: Optional[str] = None,
    ):
        self.db = db_manager
        self.tshark_path = tshark_path

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def ingest(
        self,
        filepath: str,
        filename: Optional[str] = None,
        progress_cb=None,
    ) -> CaptureMeta:

        filename = filename or filepath.split("/")[-1]

        file_sha256 = self.db.sha256_file(filepath)

        with self.db.session_scope() as session:

            capture = CaptureMeta(
                filename=filename,
                filepath=filepath,
                file_sha256=file_sha256,
                file_size_bytes=self._file_size(filepath),
                total_packets=0,
                total_flows=0,
            )

            self.db.add_sealed(session, capture)

            session.flush()

            packets, flow_accs = self._parse_packets(
                filepath,
                capture.id,
                progress_cb,
            )

            self.db.bulk_add_sealed(session, packets)

            session.flush()

            flows = self._materialize_flows(
                capture.id,
                flow_accs,
            )

            self.db.bulk_add_sealed(session, flows)

            capture.total_packets = len(packets)
            capture.total_flows = len(flows)

            if packets:
                capture.capture_start = min(
                    p.timestamp for p in packets
                )

                capture.capture_end = max(
                    p.timestamp for p in packets
                )

            # Totals changed, therefore regenerate the HMAC seal.
            self.db.reseal(capture)

            session.flush()

            capture_id = capture.id

        # Re-fetch detached copy.
        with self.db.session_scope() as session:

            result = session.get(
                CaptureMeta,
                capture_id,
            )

            session.expunge(result)

            return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _file_size(filepath: str) -> int:
        try:
            import os
            return os.path.getsize(filepath)

        except OSError:
            return 0

    def _parse_packets(
        self,
        filepath: str,
        capture_id: int,
        progress_cb=None,
    ) -> Tuple[
        List[Packet],
        Dict[FlowKey, _FlowAccumulator],
    ]:

        packets: List[Packet] = []

        flow_accs: Dict[
            FlowKey,
            _FlowAccumulator,
        ] = {}

        cap_kwargs = dict(
            keep_packets=False,
        )

        if self.tshark_path:
            cap_kwargs["tshark_path"] = self.tshark_path

        cap = pyshark.FileCapture(
            filepath,
            **cap_kwargs,
        )

        try:

            for i, raw_pkt in enumerate(cap):

                pkt = self._parse_single_packet(
                    raw_pkt,
                    capture_id,
                    frame_number=i + 1,
                )

                packets.append(pkt)

                if pkt.src_ip and pkt.dst_ip:

                    key = _normalized_flow_key(
                        pkt.src_ip,
                        pkt.dst_ip,
                        pkt.src_port,
                        pkt.dst_port,
                        pkt.ip_proto or "OTHER",
                    )

                    acc = flow_accs.get(key)

                    if acc is None:

                        acc = _FlowAccumulator(
                            src_ip=key[0],
                            dst_ip=key[1],
                            src_port=key[2],
                            dst_port=key[3],
                            protocol=key[4],
                            start_time=pkt.timestamp,
                            end_time=pkt.timestamp,
                        )

                        flow_accs[key] = acc

                    acc.absorb(pkt)

                if progress_cb and (i % 25 == 0):
                    progress_cb(
                        i + 1,
                        None,
                    )

        finally:
            cap.close()

        if progress_cb:
            progress_cb(
                len(packets),
                len(packets),
            )

        return packets, flow_accs

    def _parse_single_packet(
        self,
        raw_pkt,
        capture_id: int,
        frame_number: int,
    ) -> Packet:

        """
        Extract fields defensively.

        Missing layers yield None rather than causing the complete
        capture to fail.
        """

        try:

            timestamp = _epoch_to_dt(
                getattr(
                    raw_pkt,
                    "sniff_timestamp",
                    None,
                )
            )

            frame_len = (
                _safe_int(
                    getattr(
                        raw_pkt,
                        "length",
                        None,
                    ),
                    0,
                )
                or 0
            )

            # ----------------------------------------------------------
            # Ethernet
            # ----------------------------------------------------------

            src_mac = None
            dst_mac = None
            eth_type = None

            if hasattr(raw_pkt, "eth"):

                src_mac = getattr(
                    raw_pkt.eth,
                    "src",
                    None,
                )

                dst_mac = getattr(
                    raw_pkt.eth,
                    "dst",
                    None,
                )

                eth_type = getattr(
                    raw_pkt.eth,
                    "type",
                    None,
                )

            # ----------------------------------------------------------
            # IP / IPv6
            # ----------------------------------------------------------

            src_ip = None
            dst_ip = None
            ip_proto = None
            ttl = None

            if hasattr(raw_pkt, "ip"):

                src_ip = getattr(
                    raw_pkt.ip,
                    "src",
                    None,
                )

                dst_ip = getattr(
                    raw_pkt.ip,
                    "dst",
                    None,
                )

                ttl = _safe_int(
                    getattr(
                        raw_pkt.ip,
                        "ttl",
                        None,
                    )
                )

            elif hasattr(raw_pkt, "ipv6"):

                src_ip = getattr(
                    raw_pkt.ipv6,
                    "src",
                    None,
                )

                dst_ip = getattr(
                    raw_pkt.ipv6,
                    "dst",
                    None,
                )

                ttl = _safe_int(
                    getattr(
                        raw_pkt.ipv6,
                        "hlim",
                        None,
                    )
                )

            # ----------------------------------------------------------
            # Transport layer
            # ----------------------------------------------------------

            src_port = None
            dst_port = None

            tcp_syn = False
            tcp_ack = False
            tcp_rst = False
            tcp_fin = False
            tcp_psh = False
            tcp_urg = False

            tcp_flags_raw = None

            if hasattr(raw_pkt, "tcp"):

                ip_proto = "TCP"

                src_port = _safe_int(
                    getattr(
                        raw_pkt.tcp,
                        "srcport",
                        None,
                    )
                )

                dst_port = _safe_int(
                    getattr(
                        raw_pkt.tcp,
                        "dstport",
                        None,
                    )
                )

                tcp_flags_raw = getattr(
                    raw_pkt.tcp,
                    "flags",
                    None,
                )

                # ------------------------------------------------------
                # Preferred method:
                # decode the complete TCP flags bitmask.
                # ------------------------------------------------------

                flag_mask = _parse_tcp_flag_mask(
                    tcp_flags_raw
                )

                if flag_mask is not None:

                    tcp_fin = bool(
                        flag_mask & 0x01
                    )

                    tcp_syn = bool(
                        flag_mask & 0x02
                    )

                    tcp_rst = bool(
                        flag_mask & 0x04
                    )

                    tcp_psh = bool(
                        flag_mask & 0x08
                    )

                    tcp_ack = bool(
                        flag_mask & 0x10
                    )

                    tcp_urg = bool(
                        flag_mask & 0x20
                    )

                else:

                    # --------------------------------------------------
                    # Fallback:
                    # use individual fields exposed by PyShark.
                    # --------------------------------------------------

                    tcp_syn = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_syn",
                            None,
                        )
                    )

                    tcp_ack = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_ack",
                            None,
                        )
                    )

                    tcp_rst = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_reset",
                            None,
                        )
                    )

                    tcp_fin = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_fin",
                            None,
                        )
                    )

                    tcp_psh = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_push",
                            None,
                        )
                    )

                    tcp_urg = _flag_value(
                        getattr(
                            raw_pkt.tcp,
                            "flags_urg",
                            None,
                        )
                    )

            elif hasattr(raw_pkt, "udp"):

                ip_proto = "UDP"

                src_port = _safe_int(
                    getattr(
                        raw_pkt.udp,
                        "srcport",
                        None,
                    )
                )

                dst_port = _safe_int(
                    getattr(
                        raw_pkt.udp,
                        "dstport",
                        None,
                    )
                )

            elif hasattr(raw_pkt, "icmp"):

                ip_proto = "ICMP"

            elif src_ip or dst_ip:

                ip_proto = "OTHER"

            # ----------------------------------------------------------
            # Highest-level protocol
            # ----------------------------------------------------------

            protocol = None

            try:
                protocol = raw_pkt.highest_layer

            except Exception:
                protocol = ip_proto

            # ----------------------------------------------------------
            # DNS
            # ----------------------------------------------------------

            dns_query_name = None
            dns_is_response = False

            if hasattr(raw_pkt, "dns"):

                dns_query_name = getattr(
                    raw_pkt.dns,
                    "qry_name",
                    None,
                )

                dns_is_response = _flag_value(
                    getattr(
                        raw_pkt.dns,
                        "flags_response",
                        None,
                    )
                )

            # ----------------------------------------------------------
            # HTTP
            # ----------------------------------------------------------

            http_host = None

            if hasattr(raw_pkt, "http"):

                http_host = getattr(
                    raw_pkt.http,
                    "host",
                    None,
                )

            # ----------------------------------------------------------
            # Construct database Packet object
            # ----------------------------------------------------------

            return Packet(
                capture_id=capture_id,
                frame_number=frame_number,
                timestamp=timestamp,
                frame_len=frame_len,

                src_mac=src_mac,
                dst_mac=dst_mac,
                eth_type=eth_type,

                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_proto=ip_proto,
                ttl=ttl,

                src_port=src_port,
                dst_port=dst_port,

                tcp_syn=tcp_syn,
                tcp_ack=tcp_ack,
                tcp_rst=tcp_rst,
                tcp_fin=tcp_fin,
                tcp_psh=tcp_psh,
                tcp_urg=tcp_urg,

                tcp_flags_raw=(
                    str(tcp_flags_raw)
                    if tcp_flags_raw is not None
                    else None
                ),

                protocol=protocol,

                dns_query_name=dns_query_name,
                dns_is_response=dns_is_response,

                http_host=http_host,

                is_malformed=False,

                raw_summary=(
                    str(
                        getattr(
                            raw_pkt,
                            "summary_line",
                            "",
                        )
                    )
                    or None
                ),
            )

        except Exception as exc:

            logger.warning(
                "Malformed frame #%s: %s",
                frame_number,
                exc,
            )

            return Packet(
                capture_id=capture_id,
                frame_number=frame_number,
                timestamp=_dt.datetime.utcnow(),
                frame_len=0,
                is_malformed=True,
                raw_summary=f"parse_error: {exc}",
            )

    @staticmethod
    def _materialize_flows(
        capture_id: int,
        flow_accs: Dict[
            FlowKey,
            _FlowAccumulator,
        ],
    ) -> List[Flow]:

        flows: List[Flow] = []

        for acc in flow_accs.values():

            flows.append(
                Flow(
                    capture_id=capture_id,

                    src_ip=acc.src_ip,
                    dst_ip=acc.dst_ip,

                    src_port=acc.src_port,
                    dst_port=acc.dst_port,

                    protocol=acc.protocol,

                    start_time=acc.start_time,
                    end_time=acc.end_time,

                    packet_count=acc.packet_count,
                    byte_count=acc.byte_count,

                    syn_count=acc.syn_count,
                    ack_count=acc.ack_count,
                    rst_count=acc.rst_count,
                    fin_count=acc.fin_count,
                )
            )

        return flows