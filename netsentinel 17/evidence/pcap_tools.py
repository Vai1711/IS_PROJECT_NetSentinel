"""Minimal, dependency-free structural analysis of PCAP / PCAPNG bytes.

Used to (a) validate uploads and (b) tell the user whether a tampered PCAP copy is still
parseable, complete, or truncated.
"""
from __future__ import annotations

import struct

_CLASSIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


def analyze_capture_bytes(data: bytes) -> dict:
    out = {"format": None, "valid_header": False, "packets": 0, "complete": False, "note": ""}
    if len(data) < 24:
        out["note"] = "File too short to contain a capture header."
        return out
    magic = data[:4]
    if magic in _CLASSIC:
        e = _CLASSIC[magic]
        out.update(format="pcap", valid_header=True)
        pos, n = 24, 0
        while pos + 16 <= len(data):
            incl = struct.unpack(e + "I", data[pos + 8:pos + 12])[0]
            if pos + 16 + incl > len(data):
                out.update(packets=n, complete=False,
                           note=f"Capture is truncated or corrupt: packet #{n + 1} is cut short. "
                                f"{n} packet(s) are still readable.")
                return out
            pos += 16 + incl
            n += 1
        if pos != len(data):
            out.update(packets=n, complete=False, note=f"Capture is truncated or corrupt: {len(data) - pos} trailing byte(s) form an incomplete record header. {n} packet(s) are still readable.")
        else:
            out.update(packets=n, complete=True, note=f"Capture is structurally valid ({n} packets).")
        return out
    if magic == b"\x0a\x0d\x0d\x0a":
        bom = data[8:12]
        e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
        if e is None:
            out["note"] = "PCAPNG byte-order magic is invalid."
            return out
        out.update(format="pcapng", valid_header=True)
        pos, n = 0, 0
        while pos + 12 <= len(data):
            btype, blen = struct.unpack(e + "II", data[pos:pos + 8])
            if blen < 12 or blen % 4 or pos + blen > len(data):
                out.update(packets=n, complete=False, note=f"PCAPNG block at offset {pos} is malformed or truncated.")
                return out
            if btype in (6, 3, 2):
                n += 1
            pos += blen
        ok = pos == len(data)
        out.update(packets=n, complete=ok,
                   note=f"Capture is structurally valid ({n} packets)." if ok else "Trailing bytes after last block.")
        return out
    out["note"] = "Unknown capture magic number."
    return out
