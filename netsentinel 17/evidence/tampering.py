"""Controlled evidence-tampering simulator.

Every function here is PURE: it takes the original bytes and returns modified bytes plus a
description. `TamperingSimulator.simulate` then writes the result to a disposable copy under
<data>/evidence/simulated and records it. Originals and reference values are never touched.
Nothing here touches the network or any external system.
"""
from __future__ import annotations

import difflib
import html
import io
import json
import logging
import os
import re
import struct
import tempfile
import wave
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import numpy as np
from PIL import Image, ImageDraw

from config import Settings
from database.db_manager import DBManager
from database.models import EvidenceItem, SimulationRecord
from evidence import audit
from evidence.evidence_manager import EvidenceError, incident_code
from evidence.integrity import sha256_hex
from evidence.pcap_tools import analyze_capture_bytes

log = logging.getLogger(__name__)


class TamperingError(ValueError):
    """The chosen modification cannot be applied to this file (message is user-facing)."""


@dataclass
class TamperResult:
    data: bytes
    summary: str
    details: Dict = field(default_factory=dict)


# ----------------------------------------------------------------------------- image
def _open_image(data: bytes):
    img = Image.open(io.BytesIO(data))
    img.load()
    fmt = img.format or "PNG"
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    return img, fmt


def _save_image(img, fmt: str) -> bytes:
    buf = io.BytesIO()
    if fmt == "JPEG":
        img.convert("RGB").save(buf, format="JPEG", quality=95)
    else:
        img.save(buf, format=fmt)
    return buf.getvalue()


def _pixels_changed(a, b) -> Optional[int]:
    if a.size != b.size:
        return None
    return int((np.asarray(a.convert("RGB")) != np.asarray(b.convert("RGB"))).any(axis=2).sum())


def image_pixel(data: bytes, x: Optional[int] = None, y: Optional[int] = None, **_) -> TamperResult:
    img, fmt = _open_image(data)
    w, h = img.size
    x = w // 2 if x is None else int(x)
    y = h // 2 if y is None else int(y)
    if not (0 <= x < w and 0 <= y < h):
        raise TamperingError(f"Pixel ({x}, {y}) is outside the {w}x{h} image.")
    out = img.copy()
    old = out.getpixel((x, y))
    new = tuple(255 - c for c in old[:3]) + tuple(old[3:])
    out.putpixel((x, y), new)
    n = _pixels_changed(img, out)
    note = " (JPEG is lossy: re-encoding also perturbs neighbouring pixels.)" if fmt == "JPEG" else ""
    return TamperResult(_save_image(out, fmt), f"Changed pixel ({x}, {y}) from {old[:3]} to {new[:3]}.{note}",
                        {"x": x, "y": y, "old": list(old[:3]), "new": list(new[:3]), "pixels_changed": n})


def image_overlay(data: bytes, text: str = "TAMPERED", **_) -> TamperResult:
    img, fmt = _open_image(data)
    out = img.copy()
    ImageDraw.Draw(out).text((10, 10), text or "TAMPERED", fill=(255, 0, 0))
    return TamperResult(_save_image(out, fmt), f"Drew the text '{text}' onto the image.",
                        {"text": text, "pixels_changed": _pixels_changed(img, out)})


def image_crop(data: bytes, percent: int = 15, **_) -> TamperResult:
    img, fmt = _open_image(data)
    w, h = img.size
    nw, nh = max(1, int(w * (1 - percent / 100))), max(1, int(h * (1 - percent / 100)))
    out = img.crop((0, 0, nw, nh))
    return TamperResult(_save_image(out, fmt), f"Cropped {w}x{h} -> {nw}x{nh} ({percent}% removed from right/bottom).",
                        {"from": [w, h], "to": [nw, nh]})


# ----------------------------------------------------------------------------- audio
def _read_wav(data: bytes):
    with wave.open(io.BytesIO(data)) as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    if params.sampwidth != 2:
        raise TamperingError("Only 16-bit PCM WAV audio can be modified.")
    return params, np.frombuffer(frames, dtype="<i2").copy()


def _write_wav(params, arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(params.nchannels)
        w.setsampwidth(2)
        w.setframerate(params.framerate)
        w.writeframes(arr.astype("<i2").tobytes())
    return buf.getvalue()


def audio_sample(data: bytes, index: Optional[int] = None, **_) -> TamperResult:
    params, arr = _read_wav(data)
    i = len(arr) // 2 if index is None else int(index)
    if not 0 <= i < len(arr):
        raise TamperingError(f"Sample index {i} is outside 0..{len(arr) - 1}.")
    old = int(arr[i])
    new = old + 2000 if old + 2000 <= 32767 else old - 2000
    arr[i] = new
    return TamperResult(_write_wav(params, arr), f"Changed audio sample #{i} from {old} to {new}.",
                        {"index": i, "old": old, "new": new})


def audio_noise(data: bytes, std: float = 300.0, **_) -> TamperResult:
    params, arr = _read_wav(data)
    rng = np.random.default_rng(1337)
    noisy = np.clip(arr.astype(np.float64) + rng.normal(0, float(std), arr.shape), -32768, 32767)
    return TamperResult(_write_wav(params, noisy.astype(np.int16)),
                        f"Added Gaussian noise (std {std:g} LSB) to every sample.", {"std": float(std)})


def audio_trim(data: bytes, percent: int = 10, **_) -> TamperResult:
    params, arr = _read_wav(data)
    keep = int(len(arr) * (1 - percent / 100))
    keep -= keep % max(1, params.nchannels)
    if keep <= 0:
        raise TamperingError("Trim percentage removes the whole recording.")
    return TamperResult(_write_wav(params, arr[:keep]), f"Trimmed the last {percent}% ({len(arr) - keep} samples).",
                        {"removed_samples": int(len(arr) - keep)})


# ----------------------------------------------------------------------------- text
_URL = re.compile(r"https?://[^\s<>\"']+")
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TamperingError("Text evidence is not valid UTF-8.") from exc


def text_char(data: bytes, index: Optional[int] = None, **_) -> TamperResult:
    s = _decode(data)
    start = len(s) // 3 if index is None else int(index)
    if not 0 <= start < len(s):
        raise TamperingError("Character index is outside the text.")
    for i in range(start, len(s)):
        c = s[i]
        if c.isdigit() or (c.isalpha() and c.swapcase() != c):
            new = str((int(c) + 1) % 10) if c.isdigit() else c.swapcase()
            return TamperResult((s[:i] + new + s[i + 1:]).encode(), f"Changed character #{i} '{c}' to '{new}'.",
                                {"index": i, "old": c, "new": new})
    raise TamperingError("No alphanumeric character found to change.")


def text_url(data: bytes, replacement: str = "https://secure-update.example.invalid/login", **_) -> TamperResult:
    s = _decode(data)
    m = _URL.search(s)
    if not m:
        raise TamperingError("No URL was found in this text file.")
    out = s[:m.start()] + replacement + s[m.end():]
    return TamperResult(out.encode(), f"Replaced URL '{m.group()}' with '{replacement}'.",
                        {"old": m.group(), "new": replacement})


def text_ip(data: bytes, **_) -> TamperResult:
    s = _decode(data)
    m = _IP.search(s)
    if not m:
        raise TamperingError("No IPv4 address was found in this text file.")
    a, b, c, d = m.group().split(".")
    new = ".".join([a, b, c, str(int(d) + 1 if int(d) < 255 else 254)])
    return TamperResult((s[:m.start()] + new + s[m.end():]).encode(), f"Modified IP address {m.group()} to {new}.",
                        {"old": m.group(), "new": new})


def text_diff_html(a: str, b: str) -> tuple:
    """HTML for original/modified text with changed spans highlighted (escaped, safe to render)."""
    ha, hb = [], []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        sa, sb = html.escape(a[i1:i2]), html.escape(b[j1:j2])
        if op == "equal":
            ha.append(sa); hb.append(sb)
        else:
            if sa: ha.append(f"<mark class='ns-del'>{sa}</mark>")
            if sb: hb.append(f"<mark class='ns-add'>{sb}</mark>")
    wrap = lambda x: "<pre class='ns-text'>" + "".join(x) + "</pre>"
    return wrap(ha), wrap(hb)


# ----------------------------------------------------------------------------- pcap
def pcap_bitflip(data: bytes, byte_offset: Optional[int] = None, bit: int = 0, **_) -> TamperResult:
    default = 40 + 22 if analyze_capture_bytes(data)["format"] == "pcap" and len(data) > 62 else len(data) // 2
    off = default if byte_offset is None else int(byte_offset)
    if not 0 <= off < len(data) or not 0 <= bit <= 7:
        raise TamperingError("Byte offset or bit index is out of range.")
    out = bytearray(data)
    old = out[off]
    out[off] ^= 1 << bit
    res = analyze_capture_bytes(bytes(out))
    return TamperResult(bytes(out), f"Flipped bit {bit} of byte at file offset {off} (0x{old:02x} -> 0x{out[off]:02x}).",
                        {"offset": off, "bit": bit, "old_byte": old, "new_byte": out[off], "parse": res})


def pcap_truncate(data: bytes, keep_percent: int = 70, **_) -> TamperResult:
    cut = max(1, min(len(data) - 1, len(data) * int(keep_percent) // 100))
    out = data[:cut]
    res = analyze_capture_bytes(out)
    return TamperResult(out, f"Truncated copy to {cut} of {len(data)} bytes ({keep_percent}% kept). {res['note']}",
                        {"kept_bytes": cut, "original_bytes": len(data), "parse": res})


def pcap_field(data: bytes, field_name: str = "IP TTL", **_) -> TamperResult:
    from scapy.all import IP, TCP, UDP, rdpcap, wrpcap  # imported lazily (slow import)

    with tempfile.TemporaryDirectory() as td:
        src, dst = Path(td, "in.pcap"), Path(td, "out.pcap")
        src.write_bytes(data)
        try:
            pkts = rdpcap(str(src))
        except Exception as exc:  # scapy raises several types on bad captures
            raise TamperingError(f"The capture could not be parsed for field editing: {exc}") from exc
        for idx, p in enumerate(pkts):
            if not p.haslayer(IP):
                continue
            before = p.summary()
            if field_name == "IP TTL":
                old = p[IP].ttl; new = old - 1 if old > 1 else old + 1; p[IP].ttl = new
            elif field_name == "IP source address":
                a, b, c, d = p[IP].src.split("."); old = p[IP].src
                new = ".".join([a, b, c, str(int(d) + 1 if int(d) < 255 else 254)]); p[IP].src = new
            elif field_name == "TCP/UDP destination port":
                layer = TCP if p.haslayer(TCP) else UDP if p.haslayer(UDP) else None
                if layer is None:
                    continue
                old = p[layer].dport; new = old + 1 if old < 65535 else old - 1; p[layer].dport = new
            else:
                raise TamperingError(f"Unknown field '{field_name}'.")
            del p[IP].chksum                                   # force valid checksums on rebuild
            for layer in (TCP, UDP):
                if p.haslayer(layer):
                    del p[layer].chksum
            wrpcap(str(dst), pkts)
            out = dst.read_bytes()
            res = analyze_capture_bytes(out)
            return TamperResult(
                out, f"Packet #{idx + 1}: {field_name} {old} -> {new}. Checksums recomputed; the copy is a valid capture "
                     f"({res['packets']} packets).",
                {"packet_number": idx + 1, "field": field_name, "old": str(old), "new": str(new),
                 "before": before, "after": p.summary(), "parse": res})
    raise TamperingError(f"No packet with an editable '{field_name}' field was found.")


METHODS: Dict[str, Dict[str, Callable]] = {
    "Image": {"Change one pixel": image_pixel, "Add text overlay": image_overlay, "Crop part of the image": image_crop},
    "Audio": {"Modify one sample": audio_sample, "Add noise": audio_noise, "Trim a portion": audio_trim},
    "Text": {"Change one character": text_char, "Replace a URL": text_url, "Modify an IP address": text_ip},
    "PCAP": {"Flip one bit": pcap_bitflip, "Modify a packet field": pcap_field, "Truncate the capture": pcap_truncate},
}


class TamperingSimulator:
    def __init__(self, db: DBManager, evidence_manager, settings: Settings):
        self.db, self.em, self.settings = db, evidence_manager, settings

    def simulate(self, evidence_id: int, method: str, params: Optional[dict] = None) -> Dict:
        info = self.em.get(evidence_id)
        fn = METHODS.get(info["type"], {}).get(method)
        if fn is None:
            raise TamperingError(f"'{method}' is not available for {info['type']} evidence.")
        original = self.em.read_original(evidence_id)          # read-only access to the original
        params = dict(params or {})
        result = fn(original, **params)
        if result.data == original:
            raise TamperingError("The modification did not change any bytes.")

        folder = self.settings.simulated_dir.resolve() / incident_code(info["incident_id"]) / info["code"]
        folder.mkdir(parents=True, exist_ok=True)
        orig_dir = self.settings.original_dir.resolve()
        slug = re.sub(r"[^a-z0-9]+", "_", method.lower()).strip("_")

        with self.db.session_scope() as s:
            rec = SimulationRecord(
                incident_id=info["incident_id"], evidence_id=evidence_id, method=method,
                params_json=json.dumps(params, default=str), details_json="{}", modified_path="pending",
                modified_filename="pending", modified_sha256=sha256_hex(result.data),
                modified_size=len(result.data))
            s.add(rec)
            s.flush()
            name = f"SIM{rec.id:03d}_{slug}_{info['filename']}"
            dest = (folder / name).resolve()
            if orig_dir in dest.parents:
                raise TamperingError("Internal safety check: simulation copies must not live in the originals folder.")
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "wb") as fh:
                fh.write(result.data)
            rec.modified_path, rec.modified_filename = str(dest), name
            rec.details_json = json.dumps({"summary": result.summary, **result.details}, default=str)
            audit.log_event(s, "TAMPERING_SIMULATED",
                            f"SIMULATED: {method} applied to a COPY of {info['code']} ({result.summary})",
                            incident_id=info["incident_id"], evidence_id=evidence_id)
            out = self.describe(rec)
        log.info("Simulated '%s' on %s -> %s", method, info["code"], name)
        return out

    @staticmethod
    def describe(rec: SimulationRecord) -> Dict:
        details = json.loads(rec.details_json or "{}")
        return {"id": rec.id, "incident_id": rec.incident_id, "evidence_id": rec.evidence_id, "method": rec.method,
                "modified_path": rec.modified_path, "modified_filename": rec.modified_filename,
                "modified_sha256": rec.modified_sha256, "modified_size": rec.modified_size,
                "created_at": rec.created_at, "summary": details.get("summary", ""), "details": details}

    def list_for_evidence(self, evidence_id: int) -> List[Dict]:
        with self.db.session_scope() as s:
            rows = s.query(SimulationRecord).filter_by(evidence_id=evidence_id).order_by(SimulationRecord.id).all()
            return [self.describe(r) for r in rows]

    def get(self, simulation_id: int) -> Dict:
        with self.db.session_scope() as s:
            rec = s.get(SimulationRecord, simulation_id)
            if rec is None:
                raise EvidenceError(f"Simulation {simulation_id} not found.")
            return self.describe(rec)
