"""The single cryptographic integrity engine, operating on raw file bytes.

Every evidence type (PCAP, image, audio, text) goes through exactly this code.

Protection stack for each registered evidence file
--------------------------------------------------
* SHA-256(file bytes)                      -> content fingerprint
* HMAC-SHA256(secret, file bytes)          -> keyed integrity: needs the secret to forge
* manifest = canonical JSON {evidence id, incident id, filename, type, size, sha256, time}
  - HMAC-SHA256(secret, manifest)          -> keyed integrity of the record itself
  - RSA-2048-PSS-SHA256(manifest)          -> authenticity / non-repudiation, publicly verifiable

Verification re-derives all of these from the CANDIDATE file and compares them with the stored
reference values. Reference values are never recomputed after the fact.

Caveat: the HMAC tags are stored in the same SQLite file as the records they protect, so their
security rests entirely on the HMAC secret staying outside an attacker's reach. SQLite itself is
not tamper-proof; the signature and keyed tags are what make tampering detectable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass

from crypto.keys import KeyStore, verify_with_public_key


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hamming_bits(hex_a: str, hex_b: str) -> int:
    """Number of differing bits between two equal-length hex digests."""
    a, b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    if len(a) != len(b):
        raise ValueError("digests must have equal length")
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def canonical_manifest(meta: dict, sha256: str, size: int) -> bytes:
    body = dict(meta)
    body["sha256"] = sha256
    body["size_bytes"] = size
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class SealRecord:
    sha256: str
    size: int
    file_hmac: str
    manifest_json: str
    manifest_hmac: str
    signature: bytes

    @property
    def signature_b64(self) -> str:
        return base64.b64encode(self.signature).decode("ascii")


@dataclass(frozen=True)
class ReferenceRecord:
    """The protected reference values stored at registration time."""
    sha256: str
    size: int
    file_hmac: str
    manifest_json: str
    manifest_hmac: str
    signature: bytes


@dataclass(frozen=True)
class VerificationResult:
    reference_ok: bool          # stored manifest still carries a valid signature + HMAC
    original_sha256: str
    candidate_sha256: str
    sha_match: bool
    hmac_ok: bool
    rsa_ok: bool
    changed_bits: int
    avalanche_pct: float
    diff_bits: tuple            # 256 entries, 1 where the digests differ

    @property
    def verdict(self) -> str:
        if not self.reference_ok:
            return "REFERENCE_COMPROMISED"
        return "VERIFIED" if (self.sha_match and self.hmac_ok and self.rsa_ok) else "TAMPERED"


class IntegrityEngine:
    def __init__(self, keys: KeyStore):
        self.keys = keys

    def hmac_hex(self, data: bytes) -> str:
        return hmac.new(self.keys.hmac_key, data, hashlib.sha256).hexdigest()

    def seal(self, data: bytes, meta: dict) -> SealRecord:
        digest = sha256_hex(data)
        manifest = canonical_manifest(meta, digest, len(data))
        return SealRecord(
            sha256=digest,
            size=len(data),
            file_hmac=self.hmac_hex(data),
            manifest_json=manifest.decode("utf-8"),
            manifest_hmac=self.hmac_hex(manifest),
            signature=self.keys.sign(manifest),
        )

    def verify(self, data: bytes, ref: ReferenceRecord) -> VerificationResult:
        stored_manifest = ref.manifest_json.encode("utf-8")
        body = json.loads(ref.manifest_json)
        reference_ok = (
            self.keys.verify(stored_manifest, ref.signature)
            and hmac.compare_digest(self.hmac_hex(stored_manifest), ref.manifest_hmac)
            and body.get("sha256") == ref.sha256
        )

        cand_sha = sha256_hex(data)
        sha_match = hmac.compare_digest(cand_sha, ref.sha256)
        hmac_ok = hmac.compare_digest(self.hmac_hex(data), ref.file_hmac)

        meta = {k: v for k, v in body.items() if k not in ("sha256", "size_bytes")}
        cand_manifest = canonical_manifest(meta, cand_sha, len(data))
        rsa_ok = self.keys.verify(cand_manifest, ref.signature)

        bits = hamming_bits(ref.sha256, cand_sha)
        a, b = int(ref.sha256, 16), int(cand_sha, 16)
        diff = tuple(int(c) for c in format(a ^ b, "0256b"))
        return VerificationResult(
            reference_ok=reference_ok, original_sha256=ref.sha256, candidate_sha256=cand_sha,
            sha_match=sha_match, hmac_ok=hmac_ok, rsa_ok=rsa_ok,
            changed_bits=bits, avalanche_pct=bits / 256 * 100, diff_bits=diff,
        )


def verify_manifest_signature(public_pem: bytes, manifest: bytes, signature: bytes) -> bool:
    """Third-party verification using only a public key."""
    from crypto.keys import load_public_pem
    return verify_with_public_key(load_public_pem(public_pem), manifest, signature)
