"""RSA-2048 signature behaviour experiments on real evidence (or labelled test data)."""
from __future__ import annotations

import json
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.keys import KeyStore, verify_with_public_key
from evidence.integrity import canonical_manifest, sha256_hex


def rsa_security_demo(keys: KeyStore, data: bytes, label: str, reference_manifest: Optional[bytes] = None,
                      reference_signature: Optional[bytes] = None) -> Dict:
    """Run five checks. Each result is computed live; `passed` means the library behaved securely."""
    if reference_manifest is None:
        meta = {"evidence_id": "TEST", "incident_id": "TEST", "filename": label, "evidence_type": "test data"}
        reference_manifest = canonical_manifest(meta, sha256_hex(data), len(data))
        reference_signature = keys.sign(reference_manifest)
    body = json.loads(reference_manifest)

    tests = []

    def add(name, expected_valid, observed_valid, note):
        tests.append({"test": name, "expected": "valid" if expected_valid else "invalid",
                      "observed": "valid" if observed_valid else "invalid",
                      "passed": expected_valid == observed_valid, "note": note})

    add("Original evidence, original signature", True, keys.verify(reference_manifest, reference_signature),
        "Signature over the registered manifest verifies with the public key.")

    mod = bytearray(data); mod[len(mod) // 2] ^= 0x01
    meta = {k: v for k, v in body.items() if k not in ("sha256", "size_bytes")}
    tampered_manifest = canonical_manifest(meta, sha256_hex(bytes(mod)), len(mod))
    add("Evidence modified by one bit", False, keys.verify(tampered_manifest, reference_signature),
        "The manifest of the modified file differs, so the stored signature no longer matches.")

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    add("Verification with an incorrect public key", False,
        verify_with_public_key(other, reference_manifest, reference_signature),
        "A freshly generated, unrelated RSA-2048 public key rejects the signature.")

    bad_sig = bytearray(reference_signature); bad_sig[0] ^= 0x01
    add("Signature itself altered by one bit", False, keys.verify(reference_manifest, bytes(bad_sig)),
        "A corrupted signature is rejected.")

    edited = dict(body); edited["incident_id"] = "INC999"
    add("Manifest field edited (incident id)", False,
        keys.verify(json.dumps(edited, sort_keys=True, separators=(",", ":")).encode(), reference_signature),
        "Re-assigning evidence to another incident invalidates the signature.")

    pub = keys.public_key.public_numbers()
    return {"label": label, "tests": tests, "all_passed": all(t["passed"] for t in tests),
            "modulus_bits": pub.n.bit_length(), "public_exponent": pub.e,
            "signature_bytes": len(reference_signature), "scheme": "RSA-PSS, MGF1-SHA256, SHA-256, max salt"}
