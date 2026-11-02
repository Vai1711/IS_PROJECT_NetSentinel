"""Key management: one RSA-2048 signing key pair and one HMAC secret.

* Keys are generated with the `cryptography` library / `secrets` on first use.
* They live in <data_dir>/keys (outside the source tree, git-ignored), mode 0600.
* The private key and HMAC secret are never written to reports or offered for
  download. Only the PUBLIC key can be exported.
* LAB NOTE: the private key is stored unencrypted on disk to keep the demo simple.
  A production system would use an HSM/KMS or at least a passphrase.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

log = logging.getLogger(__name__)


def pss_padding() -> padding.PSS:
    """RSA-PSS, MGF1(SHA-256), maximum salt length (used everywhere in NetSentinel)."""
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def verify_with_public_key(public_key, data: bytes, signature: bytes) -> bool:
    """True/False. Only a genuine signature mismatch is swallowed; other errors propagate."""
    try:
        public_key.verify(signature, data, pss_padding(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def load_public_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


class KeyStore:
    def __init__(self, keys_dir: Path):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.private_path = self.keys_dir / "netsentinel_rsa_private.pem"
        self.public_path = self.keys_dir / "netsentinel_rsa_public.pem"
        self.hmac_path = self.keys_dir / "evidence.hmackey"
        self._ensure_rsa()
        self._ensure_hmac()
        self._private = serialization.load_pem_private_key(self.private_path.read_bytes(), password=None)
        self.hmac_key = self.hmac_path.read_bytes()

    @staticmethod
    def _write_secret(path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)

    def _ensure_rsa(self) -> None:
        if self.private_path.exists() and self.public_path.exists():
            return
        log.info("Generating RSA-2048 key pair in %s", self.keys_dir)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_path.unlink(missing_ok=True)
        self._write_secret(
            self.private_path,
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
        )
        self.public_path.write_bytes(
            key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
        )

    def _ensure_hmac(self) -> None:
        if not self.hmac_path.exists():
            self._write_secret(self.hmac_path, secrets.token_bytes(32))

    # -- signing ---------------------------------------------------------
    @property
    def public_key(self):
        return self._private.public_key()

    @property
    def public_pem(self) -> bytes:
        return self.public_path.read_bytes()

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data, pss_padding(), hashes.SHA256())

    def verify(self, data: bytes, signature: bytes) -> bool:
        return verify_with_public_key(self.public_key, data, signature)
