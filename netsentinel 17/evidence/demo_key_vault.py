"""Educational Cryptographic Key Vault (classroom demonstration only).

Generates DISPOSABLE demo keys and a printable PDF for explaining RSA and HMAC.

Isolation rules (this module is deliberately separate from NetSentinel's real evidence protection):
* It never imports or uses KeyStore, the database or the reports folder, so it cannot read, export or
  change the operational signing key, HMAC secret or any stored evidence signature.
* Demo keys exist only in memory. Nothing is written to disk or SQLite, and nothing here logs key material.
* The PIN below is a UI demonstration only. It is NOT real authentication or cryptographic protection.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from crypto.keys import pss_padding, verify_with_public_key   # stateless helpers only; no key material

DEMO_PIN = "1234"        # classroom demonstration PIN: not secure, not real authentication
RSA_KEY_SIZE = 2048
HMAC_KEY_BITS = 256
SAMPLE_MESSAGE = b"NetSentinel educational sample message: evidence EV001 is unchanged."
WARNING = "EDUCATIONAL USE ONLY — DO NOT USE THESE KEYS FOR REAL EVIDENCE"

NAVY, TEAL, RED = colors.HexColor("#0b1f33"), colors.HexColor("#0e8c9c"), colors.HexColor("#c62828")


def check_pin(pin: str) -> bool:
    """Constant-time comparison with the demonstration PIN."""
    return hmac.compare_digest((pin or "").encode(), DEMO_PIN.encode())


@dataclass
class DemoKeys:
    """Disposable demo key material plus the results of the sample operations."""
    private_pem: bytes = field(repr=False)          # repr=False: never printed by accident
    public_pem: bytes
    hmac_key: bytes = field(repr=False)
    generated_at: str
    key_size: int
    public_exponent: int
    sample: dict = field(default_factory=dict)


def generate_demo_keys() -> DemoKeys:
    """Fresh RSA-2048 pair (cryptography) and a random 256-bit HMAC key (secrets). Independent of the real keys."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    numbers = private.public_key().public_numbers()
    keys = DemoKeys(
        private_pem=private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()),
        public_pem=private.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo),
        hmac_key=secrets.token_bytes(32),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        key_size=private.key_size,
        public_exponent=numbers.e,
    )
    keys.sample = sample_operations(keys)
    return keys


def sample_operations(keys: DemoKeys, message: bytes = SAMPLE_MESSAGE) -> dict:
    """Run the four operations for real with the demo keys (nothing is hardcoded)."""
    private = serialization.load_pem_private_key(keys.private_pem, password=None)
    signature = private.sign(message, pss_padding(), hashes.SHA256())
    public = serialization.load_pem_public_key(keys.public_pem)
    return {
        "message": message.decode(),
        "sha256": hashlib.sha256(message).hexdigest(),
        "hmac": hmac.new(keys.hmac_key, message, hashlib.sha256).hexdigest(),
        "signature_b64": base64.b64encode(signature).decode(),
        "signature_valid": verify_with_public_key(public, message, signature),
    }


# ---------------------------------------------------------------------------- PDF (in memory only)
def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], textColor=NAVY, fontSize=20, spaceAfter=8),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], textColor=TEAL, fontSize=15, spaceBefore=4, spaceAfter=8),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=10.5, leading=15, spaceAfter=7),
        "warn": ParagraphStyle("w", parent=base["BodyText"], textColor=RED, fontSize=11, leading=15, spaceAfter=8,
                               fontName="Helvetica-Bold"),
        "mono": ParagraphStyle("m", fontName="Courier", fontSize=8.6, leading=11),
        "mono_big": ParagraphStyle("mb", fontName="Courier-Bold", fontSize=10.5, leading=15),
    }


def _page_decor(canvas, doc):
    """Warning banner, light watermark and page number on every page (drawn before the content)."""
    w, h = A4
    canvas.saveState()
    canvas.setFillColor(colors.Color(0.93, 0.93, 0.93))
    canvas.setFont("Helvetica-Bold", 30)
    canvas.translate(w / 2, h / 2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "EDUCATIONAL USE ONLY")
    canvas.restoreState()
    canvas.saveState()
    canvas.setFillColor(RED)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawCentredString(w / 2, h - 12 * mm, WARNING)
    canvas.setFillColor(colors.grey)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w / 2, 10 * mm, f"NetSentinel educational key report  |  page {doc.page} of 5")
    canvas.restoreState()


def _wrap(text: str, n: int) -> str:
    return "\n".join(text[i:i + n] for i in range(0, len(text), n))


def build_keys_pdf(keys: DemoKeys) -> bytes:
    """Five-page printable PDF built in memory (BytesIO). Nothing touches the disk."""
    st = _styles()
    s = keys.sample
    pem_pub, pem_priv = keys.public_pem.decode().strip(), keys.private_pem.decode().strip()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=24 * mm,
                            bottomMargin=20 * mm, title="NetSentinel Educational Key Report",
                            author="NetSentinel", pageCompression=0)     # uncompressed so the text is searchable
    f = []

    # page 1: summary
    f += [Paragraph("NetSentinel — Educational Cryptographic Key Report", st["title"]),
          Paragraph(WARNING, st["warn"])]
    t = Table([["Generated", keys.generated_at],
               ["RSA key size", f"{keys.key_size} bits"],
               ["RSA public exponent", str(keys.public_exponent)],
               ["HMAC key size", f"{HMAC_KEY_BITS} bits (32 random bytes)"]], colWidths=[50 * mm, 120 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 10),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e6f2f4")),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    f += [t, Spacer(1, 8 * mm),
          Paragraph("Symmetric cryptography (HMAC)", st["h1"]),
          Paragraph("One shared secret key is used both to create and to check a tag. Anyone who can check the tag "
                    "can also forge one, so the key must stay secret between the parties.", st["body"]),
          Paragraph("Asymmetric cryptography (RSA)", st["h1"]),
          Paragraph("A key pair is used: the private key signs and the public key verifies. The public key can be "
                    "shared freely; the private key must never be shared.", st["body"]),
          Paragraph("These are disposable educational keys. They were generated for this demonstration, are not "
                    "stored anywhere by NetSentinel, and are completely separate from the keys that protect real "
                    "evidence and reports.", st["warn"]),
          PageBreak()]

    # page 2: public key
    f += [Paragraph("RSA Public Key", st["h1"]),
          Paragraph("This key can be shared. Anyone can use it to verify a signature made with the matching private "
                    "key, but it cannot be used to create signatures.", st["body"]),
          Preformatted(pem_pub, st["mono"]), PageBreak()]

    # page 3: private key
    f += [Paragraph("RSA Private Key", st["h1"]),
          Paragraph("CONFIDENTIAL — DEMONSTRATION PRIVATE KEY", st["warn"]),
          Paragraph("The private key creates digital signatures. A real private key must never be publicly "
                    "distributed, emailed or printed. This one is shown only because it is a disposable classroom "
                    "example.", st["body"]),
          Preformatted(pem_priv, st["mono"]), PageBreak()]

    # page 4: HMAC key
    f += [Paragraph("HMAC Secret Key", st["h1"]),
          Paragraph("A 256-bit random key shown in hexadecimal. The same secret key is used to generate and to verify "
                    "HMAC-SHA256 authentication tags.", st["body"]),
          Spacer(1, 4 * mm), Preformatted(keys.hmac_key.hex(), st["mono_big"]), PageBreak()]

    # page 5: sample operations
    f += [Paragraph("Sample Cryptographic Operations", st["h1"]),
          Paragraph("All values below were produced just now by real operations with the demo keys.", st["body"]),
          Paragraph("Sample message", st["h1"]), Preformatted(_wrap(s["message"], 80), st["mono"]),
          Paragraph("SHA-256 digest", st["h1"]), Preformatted(_wrap(s["sha256"], 64), st["mono"]),
          Paragraph("HMAC-SHA256 tag (demo HMAC key)", st["h1"]), Preformatted(_wrap(s["hmac"], 64), st["mono"]),
          Paragraph("RSA-PSS signature, Base64 (demo private key)", st["h1"]),
          Preformatted(_wrap(s["signature_b64"], 76), st["mono"]),
          Paragraph("RSA signature verification (demo public key)", st["h1"]),
          Paragraph("VALID" if s["signature_valid"] else "INVALID", st["warn"] if not s["signature_valid"] else st["body"])]
    doc.build(f, onFirstPage=_page_decor, onLaterPages=_page_decor)
    return buf.getvalue()
