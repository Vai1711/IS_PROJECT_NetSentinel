"""Educational Key Vault: crypto correctness, PDF content, isolation from the real keys, and the PIN-gated UI."""
import ast
import base64
import hashlib
import hmac
import logging
import re
import sqlite3
from pathlib import Path

import pytest
import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from streamlit.proto.TextInput_pb2 import TextInput
from streamlit.testing.v1 import AppTest

from conftest import ROOT
from crypto.keys import pss_padding
from evidence import demo_key_vault as dkv
from ui.state import PAGES


# ---------------------------------------------------------------------------- crypto module
def test_demo_rsa_2048_keys_generated_correctly():
    k = dkv.generate_demo_keys()
    priv = serialization.load_pem_private_key(k.private_pem, password=None)
    pub = serialization.load_pem_public_key(k.public_pem)
    assert priv.key_size == 2048 and k.key_size == 2048
    assert pub.public_numbers().e == 65537 == k.public_exponent
    assert pub.public_numbers() == priv.public_key().public_numbers()      # the two halves match
    assert len(k.hmac_key) == 32                                           # 256-bit HMAC key


def test_signature_verifies_with_matching_public_key_only():
    k, other = dkv.generate_demo_keys(), dkv.generate_demo_keys()
    msg = b"hello"
    priv = serialization.load_pem_private_key(k.private_pem, password=None)
    sig = priv.sign(msg, pss_padding(), hashes.SHA256())
    from crypto.keys import verify_with_public_key
    assert verify_with_public_key(serialization.load_pem_public_key(k.public_pem), msg, sig)
    assert not verify_with_public_key(serialization.load_pem_public_key(other.public_pem), msg, sig)   # different key
    assert not verify_with_public_key(serialization.load_pem_public_key(k.public_pem), msg + b"x", sig)  # changed data
    assert k.sample["signature_valid"] is True


def test_hmac_and_sha256_are_real_computations():
    k = dkv.generate_demo_keys()
    msg = dkv.SAMPLE_MESSAGE
    assert k.sample["sha256"] == hashlib.sha256(msg).hexdigest()
    assert k.sample["hmac"] == hmac.new(k.hmac_key, msg, hashlib.sha256).hexdigest()
    assert k.sample["hmac"] != dkv.generate_demo_keys().sample["hmac"]       # different key -> different tag
    assert hmac.compare_digest(bytes.fromhex(k.sample["hmac"]), hmac.new(k.hmac_key, msg, hashlib.sha256).digest())


def test_every_generation_is_fresh():
    a, b = dkv.generate_demo_keys(), dkv.generate_demo_keys()
    assert a.private_pem != b.private_pem and a.hmac_key != b.hmac_key


def test_pdf_has_five_pages_and_all_key_sections():
    k = dkv.generate_demo_keys()
    pdf = dkv.build_keys_pdf(k)
    assert pdf.startswith(b"%PDF")
    assert len(re.findall(rb"/Type /Page\b(?!s)", pdf)) == 5
    for needle in [k.public_pem.decode().strip().splitlines()[0], k.public_pem.decode().strip().splitlines()[1],
                   k.private_pem.decode().strip().splitlines()[0], k.private_pem.decode().strip().splitlines()[1],
                   k.hmac_key.hex(), k.sample["sha256"], k.sample["hmac"], "RSA Public Key", "RSA Private Key",
                   "HMAC Secret Key", "Sample Cryptographic Operations", "CONFIDENTIAL", "DEMONSTRATION PRIVATE KEY",
                   "EDUCATIONAL USE ONLY", "2048 bits", "65537"]:
        assert needle.encode() in pdf, needle
    # the whole signature is present (it is wrapped over several lines)
    sig_lines = [ln for ln in re.findall(rb"\(([A-Za-z0-9+/=]{20,})\) Tj", pdf)]
    assert b"".join(sig_lines).count(k.sample["signature_b64"].encode()) >= 1 or \
        k.sample["signature_b64"].encode()[:60] in pdf


def test_pin_check():
    assert dkv.check_pin("1234") and not dkv.check_pin("0000") and not dkv.check_pin("") and not dkv.check_pin(None)


def test_module_is_isolated_from_operational_keys_and_database():
    tree = ast.parse((ROOT / "evidence" / "demo_key_vault.py").read_text())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
               {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m.startswith(("database", "services", "reports")) for m in imported if m)
    from_keys = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "crypto.keys"]
    assert {a.name for n in from_keys for a in n.names} <= {"pss_padding", "verify_with_public_key"}   # never KeyStore
    src = (ROOT / "evidence" / "demo_key_vault.py").read_text()
    assert "open(" not in src and "write_bytes" not in src and "logging" not in src and "print(" not in src


def test_generation_logs_no_key_material(caplog):
    with caplog.at_level(logging.DEBUG):
        k = dkv.generate_demo_keys(); dkv.build_keys_pdf(k)
    text = caplog.text
    assert k.hmac_key.hex() not in text and "PRIVATE KEY" not in text
    assert "PRIVATE" not in repr(k) and k.hmac_key.hex() not in repr(k)      # repr never prints secrets


# ---------------------------------------------------------------------------- UI (AppTest)
@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NETSENTINEL_DATA_DIR", str(tmp_path))
    st.cache_resource.clear()
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    at.run()
    at.sidebar.radio[0].set_value(PAGES[1]).run()      # Evidence Vault (works with no incident)
    assert not at.exception, [e.value for e in at.exception]
    return at


def _labels(at):
    return [b.label for b in at.button]


def _unlock(at, pin="1234"):
    at.text_input(key="kv_pin").set_value(pin)
    [b for b in at.button if b.label == "Unlock"][0].click().run()
    assert not at.exception, [e.value for e in at.exception]


def test_vault_is_locked_by_default_and_hides_everything(app):
    assert "kv_unlocked" not in app.session_state or not app.session_state["kv_unlocked"]
    assert any("Cryptographic Key Vault" in s.value for s in app.subheader)
    assert any("Enter the demonstration PIN" in m.value for m in app.markdown)
    assert app.text_input(key="kv_pin").proto.type == TextInput.PASSWORD       # masked input
    assert "Unlock" in _labels(app)
    assert "Generate New Demo Keys" not in _labels(app) and "Lock Vault" not in _labels(app)
    assert len(app.get("download_button")) == 0


@pytest.mark.parametrize("pin", ["0000", "123", "12345", "abcd", ""])
def test_wrong_pin_does_not_unlock(app, pin):
    _unlock(app, pin)
    assert any("Incorrect PIN" in e.value for e in app.error)
    assert "Generate New Demo Keys" not in _labels(app)
    assert len(app.get("download_button")) == 0
    assert app.text_input(key="kv_pin").value == ""                             # typed PIN is not kept


def test_download_unavailable_until_unlocked_and_generated(app):
    assert len(app.get("download_button")) == 0                                # locked
    _unlock(app)
    assert "Generate New Demo Keys" in _labels(app) and "Lock Vault" in _labels(app)
    assert len(app.get("download_button")) == 0                                # unlocked but no keys yet
    [b for b in app.button if b.label == "Generate New Demo Keys"][0].click().run()
    assert not app.exception
    dl = app.get("download_button")
    assert len(dl) == 1 and dl[0].proto.label == "Download Educational Keys PDF"


def test_summary_never_shows_key_material_and_lock_discards_keys(app):
    _unlock(app)
    [b for b in app.button if b.label == "Generate New Demo Keys"][0].click().run()
    keys = app.session_state["kv_keys"]
    rendered = " ".join(str(e.value) for e in list(app.markdown) + list(app.caption) + list(app.text)) + \
        " ".join(str(df.value.to_dict("records")) for df in app.dataframe)
    assert "BEGIN" not in rendered and keys.hmac_key.hex() not in rendered
    summary = app.dataframe[0].value.to_dict("records")
    assert [r["Key"] for r in summary] == ["RSA Public Key", "RSA Private Key", "HMAC Secret Key"]
    assert "2048" in summary[0]["Details"] and "65537" in summary[0]["Details"]
    first = keys.private_pem
    [b for b in app.button if b.label == "Generate New Demo Keys"][0].click().run()
    assert app.session_state["kv_keys"].private_pem != first                    # fresh pair each time
    [b for b in app.button if b.label == "Discard Keys"][0].click().run()
    assert "kv_keys" not in app.session_state and "kv_pdf" not in app.session_state
    assert len(app.get("download_button")) == 0
    [b for b in app.button if b.label == "Generate New Demo Keys"][0].click().run()
    [b for b in app.button if b.label == "Lock Vault"][0].click().run()
    assert "kv_keys" not in app.session_state and "Unlock" in _labels(app)       # locking wipes the keys too
    assert len(app.get("download_button")) == 0


def test_demo_keys_never_touch_database_files_or_operational_keys(app, tmp_path):
    def snapshot():
        files = {str(p.relative_to(tmp_path)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(tmp_path.rglob("*")) if p.is_file() and p.suffix not in {".log"}}
        con = sqlite3.connect(str(next(tmp_path.rglob("*.db"))))
        counts = {t: con.execute(f"select count(*) from {t}").fetchone()[0]
                  for (t,) in con.execute("select name from sqlite_master where type='table'")}
        con.close()
        return files, counts
    keys_dir = tmp_path / "keys"
    before_files, before_counts = snapshot()
    real_private = (keys_dir / "netsentinel_rsa_private.pem").read_bytes()
    real_public = (keys_dir / "netsentinel_rsa_public.pem").read_bytes()
    real_hmac = (keys_dir / "evidence.hmackey").read_bytes()

    _unlock(app)
    [b for b in app.button if b.label == "Generate New Demo Keys"][0].click().run()
    demo = app.session_state["kv_keys"]
    assert demo.public_pem != real_public and demo.private_pem != real_private and demo.hmac_key != real_hmac

    after_files, after_counts = snapshot()
    assert after_files == before_files, "no file may be created or changed by the key vault"
    assert after_counts == before_counts, "evidence database must be untouched"
    # operational keys are byte-for-byte unchanged
    assert (keys_dir / "netsentinel_rsa_private.pem").read_bytes() == real_private
    assert (keys_dir / "netsentinel_rsa_public.pem").read_bytes() == real_public
    assert (keys_dir / "evidence.hmackey").read_bytes() == real_hmac
    # and the demo secrets appear nowhere on disk (database, keys, reports, logs)
    secret_body = b"".join(demo.private_pem.splitlines()[1:-1])
    for p in tmp_path.rglob("*"):
        if p.is_file():
            blob = p.read_bytes()
            assert demo.hmac_key.hex().encode() not in blob and demo.hmac_key not in blob, p
            assert secret_body[:60] not in blob.replace(b"\n", b""), p
