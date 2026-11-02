import io
import shutil
import sys
import uuid
import wave
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.ingest_service import analyze_upload  # noqa: E402
from services import build_services  # noqa: E402

DEMO_PCAP = ROOT / "demo_data" / "attack_demo.pcap"
needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="TShark is not installed")


def make_png(color=(30, 60, 90), size=(64, 48)) -> bytes:
    buf = io.BytesIO(); Image.new("RGB", size, color).save(buf, "PNG"); return buf.getvalue()


def make_wav(seconds=1.0, rate=8000, seed=1) -> bytes:
    t = np.arange(int(rate * seconds)) / rate
    pcm = (np.sin(2 * np.pi * (200 + seed) * t) * 8000).astype("<i2")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(pcm.tobytes())
    return buf.getvalue()


def make_text() -> bytes:
    return (f"case {uuid.uuid4()}\nClick http://paypa1.com/secure/login from host 10.0.0.20 immediately.\n").encode()


@pytest.fixture(scope="session")
def svc(tmp_path_factory):
    return build_services(tmp_path_factory.mktemp("netsentinel_data"))


@pytest.fixture(scope="session")
def ingested(svc):
    if shutil.which("tshark") is None:
        pytest.skip("TShark is not installed")
    res = analyze_upload(svc, "attack_demo.pcap", DEMO_PCAP.read_bytes())
    incs = {i["source_ip"]: i for i in svc.incidents.list(res["capture_id"])}
    return {"svc": svc, "result": res, "phishing": incs["10.0.0.20"], "multistage": incs["10.0.0.66"]}


@pytest.fixture()
def fresh(tmp_path):
    """Service with its own empty data dir (no ingestion)."""
    return build_services(tmp_path)


@pytest.fixture(scope="session")
def incident_id(ingested):
    return ingested["phishing"]["id"]
