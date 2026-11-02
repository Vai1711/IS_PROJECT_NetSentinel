import io
import wave

import pytest
from PIL import Image

from conftest import DEMO_PCAP, make_png, make_text, make_wav, needs_tshark
from evidence.evidence_manager import EvidenceError
from evidence.pcap_tools import analyze_capture_bytes
from evidence.tampering import METHODS, TamperingError, text_diff_html


def _reg(svc, incident_id, name, data):
    return svc.evidence.register(incident_id, name, data)


def test_image_tampering_methods(svc, incident_id):
    data = make_png((10, 200, 30), (40, 30))
    e = _reg(svc, incident_id, "i.png", data)
    px = svc.simulator.simulate(e["id"], "Change one pixel", {"x": 5, "y": 6})
    assert px["details"]["pixels_changed"] == 1                       # exactly one pixel differs
    a, b = Image.open(io.BytesIO(data)).convert("RGB"), Image.open(px["modified_path"]).convert("RGB")
    assert a.getpixel((5, 6)) != b.getpixel((5, 6)) and a.getpixel((0, 0)) == b.getpixel((0, 0))
    ov = svc.simulator.simulate(e["id"], "Add text overlay", {"text": "X"})
    assert ov["details"]["pixels_changed"] > 1
    cr = svc.simulator.simulate(e["id"], "Crop part of the image", {"percent": 25})
    assert Image.open(cr["modified_path"]).size == (30, 22)


def test_audio_tampering_methods(svc, incident_id):
    data = make_wav(seed=31)
    e = _reg(svc, incident_id, "a.wav", data)
    smp = svc.simulator.simulate(e["id"], "Modify one sample", {"index": 100})
    assert smp["details"]["old"] != smp["details"]["new"]
    nz = svc.simulator.simulate(e["id"], "Add noise", {"std": 400.0})
    tr = svc.simulator.simulate(e["id"], "Trim a portion", {"percent": 20})
    n = lambda p: wave.open(p).getnframes()
    assert n(tr["modified_path"]) == int(8000 * 0.8) and n(nz["modified_path"]) == 8000 and n(smp["modified_path"]) == 8000


def test_text_tampering_methods(svc, incident_id):
    e = _reg(svc, incident_id, "t.txt", make_text())
    ch = svc.simulator.simulate(e["id"], "Change one character")
    assert len(ch["details"]["old"]) == len(ch["details"]["new"]) == 1
    url = svc.simulator.simulate(e["id"], "Replace a URL")
    assert "paypa1.com" not in open(url["modified_path"]).read() and "example.invalid" in open(url["modified_path"]).read()
    ip = svc.simulator.simulate(e["id"], "Modify an IP address")
    assert ip["details"]["old"] == "10.0.0.20" and ip["details"]["new"] == "10.0.0.21"
    left, right = text_diff_html("ip 10.0.0.20 <b>", "ip 10.0.0.21 <b>")
    assert "<mark" in left and "&lt;b&gt;" in left and "<b>" not in left      # highlighted and HTML-escaped


def test_text_without_url_gives_clear_error(svc, incident_id):
    e = _reg(svc, incident_id, "plain.txt", b"nothing interesting here 12345 plain words")
    with pytest.raises(TamperingError, match="No URL"):
        svc.simulator.simulate(e["id"], "Replace a URL")


@needs_tshark
def test_pcap_tampering_methods(ingested):
    svc = ingested["svc"]
    inc = ingested["phishing"]
    cap = svc.incidents.get(inc["id"])["capture"]
    e = svc.evidence.register_capture_file(inc["id"], cap["filepath"], cap["filename"])
    original = DEMO_PCAP.read_bytes()
    base = analyze_capture_bytes(original)
    assert base["complete"] and base["packets"] == 70

    flip = svc.simulator.simulate(e["id"], "Flip one bit", {})
    assert len(open(flip["modified_path"], "rb").read()) == len(original)
    assert flip["modified_sha256"] != e["sha256"]

    fld = svc.simulator.simulate(e["id"], "Modify a packet field", {"field_name": "IP TTL"})
    assert fld["details"]["old"] != fld["details"]["new"] and fld["details"]["parse"]["complete"]   # still a valid capture
    assert fld["details"]["parse"]["packets"] == 70

    trn = svc.simulator.simulate(e["id"], "Truncate the capture", {"keep_percent": 60})
    parse = analyze_capture_bytes(open(trn["modified_path"], "rb").read())
    assert parse["complete"] is False and "truncated" in parse["note"].lower()
    assert open(e["stored_path"], "rb").read() == original               # original untouched


def test_unsupported_method_and_noop_rejected(svc, incident_id):
    e = _reg(svc, incident_id, "m.txt", make_text())
    with pytest.raises(TamperingError, match="not available"):
        svc.simulator.simulate(e["id"], "Add noise")


def test_simulated_copies_never_inside_originals(svc, incident_id):
    e = _reg(svc, incident_id, "loc.txt", make_text())
    sim = svc.simulator.simulate(e["id"], "Change one character")
    assert str(svc.settings.original_dir.resolve()) not in sim["modified_path"]
    assert str(svc.settings.simulated_dir.resolve()) in sim["modified_path"]


def test_verifier_refuses_copy_of_other_evidence(svc, incident_id):
    e1 = _reg(svc, incident_id, "x1.txt", make_text()); e2 = _reg(svc, incident_id, "x2.txt", make_text())
    s2 = svc.simulator.simulate(e2["id"], "Change one character")
    with pytest.raises(EvidenceError):
        svc.verifier.verify(e1["id"], s2["id"])


def test_defender_attack_history_is_real_and_starts_unverified(ingested):
    svc = ingested["svc"]; inc = ingested["multistage"]["id"]
    e = svc.evidence.register(inc, "hist.txt", make_text())
    sim = svc.simulator.simulate(e["id"], "Change one character")
    row = [r for r in svc.verifier.attack_history(inc) if r["Tampering Method"] == "Change one character"][-1]
    assert row["Hash Result"] == "Not yet verified"
    svc.verifier.verify(e["id"], sim["id"])
    row = [r for r in svc.verifier.attack_history(inc) if r["Tampering Method"] == "Change one character"][-1]
    assert (row["Hash Result"], row["HMAC Result"], row["Signature Result"]) == ("Mismatch", "Invalid", "Invalid")
    assert 0 < row["Bits Changed"] < 256


@pytest.mark.parametrize("etype,method", [(t, m) for t, ms in METHODS.items() for m in ms if t != "PCAP"])
def test_every_non_pcap_method_is_detected_by_all_three_checks(svc, incident_id, etype, method):
    k = sum(map(ord, method)) % 200
    data = {"Image": make_png((k, 10, 10), (48, 48)), "Audio": make_wav(seed=k), "Text": make_text()}[etype]
    e = _reg(svc, incident_id, f"p_{method[:6].replace(' ', '_')}.{ {'Image': 'png', 'Audio': 'wav', 'Text': 'txt'}[etype] }", data)
    sim = svc.simulator.simulate(e["id"], method)
    res = svc.verifier.verify(e["id"], sim["id"])["result"]
    assert (res.sha_match, res.hmac_ok, res.rsa_ok) == (False, False, False)
    assert svc.verifier.verify(e["id"])["verdict"] == "VERIFIED"           # untouched control still passes
