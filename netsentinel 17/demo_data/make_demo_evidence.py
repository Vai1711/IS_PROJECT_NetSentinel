"""Generates the SIMULATED supporting evidence used in the viva demo (deterministic).

These files are synthetic. They are not extracted from the PCAP; they stand in for material an
investigator would supply alongside it (message, screenshot, voicemail).
"""
from pathlib import Path
import wave
import numpy as np
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent

MESSAGE = """SIMULATED EVIDENCE - synthetic phishing message for the NetSentinel lab demo
From: PayPal Security <security@paypa1.com>
To: finance-desk@corp.example
Date: Sun, 04 Oct 2026 17:22:10 +0000
Subject: Urgent: your account has been limited

Dear customer,

We detected unusual activity on your account. Verify your identity within 24 hours
or your account will be suspended:

    http://paypa1.com/secure/login

This message was opened on workstation 10.0.0.20 and the link was resolved via the
corporate resolver 10.0.0.1.

PayPal Security Team
"""


def make_screenshot(path: Path) -> None:
    img = Image.new("RGB", (640, 400), (245, 247, 250))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 640, 44], fill=(0, 48, 135))
    d.text((16, 15), "paypa1.com  -  Log in to your account", fill=(255, 255, 255))
    d.rectangle([180, 90, 460, 330], outline=(160, 170, 180), fill=(255, 255, 255))
    d.text((200, 110), "Email", fill=(60, 60, 60)); d.rectangle([200, 128, 440, 152], outline=(150, 150, 150))
    d.text((200, 170), "Password", fill=(60, 60, 60)); d.rectangle([200, 188, 440, 212], outline=(150, 150, 150))
    d.rectangle([200, 240, 440, 270], fill=(0, 112, 224)); d.text((298, 249), "Log In", fill=(255, 255, 255))
    d.text((16, 370), "SIMULATED EVIDENCE - synthetic mock-up of a lookalike page", fill=(190, 0, 0))
    img.save(path, "PNG")


def make_recording(path: Path) -> None:
    sr = 8000
    t = np.arange(int(sr * 3)) / sr
    f0 = 140 + 40 * np.sin(2 * np.pi * 1.5 * t)                      # slowly varying "voice-like" pitch
    env = 0.5 * (1 + np.sin(2 * np.pi * 3 * t)) * (t % 1.0 < 0.8)    # syllable-like pulses
    sig = env * (np.sin(2 * np.pi * np.cumsum(f0) / sr) + 0.4 * np.sin(2 * np.pi * 2 * np.cumsum(f0) / sr))
    pcm = (sig / 1.4 * 14000).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(sr); w.writeframes(pcm.tobytes())


if __name__ == "__main__":
    (HERE / "SIMULATED_phishing_message.txt").write_text(MESSAGE, encoding="utf-8")
    make_screenshot(HERE / "SIMULATED_phishing_screenshot.png")
    make_recording(HERE / "SIMULATED_voice_recording.wav")
    print("Demo evidence written to", HERE)
