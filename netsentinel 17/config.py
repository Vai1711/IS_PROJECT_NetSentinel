"""Central configuration: filesystem layout and upload limits.

All mutable state (SQLite DB, keys, evidence files, reports) lives under one
data directory that is NOT part of the source tree / version control.
Override with the NETSENTINEL_DATA_DIR environment variable (the test-suite does).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DEMO_DIR = PROJECT_ROOT / "demo_data"

MB = 1024 * 1024
# Per-type upload limits (bytes) and the extensions accepted for each type.
UPLOAD_LIMITS = {"PCAP": 100 * MB, "Image": 10 * MB, "Audio": 25 * MB, "Text": 1 * MB}
ALLOWED_EXTENSIONS = {
    "PCAP": {".pcap", ".pcapng"},
    "Image": {".png", ".jpg", ".jpeg"},
    "Audio": {".wav"},
    "Text": {".txt", ".eml", ".log"},
}


@dataclass(frozen=True)
class Settings:
    data_dir: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "netsentinel.db"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def original_dir(self) -> Path:
        return self.data_dir / "evidence" / "original"

    @property
    def simulated_dir(self) -> Path:
        return self.data_dir / "evidence" / "simulated"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure(self) -> "Settings":
        for p in (self.data_dir, self.keys_dir, self.captures_dir, self.original_dir,
                  self.simulated_dir, self.reports_dir):
            p.mkdir(parents=True, exist_ok=True)
        return self


def load_settings(data_dir: str | os.PathLike | None = None) -> Settings:
    base = data_dir or os.environ.get("NETSENTINEL_DATA_DIR") or (PROJECT_ROOT / "data")
    return Settings(Path(base).expanduser().resolve()).ensure()
