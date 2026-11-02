"""Real timing of SHA-256, HMAC-SHA256 and RSA-2048-PSS using time.perf_counter_ns().

Methodology: one untimed warm-up call, then `repeats` timed calls; the MEDIAN is reported (robust
to scheduler noise) with min/max. Inputs are random bytes generated here (clearly labelled
"generated") plus, optionally, the real evidence files supplied by the caller.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import statistics
import time
import tracemalloc
from typing import Callable, Dict, List, Sequence

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.keys import KeyStore

DEFAULT_SIZES = [1_024, 10_240, 102_400, 1_048_576, 10_485_760]


def _time_ms(fn: Callable[[], object], repeats: int) -> Dict:
    fn()  # warm-up
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return {"median_ms": statistics.median(samples), "min_ms": min(samples), "max_ms": max(samples), "runs": repeats}


def _inputs(sizes: Sequence[int], evidence: Sequence[Dict]) -> List[Dict]:
    items = [{"label": f"generated {s:,} B", "size": s, "data": os.urandom(s), "origin": "generated"} for s in sizes]
    for e in evidence:
        items.append({"label": e["label"], "size": len(e["data"]), "data": e["data"], "origin": "evidence"})
    return sorted(items, key=lambda i: i["size"])


def bench_sha256(sizes: Sequence[int], repeats: int = 15, evidence: Sequence[Dict] = ()) -> List[Dict]:
    out = []
    for it in _inputs(sizes, evidence):
        r = _time_ms(lambda d=it["data"]: hashlib.sha256(d).digest(), repeats)
        out.append({"label": it["label"], "size_bytes": it["size"], "origin": it["origin"], **r})
    return out


def bench_hmac(key: bytes, sizes: Sequence[int], repeats: int = 15, evidence: Sequence[Dict] = ()) -> List[Dict]:
    out = []
    for it in _inputs(sizes, evidence):
        r = _time_ms(lambda d=it["data"]: hmac.new(key, d, hashlib.sha256).digest(), repeats)
        out.append({"label": it["label"], "size_bytes": it["size"], "origin": it["origin"], **r})
    return out


def bench_rsa(keys: KeyStore, repeats: int = 30, message_size: int = 512, keygen_runs: int = 3) -> Dict:
    """Sign vs verify on the same message (an evidence-manifest-sized input) with the real key.

    Key generation is timed separately with fresh throw-away keys (it is a one-off cost).
    """
    msg = os.urandom(message_size)
    sig = keys.sign(msg)
    sign = _time_ms(lambda: keys.sign(msg), repeats)
    verify = _time_ms(lambda: keys.verify(msg, sig), max(repeats, 50))
    samples = []
    for _ in range(keygen_runs):
        t0 = time.perf_counter_ns()
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    keygen = {"median_ms": statistics.median(samples), "min_ms": min(samples), "max_ms": max(samples), "runs": keygen_runs}
    return {"message_size": message_size, "sign": sign, "verify": verify, "keygen": keygen, "key_bits": 2048,
            "scheme": "RSA-PSS, MGF1-SHA256, SHA-256"}


def run_all(keys: KeyStore, sizes: Sequence[int] = DEFAULT_SIZES, repeats: int = 15,
            evidence: Sequence[Dict] = (), rsa_repeats: int = 30) -> Dict:
    return {"repeats": repeats, "sizes": list(sizes),
            "sha256": bench_sha256(sizes, repeats, evidence),
            "hmac": bench_hmac(keys.hmac_key, sizes, repeats, evidence),
            "rsa": bench_rsa(keys, rsa_repeats)}


def profile_comparison(keys: KeyStore, sizes: Sequence[int] = DEFAULT_SIZES, repeats: int = 5) -> Dict:
    """Measure wall time, CPU-time ratio, and peak Python-tracked allocations.

    CPU percentage is process CPU time / elapsed time * 100 (one-core equivalent).
    tracemalloc does not account for native-library allocations or whole-process RSS.
    RSA is end-to-end PSS signing of each input, including SHA-256 hashing.
    """
    inputs = _inputs(sizes, ())
    results = {"sha256": [], "hmac": [], "rsa": []}
    for item in inputs:
        data = item["data"]
        funcs = {
            "sha256": lambda d=data: hashlib.sha256(d).digest(),
            "hmac": lambda d=data: hmac.new(keys.hmac_key, d, hashlib.sha256).digest(),
            "rsa": lambda d=data: keys.sign(d),
        }
        for name, fn in funcs.items():
            fn()  # warm-up outside measurement
            times, cpu_pct = [], []
            for _ in range(repeats):
                wall0, cpu0 = time.perf_counter_ns(), time.process_time_ns()
                fn()
                cpu_ns = time.process_time_ns() - cpu0
                wall_ns = max(1, time.perf_counter_ns() - wall0)
                times.append(wall_ns / 1e6)
                cpu_pct.append(100 * cpu_ns / wall_ns)
            # Profile allocations separately: tracemalloc would distort timings.
            tracemalloc.start()
            try:
                tracemalloc.reset_peak()
                fn()
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            median_ms = statistics.median(times)
            results[name].append({
                "size_bytes": item["size"], "median_ms": median_ms,
                "cpu_percent_one_core": statistics.median(cpu_pct),
                "peak_python_kib": peak / 1024,
                "throughput_mb_s": (item["size"] / 1_000_000) / (median_ms / 1000) if median_ms > 0 else None,
            })
    return {"repeats": repeats, "results": results,
            "cpu_definition": "Process CPU time / wall time, percent of one core; not system-wide utilization",
            "memory_definition": "Peak Python-tracked allocations (tracemalloc); excludes native allocations",
            "rsa_definition": "RSA-PSS signs each entire input; includes SHA-256 hashing; throughput is not bulk-encryption throughput"}
