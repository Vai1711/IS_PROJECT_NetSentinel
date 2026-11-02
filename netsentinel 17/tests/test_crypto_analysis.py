import hashlib

import pytest

from crypto import benchmarks, rsa_security, sha_security
from evidence.integrity import hamming_bits


def test_avalanche_one_bit_changes_about_half_the_digest():
    r = sha_security.avalanche(b"NetSentinel evidence " * 10, trials=300, seed=7)
    assert r["differing_bits"] == hamming_bits(r["original_digest"], r["modified_digest"])
    assert r["original_digest"] == hashlib.sha256(b"NetSentinel evidence " * 10).hexdigest()
    assert 108 <= r["differing_bits"] <= 148
    assert 45 <= r["mean_pct"] <= 55 and r["expected_pct"] == 50


def test_collision_experiment_counts_are_consistent():
    r = sha_security.collision_test(n=5000, truncated_bits=24, truncated_n=5000, seed=3)
    assert r["inputs_tested"] == 5000 and r["unique_hashes"] + r["observed_collisions"] == 5000
    assert r["observed_collisions"] == 0 and r["log2_work_generic_collision"] == 128
    assert r["truncated"]["observed_collisions"] >= 0 and r["truncated"]["expected_colliding_pairs"] > 0.5


def test_rsa_security_demo_behaves_securely(svc):
    r = rsa_security.rsa_security_demo(svc.keys, b"some evidence bytes" * 20, "test data")
    assert r["all_passed"] and len(r["tests"]) == 5
    assert r["modulus_bits"] == 2048 and r["public_exponent"] == 65537 and r["signature_bytes"] == 256
    valid = [t for t in r["tests"] if t["expected"] == "valid"]
    assert len(valid) == 1 and valid[0]["observed"] == "valid"


def test_benchmarks_produce_real_measurements(svc):
    out = benchmarks.run_all(svc.keys, sizes=[1024, 65536], repeats=5, rsa_repeats=5,
                             evidence=[{"label": "EV-test", "data": b"x" * 5000}])
    assert [r["size_bytes"] for r in out["sha256"]] == sorted(r["size_bytes"] for r in out["sha256"])
    assert any(r["origin"] == "evidence" for r in out["hmac"])
    assert all(r["median_ms"] > 0 and r["runs"] == 5 for r in out["sha256"] + out["hmac"])
    assert out["rsa"]["sign"]["median_ms"] > out["rsa"]["verify"]["median_ms"] > 0     # signing is slower than verifying
    assert out["rsa"]["keygen"]["median_ms"] > out["rsa"]["sign"]["median_ms"]
    big = benchmarks.bench_sha256([1024, 4_194_304], repeats=3)
    assert big[1]["median_ms"] > big[0]["median_ms"]
