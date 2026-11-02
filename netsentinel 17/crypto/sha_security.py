"""SHA-256 security experiments: avalanche effect and collision resistance (real computations)."""
from __future__ import annotations

import hashlib
import math
import os
import random
import statistics
from typing import Dict, Optional

from evidence.integrity import hamming_bits


def _flip(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def avalanche(data: bytes, trials: int = 256, bit_index: Optional[int] = None, seed: Optional[int] = None) -> Dict:
    """Flip ONE input bit and count how many of the 256 digest bits change.

    Reports one detailed example (original/modified digest) plus the mean over `trials` random
    single-bit flips; the ideal average for a good hash is 50% (128 bits).
    """
    if not data:
        raise ValueError("Need at least one byte of input.")
    rng = random.Random(seed)
    nbits = len(data) * 8
    base = hashlib.sha256(data).hexdigest()
    first = rng.randrange(nbits) if bit_index is None else bit_index
    mod = hashlib.sha256(_flip(data, first)).hexdigest()
    example_bits = hamming_bits(base, mod)
    counts = [hamming_bits(base, hashlib.sha256(_flip(data, rng.randrange(nbits))).hexdigest())
              for _ in range(trials)]
    mean = statistics.fmean(counts)
    return {"input_bytes": len(data), "flipped_bit": first, "original_digest": base, "modified_digest": mod,
            "differing_bits": example_bits, "avalanche_pct": example_bits / 256 * 100,
            "trials": trials, "trial_changed_bits": counts, "mean_bits": mean, "mean_pct": mean / 256 * 100,
            "min_bits": min(counts), "max_bits": max(counts), "stdev_bits": statistics.pstdev(counts),
            "expected_pct": 50.0}


def collision_test(n: int = 100_000, truncated_bits: int = 24, truncated_n: int = 20_000,
                   seed: Optional[int] = None) -> Dict:
    """Hash many distinct random inputs and count collisions.

    Full SHA-256: observing zero collisions is expected and proves nothing (birthday bound below).
    Truncated demo: keeping only `truncated_bits` of the digest makes collisions findable, which
    illustrates the birthday paradox that full SHA-256's 256-bit output pushes out of reach.
    """
    rng = random.Random(seed)
    gen = (lambda: rng.randbytes(32)) if seed is not None else (lambda: os.urandom(32))
    inputs = set()
    while len(inputs) < n:
        inputs.add(gen())
    hashes = {hashlib.sha256(x).digest() for x in inputs}
    full_collisions = len(inputs) - len(hashes)

    tinputs = set()
    while len(tinputs) < truncated_n:
        tinputs.add(gen())
    seen: Dict[int, bytes] = {}
    t_collisions = 0
    mask = (1 << truncated_bits) - 1
    for x in tinputs:
        h = int.from_bytes(hashlib.sha256(x).digest(), "big") >> (256 - truncated_bits)
        if h in seen:
            t_collisions += 1
        else:
            seen[h] = x
    expected_pairs = truncated_n * (truncated_n - 1) / 2 / (2 ** truncated_bits)
    p_full = n * (n - 1) / 2 / 2 ** 256
    return {"inputs_tested": n, "unique_hashes": len(hashes), "observed_collisions": full_collisions,
            "birthday_probability_full": p_full, "log2_work_generic_collision": 128,
            "truncated": {"bits": truncated_bits, "inputs": truncated_n, "observed_collisions": t_collisions,
                          "expected_colliding_pairs": expected_pairs,
                          "p_at_least_one": 1 - math.exp(-expected_pairs)}}
