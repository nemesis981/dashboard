"""memfeatures - derived features from a small region prefix (step 4e-bis). PUBLIC, pure.

4d and 4e measured that structural metadata alone (backing, permissions, size) does NOT
separate code injection from a JIT. The one untested candidate was CONTENT-based: an
executable image header at the base of an anonymous region, since a JIT emits raw machine
code while a reflective loader maps a whole PE/ELF image. Testing it needs to read a few
bytes of memory -- which is why this is opt-in and tightly bounded.

CONTRACT (operator-authorised 2026-08-22)
-----------------------------------------
  * Opt-in, default OFF -- same posture as memcap's memscan_enabled.
  * Reads ONLY a fixed page-sized prefix, and ONLY of regions already flagged as
    candidates (private + executable + {anonymous | memfd}). Never a blanket memory scan.
  * Computes exactly two DERIVED features and then DISCARDS the raw bytes: a header-match
    label (PE/ELF magic) and Shannon entropy. The raw bytes are never returned by
    compute_features, never logged, never persisted, never transmitted off-device.

The feature MATH here is pure and platform-neutral (tested anywhere). The READ is done by
the caller through the platform acquisition layer (linmem/winmem), so this module never
touches process memory itself -- it only turns a handful of bytes into two numbers and
lets them go.
"""

from __future__ import annotations

import math

#: How many bytes of a candidate region to look at. One page. A reflective image header
#: lives in the first bytes; more than a page buys nothing for this question and reads
#: more memory than needed.
PREFIX_BYTES = 4096

#: Executable-image magic numbers at a region base. Not an exhaustive format parser --
#: the question is only "does this anonymous region begin with a mapped image header",
#: which the magic answers.
_MAGICS = ((b"MZ", "pe"), (b"\x7fELF", "elf"))


def candidate_region(region: dict) -> bool:
    """Is this a region worth reading a prefix of? private + executable + not a real file.

    memfd counts as a candidate even though its `backing` is file-ish: 4e showed an
    injector can hide a payload behind a memfd exactly as a benign JIT does, so it is
    precisely a region we must look inside rather than trust by backing.
    """
    if not region.get("executable"):
        return False
    backing = region.get("backing")
    is_memfd = backing == "memfd" or str(region.get("path", "")).startswith("/memfd:")
    # memfd is a candidate REGARDLESS of private/shared. 4e's T4 mapped its payload
    # MAP_SHARED (perms r-xs), and an earlier cut required `private` first and so
    # SKIPPED it -- silently excluding the exact memfd-evasion case this pass exists to
    # look inside. Caught 2026-08-22 because the synthetic T4 victim produced no feature.
    if is_memfd:
        return True
    # anonymous is a candidate only when private -- a shared anonymous executable mapping
    # is unusual and not the injection shape we are chasing here.
    if backing == "anonymous" and region.get("private", True):
        return True
    return False


def header_match(data: bytes):
    """Return 'pe' / 'elf' if `data` begins with an executable-image magic, else None."""
    for magic, name in _MAGICS:
        if data[:len(magic)] == magic:
            return name
    return None


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of `data` in bits/byte, 0.0 for empty. A NOP sled or zero-fill is
    near 0; compiled code sits mid-range; packed/encrypted content approaches 8.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def compute_features(data: bytes) -> dict:
    """Turn a region prefix into the TWO derived features, then let the bytes go.

    Returns {"header": 'pe'|'elf'|None, "entropy": float, "prefix_len": int}. The input
    `data` is not stored anywhere; the caller is responsible for not retaining it either.
    Never raises on any byte content.
    """
    if not isinstance(data, (bytes, bytearray)):
        return {"header": None, "entropy": 0.0, "prefix_len": 0, "read": "no-data"}
    data = bytes(data[:PREFIX_BYTES])
    return {"header": header_match(data),
            "entropy": round(shannon_entropy(data), 4),
            "prefix_len": len(data)}
