"""RFC 6962 / RFC 9162 Merkle tree with domain-separated hashing.

DMF rule H-2: leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right).
The prefix byte prevents second-preimage attacks where an interior node is passed
off as a leaf. Unbalanced trees split at the largest power of two < n (no leaf
duplication, so CVE-2012-2459 style ambiguity cannot occur).
"""

from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return node_hash(merkle_root(leaf_hashes[:k]), merkle_root(leaf_hashes[k:]))


def inclusion_proof(leaf_hashes: Sequence[bytes], index: int) -> list[bytes]:
    """Audit path for leaf `index` (RFC 6962 section 2.1.1), bottom-up."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise IndexError(index)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(leaf_hashes[:k], index) + [merkle_root(leaf_hashes[k:])]
    return inclusion_proof(leaf_hashes[k:], index - k) + [merkle_root(leaf_hashes[:k])]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2 verification algorithm."""
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1 or fn == 0):
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
