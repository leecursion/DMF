"""Append-only, hash-chained audit log + signed Merkle checkpoints.

DMF rule H-6: one chain per document (chain_id = document id) plus one per tenant for
non-document events. Per-document chains remove the global write hotspot; tamper
evidence across chains comes from periodic checkpoints:

    checkpoint_root = MerkleRoot( leaf(JCS({chain_id, seq, entry_hash})) for each chain head,
                                  sorted by chain_id )

The checkpoint is signed (KMS/HSM Ed25519 in production) and anchored externally
(RFC 3161 timestamp + WORM object storage), so even a DB superuser who rewrites a whole
chain consistently is detected against the last anchored checkpoint.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from .canonical import canonicalize
from .merkle import leaf_hash, merkle_root

GENESIS = "0" * 64
DOMAIN = b"dmf.audit/v1\x00"


@dataclass(frozen=True)
class AuditEntry:
    chain_id: str
    seq: int
    prev_hash: str
    occurred_at: str          # RFC 3339 UTC, e.g. 2026-11-11T01:02:03.456789Z
    actor: str                # agent IRI (prov:Agent)
    action: str               # e.g. ticket.approve, version.commit, release.promote
    target: str               # entity IRI (prov:Entity)
    ticket_id: str | None
    detail: Mapping[str, Any]
    entry_hash: str = ""

    def body(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "ticket_id": self.ticket_id,
            "detail": dict(self.detail),
        }


def compute_entry_hash(entry: AuditEntry) -> str:
    return hashlib.sha256(DOMAIN + canonicalize(entry.body())).hexdigest()


class ChainBrokenError(Exception):
    def __init__(self, seq: int, reason: str):
        super().__init__(f"audit chain broken at seq={seq}: {reason}")
        self.seq = seq
        self.reason = reason


@dataclass
class AuditChain:
    chain_id: str
    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def head(self) -> tuple[int, str]:
        if not self.entries:
            return 0, GENESIS
        last = self.entries[-1]
        return last.seq, last.entry_hash

    def append(self, *, occurred_at: str, actor: str, action: str, target: str,
               ticket_id: str | None = None, detail: Mapping[str, Any] | None = None) -> AuditEntry:
        seq, prev = self.head
        draft = AuditEntry(self.chain_id, seq + 1, prev, occurred_at, actor, action,
                           target, ticket_id, detail or {})
        entry = AuditEntry(**{**draft.__dict__, "entry_hash": compute_entry_hash(draft)})
        self.entries.append(entry)
        return entry


def verify_chain(entries: Sequence[AuditEntry], *, expected_head: tuple[int, str] | None = None) -> None:
    prev, expected_seq = GENESIS, 1
    for e in entries:
        if e.seq != expected_seq:
            raise ChainBrokenError(e.seq, f"gap: expected seq {expected_seq}")
        if e.prev_hash != prev:
            raise ChainBrokenError(e.seq, "prev_hash does not match previous entry")
        if compute_entry_hash(e) != e.entry_hash:
            raise ChainBrokenError(e.seq, "entry_hash mismatch (content tampered)")
        prev, expected_seq = e.entry_hash, expected_seq + 1
    if expected_head is not None and entries:
        if (entries[-1].seq, entries[-1].entry_hash) != expected_head:
            raise ChainBrokenError(entries[-1].seq, "head differs from anchored checkpoint (truncation?)")


# ---------------------------------------------------------------- checkpoints

class Signer(Protocol):
    key_id: str
    def sign(self, message: bytes) -> bytes: ...
    def verify(self, message: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True)
class HmacDevSigner:
    """Development only. Production: KMS/HSM-backed Ed25519 (asymmetric, so auditors
    can verify without being able to forge)."""
    key_id: str
    secret: bytes

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self.secret, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


@dataclass(frozen=True)
class Checkpoint:
    tenant_id: str
    checkpoint_no: int
    prev_checkpoint_root: str
    created_at: str
    heads: tuple[tuple[str, int, str], ...]   # (chain_id, seq, entry_hash), sorted
    root: str
    key_id: str
    signature: str

    def signed_message(self) -> bytes:
        return canonicalize({
            "t": "dmf.checkpoint/v1",
            "tenant_id": self.tenant_id,
            "checkpoint_no": self.checkpoint_no,
            "prev_checkpoint_root": self.prev_checkpoint_root,
            "created_at": self.created_at,
            "root": self.root,
        })


def _heads_root(heads: Sequence[tuple[str, int, str]]) -> str:
    return merkle_root([
        leaf_hash(canonicalize({"chain_id": c, "seq": s, "entry_hash": h})) for c, s, h in heads
    ]).hex()


def make_checkpoint(tenant_id: str, checkpoint_no: int, prev_root: str, created_at: str,
                    chains: Sequence[AuditChain], signer: Signer) -> Checkpoint:
    heads = tuple(sorted((c.chain_id, *c.head) for c in chains if c.entries))
    root = _heads_root(heads)
    unsigned = Checkpoint(tenant_id, checkpoint_no, prev_root, created_at, heads, root,
                          signer.key_id, "")
    sig = signer.sign(unsigned.signed_message()).hex()
    return Checkpoint(**{**unsigned.__dict__, "signature": sig})


def verify_checkpoint(cp: Checkpoint, signer: Signer) -> bool:
    return _heads_root(cp.heads) == cp.root and signer.verify(
        cp.signed_message(), bytes.fromhex(cp.signature))
