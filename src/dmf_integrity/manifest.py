"""Document version manifest: module leaves -> manifest root -> version hash chain.

Hash hierarchy (DMF rules H-3..H-5):

    content bytes ──sha256──► content_sha256            (CAS key in object storage)
    ModuleRef (JCS) ──leaf──► module leaf                (one per section/module)
    leaves ordered by ordinal ──RFC6962──► manifest_root (identifies the *content* state)
    IMMUTABLE_CORE leaves by id ──RFC6962──► restrict_seal (must never change w/o amendment)
    {doc, version_no, parent_version_hash, manifest_root, seal, metadata}
          ──sha256──► version_hash                       (hash chain per document)

manifest_root is content identity: a rollback re-creates an old manifest_root.
version_hash is history identity: a rollback still produces a *new* version_hash
because parent_version_hash differs. This is what makes rollback auditable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence

from .canonical import canonicalize
from .merkle import inclusion_proof, leaf_hash, merkle_root

GENESIS_HASH = "0" * 64


class Mutability(str, Enum):
    MUTABLE = "MUTABLE"                 # editable under normal ticket approval
    RESTRICTED = "RESTRICTED"           # editable, but escalates risk level (R2+)
    IMMUTABLE_CORE = "IMMUTABLE_CORE"   # covered by restrict_seal; CORE_AMENDMENT only


@dataclass(frozen=True)
class ModuleRef:
    module_id: str
    kind: str                      # e.g. "section", "table", "rule", "appendix"
    mutability: Mutability
    ordinal: int
    content_sha256: str            # hex sha256 of the stored content bytes
    depends_on: tuple[str, ...] = field(default_factory=tuple)

    def payload(self) -> dict:
        return {
            "t": "dmf.module/v1",
            "module_id": self.module_id,
            "kind": self.kind,
            "mutability": self.mutability.value,
            "ordinal": self.ordinal,
            "content_sha256": self.content_sha256,
            "depends_on": sorted(self.depends_on),
        }

    def leaf(self) -> bytes:
        return leaf_hash(canonicalize(self.payload()))

    def seal_leaf(self) -> bytes:
        # ordinal excluded: reordering mutable sections must not break the seal.
        return leaf_hash(canonicalize({
            "t": "dmf.seal/v1",
            "module_id": self.module_id,
            "kind": self.kind,
            "content_sha256": self.content_sha256,
        }))


def content_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordered(modules: Iterable[ModuleRef]) -> list[ModuleRef]:
    ms = sorted(modules, key=lambda m: m.ordinal)
    ids = [m.module_id for m in ms]
    ords = [m.ordinal for m in ms]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate module_id in manifest")
    if len(set(ords)) != len(ords):
        raise ValueError("duplicate ordinal in manifest")
    return ms


def manifest_root(modules: Iterable[ModuleRef]) -> str:
    return merkle_root([m.leaf() for m in _ordered(modules)]).hex()


def module_proof(modules: Iterable[ModuleRef], module_id: str) -> tuple[int, int, list[str]]:
    """(index, tree_size, audit_path) proving one module belongs to a manifest root."""
    ms = _ordered(modules)
    idx = next(i for i, m in enumerate(ms) if m.module_id == module_id)
    return idx, len(ms), [h.hex() for h in inclusion_proof([m.leaf() for m in ms], idx)]


def restrict_seal(modules: Iterable[ModuleRef]) -> str:
    core = sorted(
        (m for m in modules if m.mutability is Mutability.IMMUTABLE_CORE),
        key=lambda m: m.module_id,
    )
    return merkle_root([m.seal_leaf() for m in core]).hex()


def version_hash(
    *,
    document_id: str,
    version_no: int,
    parent_version_hash: str | None,
    manifest_root_hex: str,
    restrict_seal_hex: str,
    metadata: Mapping,
) -> str:
    body = {
        "t": "dmf.version/v1",
        "document_id": document_id,
        "version_no": version_no,
        "parent_version_hash": parent_version_hash or GENESIS_HASH,
        "manifest_root": manifest_root_hex,
        "restrict_seal": restrict_seal_hex,
        "metadata": dict(metadata),   # Dublin Core terms, JCS-canonicalized
    }
    return hashlib.sha256(canonicalize(body)).hexdigest()


@dataclass(frozen=True)
class VersionRecord:
    document_id: str
    version_no: int
    parent_version_hash: str | None
    modules: tuple[ModuleRef, ...]
    metadata: Mapping
    manifest_root: str
    restrict_seal: str
    version_hash: str


def build_version(
    document_id: str,
    version_no: int,
    parent: VersionRecord | None,
    modules: Sequence[ModuleRef],
    metadata: Mapping,
) -> VersionRecord:
    mr = manifest_root(modules)
    seal = restrict_seal(modules)
    vh = version_hash(
        document_id=document_id,
        version_no=version_no,
        parent_version_hash=parent.version_hash if parent else None,
        manifest_root_hex=mr,
        restrict_seal_hex=seal,
        metadata=metadata,
    )
    return VersionRecord(document_id, version_no, parent.version_hash if parent else None,
                         tuple(modules), metadata, mr, seal, vh)


def verify_version_chain(versions: Sequence[VersionRecord]) -> None:
    """Recompute every hash and link; raise on the first inconsistency."""
    prev: VersionRecord | None = None
    for v in versions:
        expected_parent = prev.version_hash if prev else None
        if v.parent_version_hash != expected_parent:
            raise ValueError(f"v{v.version_no}: broken parent link")
        rebuilt = build_version(v.document_id, v.version_no, prev, v.modules, v.metadata)
        if rebuilt.version_hash != v.version_hash:
            raise ValueError(f"v{v.version_no}: version_hash mismatch (tampered)")
        prev = v
