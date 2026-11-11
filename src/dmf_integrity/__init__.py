"""DMF integrity primitives: canonical JSON, Merkle trees, version/audit hash chains."""

from .canonical import canonicalize
from .manifest import (
    ModuleRef, Mutability, VersionRecord, build_version, content_sha256,
    manifest_root, module_proof, restrict_seal, verify_version_chain,
)
from .merge import three_way_merge
from .restrict import check_restrictions, risk_floor
from .audit_chain import AuditChain, verify_chain, make_checkpoint, verify_checkpoint

__all__ = [
    "canonicalize", "ModuleRef", "Mutability", "VersionRecord", "build_version",
    "content_sha256", "manifest_root", "module_proof", "restrict_seal",
    "verify_version_chain", "three_way_merge", "check_restrictions", "risk_floor",
    "AuditChain", "verify_chain", "make_checkpoint", "verify_checkpoint",
]
