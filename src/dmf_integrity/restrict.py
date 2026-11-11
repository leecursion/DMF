"""Restrict stage: validates a candidate manifest against its base before commit.

Runs (1) in the service before writing, and (2) its seal comparison is re-enforced by
a DB trigger (see schema/postgres/001_core.sql: trg_version_restrict_seal).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .manifest import ModuleRef, Mutability, restrict_seal


@dataclass(frozen=True)
class Violation:
    code: str
    module_id: str
    detail: str


def check_restrictions(
    base: Sequence[ModuleRef],
    candidate: Sequence[ModuleRef],
    *,
    allow_core_amendment: bool = False,
) -> list[Violation]:
    out: list[Violation] = []
    b = {m.module_id: m for m in base}
    c = {m.module_id: m for m in candidate}

    # R-1 immutable core: no add/remove/modify, and no downgrade of mutability.
    if not allow_core_amendment:
        for mid, bm in b.items():
            if bm.mutability is Mutability.IMMUTABLE_CORE:
                cm = c.get(mid)
                if cm is None:
                    out.append(Violation("CORE_REMOVED", mid, "immutable core module removed"))
                elif cm.mutability is not Mutability.IMMUTABLE_CORE:
                    out.append(Violation("CORE_DOWNGRADED", mid, "mutability downgraded"))
                elif cm.content_sha256 != bm.content_sha256 or cm.kind != bm.kind:
                    out.append(Violation("CORE_MODIFIED", mid, "immutable core content changed"))
        for mid, cm in c.items():
            if cm.mutability is Mutability.IMMUTABLE_CORE and (
                mid not in b or b[mid].mutability is not Mutability.IMMUTABLE_CORE
            ):
                out.append(Violation("CORE_ADDED", mid, "new core module requires amendment"))
        if not out and restrict_seal(base) != restrict_seal(candidate):
            out.append(Violation("SEAL_MISMATCH", "*", "restrict seal changed"))

    # R-2 dependency closure: every depends_on must resolve inside the candidate.
    for mid, cm in c.items():
        for dep in cm.depends_on:
            if dep not in c:
                out.append(Violation("DANGLING_DEPENDENCY", mid, f"depends on missing {dep}"))

    # R-3 dependency must not be cyclic.
    out.extend(_cycles(c))
    return out


def _cycles(mods: dict[str, ModuleRef]) -> list[Violation]:
    WHITE, GREY, BLACK = 0, 1, 2
    color = {k: WHITE for k in mods}
    found: list[Violation] = []

    def visit(k: str) -> None:
        color[k] = GREY
        for d in mods[k].depends_on:
            if d not in mods:
                continue
            if color[d] == GREY:
                found.append(Violation("DEPENDENCY_CYCLE", k, f"cycle via {d}"))
            elif color[d] == WHITE:
                visit(d)
        color[k] = BLACK

    for k in mods:
        if color[k] == WHITE:
            visit(k)
    return found


def risk_floor(base: Sequence[ModuleRef], candidate: Sequence[ModuleRef]) -> int:
    """Minimum risk level implied by which mutability classes were touched (0..3)."""
    b = {m.module_id: m for m in base}
    c = {m.module_id: m for m in candidate}
    touched = {k for k in b.keys() | c.keys() if b.get(k) != c.get(k)}
    level = 0 if not touched else 1
    for k in touched:
        mut = (c.get(k) or b[k]).mutability
        prev_mut = b[k].mutability if k in b else mut
        if Mutability.IMMUTABLE_CORE in (mut, prev_mut):
            return 3
        if Mutability.RESTRICTED in (mut, prev_mut):
            level = max(level, 2)
    return level
