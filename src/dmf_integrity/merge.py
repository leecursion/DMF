"""Module-level three-way merge (atomic decomposition -> recombination).

Because a document is a set of content-addressed modules, concurrent tickets that touch
*different* modules merge automatically; only same-module edits produce conflicts, which
become a CONFLICT_RESOLUTION ticket instead of a silent overwrite.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .manifest import ModuleRef


@dataclass(frozen=True)
class MergeConflict:
    module_id: str
    base: ModuleRef | None
    ours: ModuleRef | None
    theirs: ModuleRef | None


@dataclass(frozen=True)
class MergeResult:
    modules: tuple[ModuleRef, ...]
    conflicts: tuple[MergeConflict, ...]

    @property
    def clean(self) -> bool:
        return not self.conflicts


def three_way_merge(
    base: Sequence[ModuleRef], ours: Sequence[ModuleRef], theirs: Sequence[ModuleRef]
) -> MergeResult:
    b = {m.module_id: m for m in base}
    o = {m.module_id: m for m in ours}
    t = {m.module_id: m for m in theirs}
    merged: dict[str, ModuleRef] = {}
    conflicts: list[MergeConflict] = []

    for mid in sorted(b.keys() | o.keys() | t.keys()):
        bm, om, tm = b.get(mid), o.get(mid), t.get(mid)
        if om == tm:
            pick = om
        elif om == bm:
            pick = tm
        elif tm == bm:
            pick = om
        else:
            conflicts.append(MergeConflict(mid, bm, om, tm))
            continue
        if pick is not None:
            merged[mid] = pick

    # Ordinal collisions (both sides inserted at the same position) are conflicts too.
    seen: dict[int, str] = {}
    for mid, m in merged.items():
        if m.ordinal in seen:
            conflicts.append(MergeConflict(mid, b.get(mid), o.get(mid), t.get(mid)))
        else:
            seen[m.ordinal] = mid

    return MergeResult(tuple(sorted(merged.values(), key=lambda m: m.ordinal)), tuple(conflicts))
