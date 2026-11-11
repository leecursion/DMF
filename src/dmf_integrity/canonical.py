"""Canonical JSON serialization (RFC 8785 JCS subset) used for every hashed payload.

DMF rule H-1: "Hash bytes, never objects." Every structured payload is turned into
bytes by this module before it is hashed, so two implementations (Python service,
TS client, offline auditor) produce identical digests.

Deliberate restrictions versus full JCS (simpler and safer for audit data):
  * floats are rejected -> use integers (minor units) or decimal strings
  * integers must fit in IEEE-754 safe range (|n| <= 2^53 - 1)
  * object keys must be strings
"""

from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    pass


def canonicalize(obj: Any) -> bytes:
    return _encode(obj).encode("utf-8")


def _encode(o: Any) -> str:
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        if abs(o) > MAX_SAFE_INT:
            raise CanonicalizationError(f"integer out of safe range: {o}")
        return str(o)
    if isinstance(o, float):
        raise CanonicalizationError("floats are forbidden in hashed payloads")
    if isinstance(o, str):
        # Python escapes exactly as JCS requires: \b \f \n \r \t \" \\ short forms,
        # other control chars as lowercase \u00xx, everything else literal UTF-8.
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in o) + "]"
    if isinstance(o, dict):
        for k in o:
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string key: {k!r}")
        # JCS orders keys by UTF-16 code units.
        keys = sorted(o, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_encode(k) + ":" + _encode(o[k]) for k in keys) + "}"
    raise CanonicalizationError(f"unsupported type: {type(o).__name__}")
