"""Integrity primitives — canonicalization + hash chain ."""

import hashlib
import json
from typing import Any, Iterable, Optional

GENESIS_SEED = "sentinel:genesis"


def _assert_no_floats(obj: Any, path: str = "$") -> None:
    """G1 enforcement: floats are non-canonical (repr drift). Money must be int paise."""
    if isinstance(obj, float):
        raise ValueError(f"float at {path} — chain payloads must be float-free (use int paise)")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_floats(v, f"{path}[{i}]")


def canonicalize(obj: Any) -> bytes:
    """Stable, deterministic serialization (key order, unicode, separators)."""
    _assert_no_floats(obj)
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def genesis_hash() -> str:
    return hashlib.sha256(GENESIS_SEED.encode("utf-8")).hexdigest()


def chain_hash(prev_hash: str, payload: Any) -> str:
    return hashlib.sha256((prev_hash + ":" + canonicalize(payload).decode("utf-8")).encode("utf-8")).hexdigest()


def build_chain(payloads: Iterable[Any]) -> list[tuple[str, str]]:
    """Return [(prev_hash, hash), ...] for an ordered payload sequence."""
    out: list[tuple[str, str]] = []
    prev = genesis_hash()
    for payload in payloads:
        h = chain_hash(prev, payload)
        out.append((prev, h))
        prev = h
    return out


def verify_chain(rows: list[tuple[int, Any, str, str]]) -> tuple[bool, Optional[int]]:
    
    expected_prev = genesis_hash()
    for seq, payload, stored_prev, stored_hash in rows:
        if stored_prev != expected_prev:
            return False, seq
        if chain_hash(stored_prev, payload) != stored_hash:
            return False, seq
        expected_prev = stored_hash
    return True, None
