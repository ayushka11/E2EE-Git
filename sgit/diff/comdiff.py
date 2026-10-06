from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Generic, Iterable, Literal, Sequence, TypeVar

from sgit.codec.lines import enc_line

T = TypeVar("T")


@dataclass(frozen=True)
class Op(Generic[T]):
    kind: Literal["insert", "delete"]
    idx: int
    m: T | None = None


def comdiff_line(old: Sequence[bytes], new: Sequence[bytes]) -> list[Op[bytes]]:
    """Return a simple left-to-right diff using the paper's index convention."""
    matcher = SequenceMatcher(None, list(old), list(new), autojunk=False)
    ops: list[Op[bytes]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"delete", "replace"}:
            for _ in range(i2 - i1):
                ops.append(Op("delete", j1))
        if tag in {"insert", "replace"}:
            for offset, value in enumerate(new[j1:j2]):
                ops.append(Op("insert", j1 + offset, value))
    return ops


def apply_ops(seq: Sequence[T], ops: Iterable[Op[T]]) -> list[T]:
    values = list(seq)
    for op in ops:
        if op.kind == "delete":
            if not 0 <= op.idx < len(values):
                raise IndexError(f"delete index out of range: {op.idx}")
            values.pop(op.idx)
        elif op.kind == "insert":
            if op.m is None:
                raise ValueError("insert op requires a payload")
            if not 0 <= op.idx <= len(values):
                raise IndexError(f"insert index out of range: {op.idx}")
            values.insert(op.idx, op.m)
    return values


def encrypt_ops(k: bytes, ops: list[Op[bytes]]) -> list[Op[bytes]]:
    encrypted: list[Op[bytes]] = []
    for op in ops:
        if op.kind == "delete":
            encrypted.append(op)
        else:
            if op.m is None:
                raise ValueError("insert ops must carry a payload")
            encrypted.append(Op("insert", op.idx, enc_line(k, op.m)))
    return encrypted
