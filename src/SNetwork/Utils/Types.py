from __future__ import annotations
from typing import Optional as _Optional

type Bool = bool
type Bytes = bytes
type Dict[K, V] = dict[K, V]
type Float = float
type Int = int
type List[T] = list[T]
type Optional[T] = _Optional[T]
type Set[T] = set[T]
type Str = str
type Tuple[*Ts] = tuple[Ts]
type Type[T] = type[T]
type Json = Dict[Str, Str | Int | Bool | List[Json] | Json]


__all__ = ["Bool", "Bytes", "Dict", "Float", "Int", "List", "Optional", "Set", "Str", "Tuple", "Type", "Json"]
