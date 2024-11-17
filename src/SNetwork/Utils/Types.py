from __future__ import annotations
from typing import Callable, NoReturn

type Bool = bool
type Bytes = bytes
type Dict[K, V] = dict[K, V]
type Float = float
type Int = int
type List[T] = list[T]
type Set[T] = set[T]
type Str = str
type Tuple[* Ts] = tuple[Ts]
type Type[T] = type[T]
type Json = Dict[Str, Str | Int | Bool | List[Json] | Json]
type Optional[T] = T | None

__all__ = [
    "Bool", "Bytes", "Callable", "Dict", "Float", "Int", "List", "Optional", "Set", "Str", "Tuple", "Type", "Json",
    "NoReturn"
]
