from __future__ import annotations
from typing import Optional as _Optional
import sys


if sys.version_info < (3, 12):
    Bool = bool
    Bytes = bytes
    Dict = dict
    Float = float
    Int = int
    List = list
    Optional = _Optional
    Set = set
    Str = str
    Tuple = tuple
    Type = type
    Json = Dict
else:
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
