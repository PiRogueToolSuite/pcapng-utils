"""cf. https://docs.python.org/3.11/library/bisect.html#searching-sorted-lists"""

from typing import TypeVar, Any

from sortedcontainers import SortedKeyList

_KT = TypeVar('_KT', bound=float)


def get_le(lst: SortedKeyList, key: _KT) -> tuple[int, _KT, Any] | None:
    """Find rightmost element whose key is less than or equal to key"""
    ix: int = lst.bisect_key_right(key) - 1
    if ix == -1:
        return None
    e = lst[ix]
    return ix, lst.key(e), e


def get_gt(lst: SortedKeyList, key: _KT) -> tuple[int, _KT, Any] | None:
    """Find leftmost element whose key is greater than key"""
    ix: int = lst.bisect_key_right(key)
    if ix == len(lst):
        return None
    e = lst[ix]
    return ix, lst.key(e), e


def get_closest_in_window(lst: SortedKeyList, key: _KT, rel_window: tuple[_KT, _KT]) -> tuple[int, _KT, Any] | None:
    """Find element with closest key in provided relative window of keys (inclusive)"""
    lb_ix, lb_key, lb_elt = get_le(lst, key) or (None, None, None)
    ub_ix, ub_key, ub_elt = get_gt(lst, key) or (None, None, None)
    lb_delta_key, ub_delta_key = None, None
    if lb_key is not None:
        lb_delta_key = key - lb_key  # >= 0
        if lb_delta_key > -rel_window[0]:
            lb_delta_key = None
    if ub_key is not None:
        ub_delta_key = ub_key - key  # > 0
        if ub_delta_key > rel_window[1]:
            ub_delta_key = None
    if lb_delta_key is None:
        if ub_delta_key is None:
            return None
        assert ub_ix is not None and ub_key is not None  # for typing
        return ub_ix, ub_key, ub_elt
    assert lb_ix is not None and lb_key is not None  # for typing
    if ub_delta_key is None:
        return lb_ix, lb_key, lb_elt
    assert ub_ix is not None and ub_key is not None  # for typing
    if lb_delta_key <= ub_delta_key:
        return lb_ix, lb_key, lb_elt
    return ub_ix, ub_key, ub_elt
