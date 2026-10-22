"""A minimal RuleDataSnapshot: a view on a JSON tree at a path."""

from __future__ import annotations

from typing import Any


def split_path(path: str) -> list[str]:
    return [p for p in path.strip("/").split("/") if p]


def normalize(tree: Any) -> Any:
    """Drop nulls and empty objects, as the database does when storing."""
    if isinstance(tree, dict):
        out = {k: normalize(v) for k, v in tree.items()}
        out = {k: v for k, v in out.items() if v is not None}
        return out or None
    return tree


def get_at(tree: Any, segments: list[str]) -> Any:
    for seg in segments:
        if not isinstance(tree, dict) or seg not in tree:
            return None
        tree = tree[seg]
    return tree


def set_at(tree: Any, segments: list[str], value: Any) -> Any:
    """Return a new tree with ``value`` written at ``segments`` (null deletes)."""
    if not segments:
        return normalize(value)
    base = dict(tree) if isinstance(tree, dict) else {}
    base[segments[0]] = set_at(base.get(segments[0]), segments[1:], value)
    return normalize(base)


class Snapshot:
    """``data`` / ``newData`` / ``root`` as seen by a rule expression."""

    def __init__(self, tree: Any, segments: list[str] | None = None) -> None:
        self._tree = tree
        self._segments = segments or []

    def val(self) -> Any:
        return get_at(self._tree, self._segments)

    def exists(self) -> bool:
        return self.val() is not None

    def child(self, path: str) -> Snapshot:
        return Snapshot(self._tree, self._segments + split_path(path))

    def parent(self) -> Snapshot:
        return Snapshot(self._tree, self._segments[:-1])

    def has_child(self, name: str) -> bool:
        return self.child(name).exists()

    def has_children(self) -> bool:
        return isinstance(self.val(), dict)

    @property
    def path(self) -> str:
        return "/" + "/".join(self._segments)
