"""Cascading evaluation of ``.read`` / ``.write`` / ``.validate`` rules.

Semantics implemented (see README "What the interpreter covers"):

* A read of ``P`` is allowed when a ``.read`` rule at ``P`` or any ancestor
  evaluates to ``true``. Rules below ``P`` are not consulted.
* A write to ``P`` is allowed when a ``.write`` rule at ``P`` or any ancestor
  is ``true``, **and** every ``.validate`` rule on the path root → ``P`` and in
  the written subtree passes. ``.validate`` is skipped where the new data is
  null, so deletes are not validated. ``data`` / ``newData`` always refer to
  the node the rule sits on; ``root`` is the pre-write root.
* Along a path a literal key wins over a ``$variable`` key; the variable is
  bound to the actual segment for the rest of the walk.
* A multi-location ``update`` is one independent write per child path; all
  must pass.
* An expression that errors (for example ``auth.uid`` when ``auth`` is null)
  counts as ``false`` and the error is recorded in the trace.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from rtdb_rules.expr import RulesError, evaluate, parse
from rtdb_rules.snapshot import Snapshot, normalize, set_at, split_path

RULE_KEYS = (".read", ".write", ".validate", ".indexOn")


@dataclass
class Decision:
    allowed: bool
    reason: str
    trace: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.allowed


class _Node:
    """One node of the rules tree with its expressions pre-parsed."""

    def __init__(self, raw: dict[str, Any], where: str) -> None:
        if not isinstance(raw, dict):
            raise RulesError(f"rules node at {where} must be an object")
        self.where = where
        self.exprs: dict[str, tuple] = {}
        for key in (".read", ".write", ".validate"):
            if key in raw:
                src = raw[key]
                if isinstance(src, bool):
                    src = "true" if src else "false"
                if not isinstance(src, str):
                    raise RulesError(f"{where}{key} must be a string or boolean")
                try:
                    self.exprs[key] = parse(src)
                except RulesError as e:
                    raise RulesError(f"{where}{key}: {e}") from None
        self.children: dict[str, _Node] = {}
        self.wildcard: tuple[str, _Node] | None = None
        for key, sub in raw.items():
            if key in RULE_KEYS:
                continue
            child = _Node(sub, f"{where}/{key}")
            if key.startswith("$"):
                if self.wildcard is not None:
                    raise RulesError(f"{where} has two $variables")
                self.wildcard = (key, child)
            else:
                self.children[key] = child

    def step(self, segment: str) -> tuple[_Node | None, str | None]:
        if segment in self.children:
            return self.children[segment], None
        if self.wildcard is not None:
            return self.wildcard[1], self.wildcard[0]
        return None, None


class Rules:
    """The parsed ``rules.json``. ``data`` is the current database content."""

    def __init__(self, rules_json: dict[str, Any]) -> None:
        if "rules" not in rules_json:
            raise RulesError("rules file must have a top-level 'rules' key")
        self.root = _Node(rules_json["rules"], "")

    # -- helpers ------------------------------------------------------------
    def _walk(self, segments: list[str]) -> list[tuple[_Node, dict[str, str], list[str]]]:
        """Nodes along root → target with the $variables bound so far."""
        node: _Node | None = self.root
        bound: dict[str, str] = {}
        out = [(self.root, {}, [])]
        for i, seg in enumerate(segments):
            node, var = node.step(seg)
            if node is None:
                break
            if var:
                bound = {**bound, var: seg}
            out.append((node, bound, segments[: i + 1]))
        return out

    @staticmethod
    def _eval(node: _Node, key: str, env: dict[str, Any], trace: list[str]) -> bool:
        where = node.where or "/"
        try:
            result = evaluate(node.exprs[key], env)
            if not isinstance(result, bool):
                raise RulesError(f"rule returned {type(result).__name__}, not boolean")
        except RulesError as e:
            trace.append(f"{where} {key}: error → false ({e})")
            return False
        trace.append(f"{where} {key}: {'true' if result else 'false'}")
        return result

    @staticmethod
    def _env(
        auth: dict[str, Any] | None,
        data: Snapshot,
        new: Snapshot | None,
        root: Snapshot,
        now: int,
        bound: dict[str, str],
    ) -> dict[str, Any]:
        env: dict[str, Any] = {"auth": auth, "data": data, "root": root, "now": now, **bound}
        if new is not None:
            env["newData"] = new
        return env

    # -- public API ---------------------------------------------------------
    def can_read(self, path: str, auth: dict[str, Any] | None, data: Any, now: int | None = None) -> Decision:
        now = now if now is not None else int(time.time() * 1000)
        data = normalize(data)
        root = Snapshot(data)
        trace: list[str] = []
        for node, bound, prefix in self._walk(split_path(path)):
            if ".read" in node.exprs:
                env = self._env(auth, Snapshot(data, prefix), None, root, now, bound)
                if self._eval(node, ".read", env, trace):
                    return Decision(True, f"granted by .read at {node.where or '/'}", trace)
        return Decision(False, "no .read rule granted access", trace)

    def can_write(
        self,
        path: str,
        value: Any,
        auth: dict[str, Any] | None,
        data: Any,
        now: int | None = None,
    ) -> Decision:
        now = now if now is not None else int(time.time() * 1000)
        data = normalize(data)
        segments = split_path(path)
        new_tree = set_at(data, segments, value)
        root = Snapshot(data)
        trace: list[str] = []
        chain = self._walk(segments)
        granted_at = None
        for node, bound, prefix in chain:
            if ".write" in node.exprs:
                env = self._env(auth, Snapshot(data, prefix), Snapshot(new_tree, prefix), root, now, bound)
                if self._eval(node, ".write", env, trace):
                    granted_at = node.where or "/"
                    break
        if granted_at is None:
            return Decision(False, "no .write rule granted access", trace)

        # .validate on the path root → P (merged data), then in the written subtree.
        checks = [(node, bound, prefix) for node, bound, prefix in chain]
        if len(chain) == len(segments) + 1:  # rules reach the target node
            last_node, last_bound, _ = chain[-1]
            checks += self._subtree(last_node, last_bound, segments, new_tree)
        for node, bound, prefix in checks:
            if ".validate" not in node.exprs:
                continue
            new = Snapshot(new_tree, prefix)
            if not new.exists():
                trace.append(f"{node.where or '/'} .validate: skipped (new data is null)")
                continue
            env = self._env(auth, Snapshot(data, prefix), new, root, now, bound)
            if not self._eval(node, ".validate", env, trace):
                return Decision(False, f"failed .validate at {node.where or '/'}", trace)
        return Decision(True, f"granted by .write at {granted_at}", trace)

    def _subtree(
        self, node: _Node, bound: dict[str, str], prefix: list[str], new_tree: Any
    ) -> list[tuple[_Node, dict[str, str], list[str]]]:
        """Rule nodes under ``node`` that match the written data's children."""
        value = Snapshot(new_tree, prefix).val()
        out: list[tuple[_Node, dict[str, str], list[str]]] = []
        if not isinstance(value, dict):
            return out
        for key in value:
            child, var = node.step(key)
            if child is None:
                continue
            child_bound = {**bound, var: key} if var else bound
            child_prefix = prefix + [key]
            out.append((child, child_bound, child_prefix))
            out += self._subtree(child, child_bound, child_prefix, new_tree)
        return out

    def can_update(
        self,
        path: str,
        values: dict[str, Any],
        auth: dict[str, Any] | None,
        data: Any,
        now: int | None = None,
    ) -> Decision:
        """Multi-location update: every child path is its own write."""
        trace: list[str] = []
        for child_path, value in values.items():
            full = "/" + "/".join(split_path(path) + split_path(child_path))
            d = self.can_write(full, value, auth, data, now)
            trace += [f"{full}: {line}" for line in d.trace]
            if not d.allowed:
                return Decision(False, f"{full}: {d.reason}", trace)
        return Decision(True, f"all {len(values)} paths granted", trace)
