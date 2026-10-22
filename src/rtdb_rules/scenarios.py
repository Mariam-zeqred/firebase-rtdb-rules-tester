"""Scenario files: one JSON list per file, evaluated against one seed."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OPS = ("read", "write", "update")


@dataclass(frozen=True)
class Auth:
    """What ``auth`` looks like inside a rule for this caller."""

    uid: str
    token: dict[str, Any] = field(default_factory=dict)
    provider: str = "custom"

    def as_rule_object(self) -> dict[str, Any]:
        token = {"sub": self.uid, "user_id": self.uid, **self.token}
        return {"uid": self.uid, "provider": self.provider, "token": token}


@dataclass(frozen=True)
class Scenario:
    name: str
    op: str
    path: str
    expect: bool  # True = allow
    auth: Auth | None
    value: Any = None  # write: the new value (None deletes)
    values: dict[str, Any] | None = None  # update: child path -> value
    why: str = ""
    now: int | None = None  # ms epoch pinned for the interpreter only
    source: str = ""

    @staticmethod
    def from_dict(raw: dict[str, Any], source: str = "") -> Scenario:
        missing = [k for k in ("name", "op", "path", "expect") if k not in raw]
        if missing:
            raise ValueError(f"{source}: scenario is missing {missing}")
        if raw["op"] not in OPS:
            raise ValueError(f"{source}: op must be one of {OPS}")
        if raw["expect"] not in ("allow", "deny"):
            raise ValueError(f"{source}: expect must be 'allow' or 'deny'")
        if raw["op"] == "write" and "value" not in raw:
            raise ValueError(f"{source}: a write needs 'value' (null to delete)")
        if raw["op"] == "update" and not isinstance(raw.get("values"), dict):
            raise ValueError(f"{source}: an update needs a 'values' object")
        auth_raw = raw.get("auth")
        auth = None
        if auth_raw is not None:
            auth = Auth(auth_raw["uid"], dict(auth_raw.get("token", {})), auth_raw.get("provider", "custom"))
        return Scenario(
            name=raw["name"],
            op=raw["op"],
            path=raw["path"],
            expect=raw["expect"] == "allow",
            auth=auth,
            value=raw.get("value"),
            values=raw.get("values"),
            why=raw.get("why", ""),
            now=raw.get("now"),
            source=source,
        )


def load_scenarios(folder: str | Path) -> list[Scenario]:
    folder = Path(folder)
    out: list[Scenario] = []
    for file in sorted(folder.glob("*.json")):
        if file.name == "seed.json":
            continue
        items = json.loads(file.read_text())
        if not isinstance(items, list):
            raise ValueError(f"{file}: expected a JSON list of scenarios")
        out += [Scenario.from_dict(item, f"{file.name}#{i}") for i, item in enumerate(items)]
    names = [s.name for s in out]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ValueError(f"duplicate scenario names: {sorted(dupes)}")
    return out


def load_seed(folder: str | Path) -> Any:
    seed = Path(folder) / "seed.json"
    return json.loads(seed.read_text()) if seed.exists() else None


def load_rules_file(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())
