"""The shipped ruleset against the shipped scenarios, with the interpreter."""

import json
from pathlib import Path

import pytest

from rtdb_rules.cli import decide, main
from rtdb_rules.interpreter import Rules
from rtdb_rules.scenarios import Scenario, load_scenarios, load_seed

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = load_scenarios(ROOT / "scenarios")
SEED = load_seed(ROOT / "scenarios")
HARDENED = Rules(json.loads((ROOT / "database.rules.json").read_text()))
OPEN = Rules(json.loads((ROOT / "rules" / "open.rules.json").read_text()))


def test_scenario_set_is_meaningful():
    assert len(SCENARIOS) >= 30
    assert {s.op for s in SCENARIOS} == {"read", "write", "update"}
    assert sum(s.expect for s in SCENARIOS) >= 10 and sum(not s.expect for s in SCENARIOS) >= 20
    assert any(s.auth is None for s in SCENARIOS)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_hardened_rules_match_expectation(scenario):
    d = decide(HARDENED, scenario, SEED)
    assert d.allowed == scenario.expect, f"{scenario.name}: {d.reason}\n" + "\n".join(d.trace)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_open_rules_allow_everything(scenario):
    """The weakness being fixed: with {.read: true, .write: true} every scenario is allowed."""
    assert decide(OPEN, scenario, SEED).allowed


def test_scenario_validation_errors():
    with pytest.raises(ValueError):
        Scenario.from_dict({"name": "x", "op": "write", "path": "/", "expect": "allow"})  # no value
    with pytest.raises(ValueError):
        Scenario.from_dict({"name": "x", "op": "read", "path": "/", "expect": "maybe"})
    with pytest.raises(ValueError):
        Scenario.from_dict({"name": "x", "op": "update", "path": "/", "expect": "allow", "values": 1})


def test_cli_check_passes(capsys):
    assert (
        main(["check", "--rules", str(ROOT / "database.rules.json"), "--scenarios", str(ROOT / "scenarios")])
        == 0
    )
    out = capsys.readouterr().out
    assert f"{len(SCENARIOS)} scenarios, 0 mismatches" in out


def test_cli_reports_mismatch(capsys):
    code = main(
        ["check", "--rules", str(ROOT / "rules" / "open.rules.json"), "--scenarios", str(ROOT / "scenarios")]
    )
    assert code == 1
    assert "MISMATCH" in capsys.readouterr().out
