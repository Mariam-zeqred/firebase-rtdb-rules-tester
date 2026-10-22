"""Differential test: official Firebase emulator vs interpreter vs expectation.

Skipped unless the firebase CLI (or FIREBASE_CLI=/path/to/firebase) and Java are
available. Run with ``make emulator``.
"""

import json
import shutil
from pathlib import Path

import pytest

from rtdb_rules.cli import decide
from rtdb_rules.emulator import Emulator, EmulatorUnavailable, find_firebase
from rtdb_rules.interpreter import Rules
from rtdb_rules.scenarios import load_scenarios, load_seed

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    find_firebase() is None or shutil.which("java") is None,
    reason="firebase CLI or java not available",
)


@pytest.fixture(scope="module")
def emulator():
    try:
        with Emulator() as emu:
            yield emu
    except EmulatorUnavailable as e:
        pytest.skip(str(e))


@pytest.mark.parametrize("rules_file", ["database.rules.json", "rules/open.rules.json"])
def test_emulator_agrees_with_interpreter(emulator, rules_file):
    rules_json = json.loads((ROOT / rules_file).read_text())
    emulator.set_rules(rules_json)
    rules = Rules(rules_json)
    seed = load_seed(ROOT / "scenarios")
    disagreements = []
    for s in load_scenarios(ROOT / "scenarios"):
        emu = emulator.run(s, seed)
        interp = decide(rules, s, seed).allowed
        if emu != interp:
            disagreements.append((s.name, emu, interp))
        if rules_file == "database.rules.json" and emu != s.expect:
            disagreements.append((s.name, emu, f"expected {s.expect}"))
    assert disagreements == []
