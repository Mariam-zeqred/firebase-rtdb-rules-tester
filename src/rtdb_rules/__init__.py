"""Host-side tester for Firebase Realtime Database security rules.

Two backends evaluate the same scenario files against the same ``rules.json``:

* :mod:`rtdb_rules.interpreter` - a small interpreter for the common
  ``.read`` / ``.write`` / ``.validate`` / ``$variable`` subset, runs anywhere.
* :mod:`rtdb_rules.emulator` - the official Firebase Database emulator over
  REST, used when ``firebase-tools`` and Java are installed.
"""

from rtdb_rules.interpreter import Decision, Rules, RulesError
from rtdb_rules.scenarios import Auth, Scenario, load_scenarios, load_seed

__all__ = [
    "Auth",
    "Decision",
    "Rules",
    "RulesError",
    "Scenario",
    "load_scenarios",
    "load_seed",
]
