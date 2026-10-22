"""``python -m rtdb_rules check`` : evaluate every scenario and print a table."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from rtdb_rules.interpreter import Decision, Rules
from rtdb_rules.scenarios import Scenario, load_rules_file, load_scenarios, load_seed


def decide(rules: Rules, s: Scenario, seed: Any) -> Decision:
    auth = s.auth.as_rule_object() if s.auth else None
    if s.op == "read":
        return rules.can_read(s.path, auth, seed, s.now)
    if s.op == "write":
        return rules.can_write(s.path, s.value, auth, seed, s.now)
    return rules.can_update(s.path, s.values or {}, auth, seed, s.now)


def _verdict(allowed: bool) -> str:
    return "allow" if allowed else "deny"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rtdb_rules", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="run scenarios against a rules file")
    chk.add_argument("--rules", default="database.rules.json")
    chk.add_argument("--scenarios", default="scenarios")
    chk.add_argument("--backend", choices=["interpreter", "emulator", "both"], default="interpreter")
    chk.add_argument("--trace", action="store_true", help="print the rule-by-rule trace of every scenario")
    chk.add_argument(
        "--no-expect",
        action="store_true",
        help="do not compare with 'expect' (useful to see what another rules file allows)",
    )
    args = ap.parse_args(argv)

    rules = Rules(load_rules_file(args.rules))
    scenarios = load_scenarios(args.scenarios)
    seed = load_seed(args.scenarios)
    emu_results: dict[str, bool] = {}
    if args.backend in ("emulator", "both"):
        from rtdb_rules.emulator import Emulator, EmulatorUnavailable

        try:
            with Emulator() as emu:
                emu.set_rules(load_rules_file(args.rules))
                for s in scenarios:
                    emu_results[s.name] = emu.run(s, seed)
        except EmulatorUnavailable as e:
            print(f"emulator unavailable: {e}", file=sys.stderr)
            if args.backend == "emulator":
                return 2

    cols = ["scenario", "op", "expect", "interpreter"] + (["emulator"] if emu_results else [])
    width = max(len(s.name) for s in scenarios)
    print(
        f"{cols[0]:<{width}}  {'op':<6} {'expect':<6} {'interp':<6}" + ("  emulator" if emu_results else "")
    )
    failures = 0
    for s in scenarios:
        d = decide(rules, s, seed)
        row = f"{s.name:<{width}}  {s.op:<6} {_verdict(s.expect):<6} {_verdict(d.allowed):<6}"
        bad = not args.no_expect and d.allowed != s.expect
        if emu_results:
            e = emu_results[s.name]
            row += f"  {_verdict(e):<6}"
            bad = bad or e != d.allowed or (not args.no_expect and e != s.expect)
        print(row + ("   <-- MISMATCH" if bad else ""))
        failures += bad
        if args.trace or bad:
            print(f"    {d.reason}")
            for line in d.trace:
                print(f"      {line}")
    print(
        f"\n{len(scenarios)} scenarios, {failures} mismatches"
        + (", emulator compared" if emu_results else ", interpreter only")
    )
    return 1 if failures else 0
