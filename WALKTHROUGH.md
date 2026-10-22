# Walkthrough (for Mariam)

## Why it is designed this way

Both of your production apps talk to a Realtime Database that accepts any read or write from anyone
who has the URL. Rules fix that, but they are easy to get subtly wrong, and the Firebase console tests
one request at a time by hand. This repo turns "does my ruleset do what I think?" into a file of
scenarios and a `make check`, re-run in seconds after every change. The official emulator is the ground truth, but it needs Node, Java and a download, so
there is also a small interpreter of the subset of the rules language that real projects use. Both run
the same scenario files, and `tests/test_emulator.py` checks that they agree.

The ruleset follows one idea: **a device may only touch its own node, and only in the shape the apps
expect**. Identity is a custom token with two claims, `device: true` and `deviceId`. Ownership lives at
`/devices/<id>/owners/<uid>`, written only by a server, and app-side rules look it up with
`root.child(...)`. No `.read` or `.write` at the root means everything not listed is denied.

## File map

- `database.rules.json` is the deliverable: the hardened ruleset. `rules/open.rules.json` is the
  pattern it replaces.
- `scenarios/seed.json` is the database before each scenario; `scenarios/01_device.json`,
  `02_app.json`, `03_anonymous.json` hold the 39 cases with a `why` line each.
- `src/rtdb_rules/expr.py` tokenises, parses and evaluates one rule expression. `snapshot.py` is
  `data`/`newData`/`root`. `interpreter.py` walks the rules tree along a path and applies the cascade
  rules (read: any ancestor grants; write: any ancestor grants, then every `.validate` must pass).
- `src/rtdb_rules/emulator.py` starts the emulator, pushes rules and seed with the `owner` token, and
  sends each scenario as one REST call with an unsigned JWT.
- `src/rtdb_rules/cli.py` prints the table; `tests/` covers the language, the cascade semantics, the
  shipped scenarios and the emulator comparison.

## Three questions a professor may ask

**1. Why can a device not revoke a write that a parent rule granted, and does your tester model that?**
Because Firebase rules cascade downwards: a `.write: true` at `/a` covers all of `/a/**`, and deeper
rules are not consulted for permission. That is why the hardened file has no root rules and grants
writes at the deepest sensible node. The interpreter does the same (`test_write_cannot_be_granted_by_a_child_rule`);
only `.validate` applies below the granting node.

**2. Your `hasChildren(['ts','temp','hum','heater'])` rule sits on `status`. Does a single-field update
like `/status/heater = true` fail it?** No, and the scenario "device updates one field of its status"
checks that on both backends. `.validate` on an ancestor is evaluated against the *merged* `newData`,
so if the status already exists, the other fields are present. On a fresh device the same partial write
is denied ("device writes a partial status to a fresh node").

**3. Rules cannot stop a compromised device from lying. What do they buy you?** Containment and schema.
A stolen token for `hive-1C5A00` cannot touch any other device, change its own setpoint, rewrite or
delete history, or store a string where the app expects a number.
The animals' safety still rests on the firmware's local limits.

## One thing you could extend

Add a `.validate` on `history/$ts` that ties the key to the body: `$ts === newData.child('ts').val()`
does not work because `$ts` is a string and `ts` a number, and the rules language has no number-to-string
conversion. Find a layout that keeps key and body consistent (store `ts` as a string, or drop it from the body),
write the scenario first, then change the rule and check that both backends agree.
