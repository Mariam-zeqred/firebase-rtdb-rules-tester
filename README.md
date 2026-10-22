# firebase-rtdb-rules-tester

A pytest harness for Firebase Realtime Database security rules. It loads a `rules.json` and a folder of
scenario files ("the device writes its own node", "an anonymous client reads everything", …) and says
allow or deny for each one, either with the official Firebase Database emulator when `firebase-tools`
and Java are installed, or with a small, documented interpreter of the common rules subset that runs
anywhere. The repo ships a hardened ruleset for an IoT fleet layout, 39 scenarios, and tests that prove
the ruleset closes the holes of an open database.

Why it exists: the two production repos this portfolio links to
([queen-bee-incubator](https://github.com/Mariam-zeqred/queen-bee-incubator) and
[smart-poultry-farm](https://github.com/Mariam-zeqred/smart-poultry-farm)) were built with an open
database, `{".read": true, ".write": true}`. Anyone who knows the database URL can read all telemetry,
change a setpoint or delete the data. `rules/open.rules.json` is that ruleset; `database.rules.json`
is the fix. Under the open rules every one of the 39 scenarios is allowed, including
"anonymous deletes everything". Under the hardened rules 11 are allowed and 28 denied, exactly as the
scenario files expect, and the official emulator agrees with the interpreter on all 39 for both files.

## Data path and where the rules sit

```
 ESP32 incubator ──custom token {device, deviceId}──▶ /devices/<id>/status   (write, 15 s)
                                                     /devices/<id>/history/<ts>  (append only)
                                              ◀────  /devices/<id>/control   (read)
 Flutter app ─────Firebase Auth user token──────────▶ /devices/<id>/control, /settings  (write)
                                              ◀────  /devices/<id>/*          (read, owners only)
 Admin SDK (server, bypasses rules) ────────────────▶ /devices/<id>/owners/<uid>: true
                                     ▲
              every request is checked here by database.rules.json
```

How this repo tests those rules:

```
 database.rules.json ─┐          ┌─ interpreter (src/rtdb_rules/interpreter.py)  ─┐
 scenarios/*.json ────┼──▶ check ┤                                                 ├─▶ table + exit code
 scenarios/seed.json ─┘          └─ Firebase emulator over REST (emulator.py)    ─┘
```

## Run it

```bash
pip install -r requirements.txt
make check                  # ruff + 111 pytest tests + the scenario table (interpreter)
python -m rtdb_rules check --trace            # rule-by-rule trace for every scenario
python -m rtdb_rules check --rules rules/open.rules.json --no-expect   # what the old rules allow

# optional, the official emulator (needs Node 18+ and Java 11+):
npm install -g firebase-tools
make emulator               # differential test: emulator vs interpreter vs expectation
```

The emulator test is skipped automatically when the `firebase` CLI or Java is missing. Set
`FIREBASE_CLI=/path/to/firebase` if the CLI is not on `PATH`.

## What the output looks like

```
scenario                                            op     expect interp  emulator
device writes its own status                        write  allow  allow   allow
device writes another device's status               write  deny   deny    deny
device updates one field of its status              write  allow  allow   allow
device overwrites an existing history entry         write  deny   deny    deny
owner sets the target temperature                   write  allow  allow   allow
owner sets a dangerous target temperature           write  deny   deny    deny
anonymous deletes everything                        write  deny   deny    deny
...
39 scenarios, 0 mismatches, emulator compared
```

With `--trace` each row shows which rule decided:

```
device writes a status with an unknown field        write  deny   deny
    failed .validate at /devices/$deviceId/status/$other
      /devices/$deviceId/status .write: true
      /devices/$deviceId/status .validate: true
      /devices/$deviceId/status/ts .validate: true
      ...
      /devices/$deviceId/status/$other .validate: false
```

## The hardened ruleset (`database.rules.json`)

| Path | Who may write | Who may read | Checks |
|---|---|---|---|
| `/devices/$id/status` | the device whose token carries `device: true` and `deviceId == $id` | device itself, owners | required fields `ts temp hum heater`; numeric ranges; `ts` at most 5 min ahead of server time; unknown fields rejected |
| `/devices/$id/history/$ts` | same device, only if the key does not exist yet and the value is not null (append-only) | device, owners | key is 10 digits; same field checks |
| `/devices/$id/control` | owners (`/devices/$id/owners/<uid> == true`) | device, owners | `targetTemp` 20–40 °C, `heaterOverride` in {auto, off}, `updatedBy == auth.uid` |
| `/devices/$id/settings` | owners | device, owners | name length, alert thresholds |
| `/devices/$id/owners/$uid` | nobody through the client SDK (Admin SDK only) | device, owners | value must be `true` |
| `/users/$uid/devices/$id` | the user themself | the user themself | may only bookmark a device whose owners list contains them |
| everything else | nobody | nobody | no root `.read`/`.write`, so the default is deny |

Device identity is a Firebase **custom token** minted per device by a server with the Admin SDK:
`createCustomToken("dev-hive-1C5A00", { device: true, deviceId: "hive-1C5A00" })`. The firmware
exchanges it once for an ID token at `identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken`,
then sends `?auth=<idToken>` on every REST call and refreshes the token hourly with the refresh token.
The custom token lives in the device's `secrets.h`, never in git. Owners are written by the same
server when a device is claimed; the client SDK cannot grant ownership.

## Scenario files

`scenarios/seed.json` is the database content before each scenario. The device node is a real reading
from the incubator export in
[incubator-telemetry-analysis](https://github.com/Mariam-zeqred/incubator-telemetry-analysis)
(`hive-1C5A00`, 3 Oct 2026); the user ids and the second device are placeholders. Each scenario is one
JSON object:

```json
{ "name": "device writes another device's status",
  "why": "A stolen device token must not impersonate a different incubator.",
  "auth": { "uid": "dev-hive-1C5A00", "token": { "device": true, "deviceId": "hive-1C5A00" } },
  "op": "write", "path": "/devices/hive-2B7F10/status",
  "value": { "ts": 1791021726, "temp": 26.9, "hum": 81.4, "heater": true },
  "expect": "deny" }
```

`auth: null` is an anonymous client; `op` is `read`, `write` (value `null` deletes) or `update`
(a multi-location patch with a `values` map); `now` pins the clock for the interpreter.

## What the interpreter covers, and what it does not

Covered, and checked against the emulator in `tests/test_emulator.py`:

- cascading `.read` / `.write` (a rule at an ancestor grants, a child cannot revoke), literal keys
  beating `$variables`, `.validate` on the path root → target with merged `newData` and on the written
  subtree, `.validate` skipped for null (deletes), multi-location updates checked path by path;
- `auth`, `auth.uid`, `auth.token.<claim>` (missing claim reads as `null`), `data`, `newData`, `root`
  (pre-write), `now`, `$variables`;
- `val exists child parent hasChild hasChildren isNumber isString isBoolean getPriority`,
  string `length contains beginsWith endsWith replace toLowerCase toUpperCase matches(/re/i)`,
  `&& || ! === !== < <= > >= + - * / % ?:`. An expression error (for example `auth.uid` with
  `auth == null`) makes the rule `false`, as in the real engine, and is shown in the trace.

Not covered (use the emulator for these): query-based rules (`query.orderByChild` and friends),
`.indexOn`, priorities, `ServerValue` placeholders, and transactions. `matches` uses Python's `re`,
which differs from Firebase's RE2 on exotic patterns. Whether `root` and `newData` see the other paths
of the same multi-location update is not modelled (each path is checked against the pre-update tree);
the two update scenarios here do not depend on it. Rules deployed to production should be tested with
the emulator at least once; the interpreter is for fast feedback and for machines without Node and Java.

## Results

All numbers come from running `make check` and `make emulator` in this repo:

| Rules file | Allowed | Denied | Matches `expect` | Emulator agrees |
|---|---|---|---|---|
| `database.rules.json` | 11 | 28 | 39 / 39 | 39 / 39 |
| `rules/open.rules.json` | 39 | 0 | n/a (0 / 28 denies) | 39 / 39 |

Emulator: `firebase-database-emulator-v4.11.2` via firebase-tools 14.27.0 and Java 21. The whole
`make check` takes about 5 s, the emulator run about 10 s.

## Limitations

- The layout is one device → one `status` node → one `history` list, which is what the incubator
  firmware writes today; a poultry house with several zones would nest one more level.
- The ruleset guards *shape*, not *truth*: a compromised device can still write plausible wrong readings.
  Only the firmware's own safety layer protects the animals.
- History is append-only for devices and read-only for owners, so retention needs a server job
  (Admin SDK) or a scheduled function; the rules alone cannot delete.
- Custom tokens require a small server to mint them. For a hobby deployment that is a Cloud Function
  or a laptop script; it is still less work than living with an open database.

## Next steps

- Add a `scenarios/` set for the poultry layout (zones, fans, gas alarms) and a second rules file.
- Mint real custom tokens with the Admin SDK and run the scenarios against a dev project with the
  REST API (same scenario format, different backend).
- Port the ESP32 side: token exchange + refresh in the `esp32-mqtt-sensor-node` style, `secrets.example.h`.
