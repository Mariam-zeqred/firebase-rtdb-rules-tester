"""Run scenarios against the official Firebase Realtime Database emulator.

The emulator is started with ``firebase emulators:start --only database``;
rules and seed are pushed over REST with the emulator's ``owner`` token, and
each scenario is one REST request carrying an unsigned JWT in ``?auth=``
(the emulator does not verify signatures). Needs ``firebase-tools`` and Java.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from rtdb_rules.scenarios import Auth, Scenario

PROJECT = "demo-rules-tester"
NAMESPACE = f"{PROJECT}-default-rtdb"
DEFAULT_PORT = 9123


class EmulatorUnavailable(RuntimeError):
    pass


def find_firebase() -> str | None:
    for candidate in (
        os.environ.get("FIREBASE_CLI"),
        shutil.which("firebase"),
        str(Path("node_modules/.bin/firebase")),
    ):
        if candidate and Path(candidate).exists():
            return candidate
    return None


def _b64(obj: dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fake_id_token(auth: Auth) -> str:
    """An unsigned JWT with the claims the emulator exposes as ``auth``."""
    now = int(time.time())
    payload = {
        "iss": f"https://securetoken.google.com/{PROJECT}",
        "aud": PROJECT,
        "iat": now,
        "exp": now + 3600,
        "auth_time": now,
        "sub": auth.uid,
        "user_id": auth.uid,
        "firebase": {"sign_in_provider": auth.provider, "identities": {}},
        **auth.token,
    }
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(payload)}."


class Emulator:
    """Context manager around one emulator process."""

    def __init__(self, port: int = DEFAULT_PORT, startup_timeout: float = 90.0) -> None:
        self.port = port
        self.startup_timeout = startup_timeout
        self.proc: subprocess.Popen[bytes] | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> Emulator:
        firebase = find_firebase()
        if firebase is None:
            raise EmulatorUnavailable("firebase CLI not found (npm install -g firebase-tools)")
        if shutil.which("java") is None:
            raise EmulatorUnavailable("java not found; the emulator needs a JRE")
        self._tmp = tempfile.TemporaryDirectory(prefix="rtdb-emu-")
        cfg = Path(self._tmp.name)
        (cfg / "database.rules.json").write_text(json.dumps({"rules": {".read": False, ".write": False}}))
        (cfg / "firebase.json").write_text(
            json.dumps(
                {
                    "database": {"rules": "database.rules.json"},
                    "emulators": {
                        "database": {"port": self.port, "host": "127.0.0.1"},
                        "ui": {"enabled": False},
                    },
                }
            )
        )
        log = open(cfg / "emulator.log", "wb")
        self.proc = subprocess.Popen(
            [firebase, "emulators:start", "--only", "database", "--project", PROJECT],
            cwd=cfg,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise EmulatorUnavailable(
                    f"emulator exited early; log:\n{(cfg / 'emulator.log').read_text()[-3000:]}"
                )
            try:
                self._request("GET", "/.json", admin=True)
                return self
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.5)
        self.__exit__(None, None, None)
        raise EmulatorUnavailable("emulator did not become ready in time")

    def __exit__(self, *exc: object) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._tmp:
            self._tmp.cleanup()

    # -- REST ----------------------------------------------------------------
    def _request(
        self, method: str, path: str, body: Any = None, admin: bool = False, auth: Auth | None = None
    ) -> tuple[int, Any]:
        url = f"{self.base}{path}?ns={NAMESPACE}"
        headers = {"Content-Type": "application/json"}
        if admin:
            headers["Authorization"] = "Bearer owner"
        elif auth is not None:
            url += f"&auth={fake_id_token(auth)}"
        data = None if body is _NOBODY else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def set_rules(self, rules: dict[str, Any]) -> None:
        status, body = self._request("PUT", "/.settings/rules.json", rules, admin=True)
        if status != 200:
            raise RuntimeError(f"rules upload failed: {status} {body}")

    def set_seed(self, seed: Any) -> None:
        status, body = self._request("PUT", "/.json", seed, admin=True)
        if status != 200:
            raise RuntimeError(f"seed upload failed: {status} {body}")

    def run(self, scenario: Scenario, seed: Any) -> bool:
        """True if the emulator allowed the operation (seed is restored first)."""
        self.set_seed(seed)
        path = "/" + "/".join(p for p in scenario.path.strip("/").split("/") if p) + ".json"
        if scenario.op == "read":
            status, _ = self._request("GET", path, _NOBODY, auth=scenario.auth)
        elif scenario.op == "write":
            status, _ = self._request("PUT", path, scenario.value, auth=scenario.auth)
        else:
            status, _ = self._request("PATCH", path, scenario.values, auth=scenario.auth)
        if status == 200:
            return True
        if status in (401, 403):
            return False
        raise RuntimeError(f"unexpected emulator response {status} for {scenario.name}")


_NOBODY = object()
