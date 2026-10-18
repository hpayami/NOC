"""Suricata adapter. Writes the managed rules file atomically and talks to the engine through
`suricatasc` when it is present. Everything it cannot observe is reported as unknown (None),
never as a healthy default."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

Runner = Callable[[list[str]], tuple[int, str, str]]


def default_runner(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, "", str(err)


@dataclass
class EngineState:
    state: str  # healthy | degraded | failed
    detail: str | None
    engine_version: str | None
    packets_captured: int | None
    packets_dropped: int | None


class SuricataAdapter:
    def __init__(self, rules_file: Path, socket: Path, runner: Runner = default_runner, suricatasc: str = "suricatasc"):
        self.rules_file = rules_file
        self.socket = socket
        self.runner = runner
        self.suricatasc = suricatasc

    # ---- rules ------------------------------------------------------------------------------
    def write_bundle(self, bundle: dict[str, Any]) -> Path:
        lines = [
            f"# NOC managed rules — bundle {bundle['bundleSha256']} generated {bundle['generatedAt']}",
            f"# engine={bundle['engine']} site={bundle.get('site') or '-'} rules={bundle['ruleCount']}",
            "# Do not edit: the sensor agent rewrites this file from the registry.",
        ]
        for r in bundle["rules"]:
            lines.append(f"# {r['source']} {r['externalId']} rev {r['revision']} sha256:{r['contentSha256']}")
            lines.append(r["content"].rstrip("\n"))
        content = "\n".join(lines) + "\n"
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".noc-rules-", dir=str(self.rules_file.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp, self.rules_file)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return self.rules_file

    def _sc(self, command: str) -> tuple[bool, str]:
        if shutil.which(self.suricatasc) is None and self.runner is default_runner:
            return False, "suricatasc not installed"
        if not self.socket.exists() and self.runner is default_runner:
            return False, f"command socket {self.socket} missing (is Suricata running with unix-command enabled?)"
        code, out, err = self.runner([self.suricatasc, "-c", command, str(self.socket)])
        if code != 0:
            return False, (err or out or f"exit {code}").strip()[:512]
        return True, out.strip()

    def reload_rules(self) -> tuple[bool, str]:
        ok, detail = self._sc("reload-rules")
        return ok, detail if detail else ("rules reloaded" if ok else "reload failed")

    # ---- health -----------------------------------------------------------------------------
    def engine_state(self) -> EngineState:
        ok, detail = self._sc("uptime")
        if not ok:
            return EngineState("failed", detail, None, None, None)
        version: str | None = None
        okv, out = self._sc("version")
        if okv:
            version = self._message(out) or out[:64]
        captured = dropped = None
        okc, counters = self._sc("dump-counters")
        if okc:
            captured, dropped = self._parse_counters(counters)
        state = "healthy"
        note = None
        if captured and dropped and captured > 0 and dropped / captured > 0.05:
            state = "degraded"
            note = f"kernel drops {dropped}/{captured}"
        return EngineState(state, note, version, captured, dropped)

    @staticmethod
    def _message(out: str) -> str | None:
        try:
            doc = json.loads(out)
            m = doc.get("message")
            return str(m) if m is not None else None
        except ValueError:
            return None

    @staticmethod
    def _parse_counters(out: str) -> tuple[int | None, int | None]:
        try:
            doc = json.loads(out)
        except ValueError:
            return None, None
        msg = doc.get("message", doc)
        captured = dropped = None

        def walk(node: Any) -> None:
            nonlocal captured, dropped
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "kernel_packets" and isinstance(v, (int, float)):
                        captured = (captured or 0) + int(v)
                    elif k == "kernel_drops" and isinstance(v, (int, float)):
                        dropped = (dropped or 0) + int(v)
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(msg)
        return captured, dropped
