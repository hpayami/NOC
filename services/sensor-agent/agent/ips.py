"""Inline-prevention directive application. The agent never reconfigures capture on its own: an
operator provides a hook (a script receiving the directive JSON on stdin) and declares the host
inline-capable. Without both, an `ips`/`ips_test` directive is acknowledged as NOT applied, with
the reason — the platform then keeps the sensor in detect-only."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

HookRunner = Callable[[list[str], bytes], tuple[int, str, str]]


def default_hook_runner(cmd: list[str], stdin: bytes) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=60, check=False)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, "", str(err)


class IpsApplier:
    def __init__(self, hook: Path | None, inline_capable: bool, runner: HookRunner = default_hook_runner):
        self.hook = hook
        self.inline_capable = inline_capable
        self.runner = runner

    def apply(self, directive: dict[str, Any]) -> tuple[bool, str]:
        mode = directive.get("mode")
        if directive.get("failOpen") is not True:
            return False, "directive is not fail-open; refusing to apply"
        if mode == "ids":
            if self.hook and self.inline_capable:
                code, out, err = self.runner([str(self.hook)], json.dumps(directive).encode("utf-8"))
                if code != 0:
                    return False, f"hook exit {code} while returning to detect-only: {(err or out).strip()[:300]}"
            return True, "detect-only: no inline configuration active"
        if not self.inline_capable:
            return False, "host not declared inline-capable (SENSOR_INLINE_CAPABLE); directive recorded, not applied"
        if not self.hook:
            return False, "no NOC_IPS_APPLY_HOOK configured; inline prevention cannot be applied by the agent"
        if not self.hook.exists():
            return False, f"hook {self.hook} does not exist"
        code, out, err = self.runner([str(self.hook)], json.dumps(directive).encode("utf-8"))
        if code != 0:
            return False, f"hook exit {code}: {(err or out).strip()[:300]}"
        return True, (out.strip()[:300] or f"applied {mode} policy {directive.get('policyId')} v{directive.get('version')}")
