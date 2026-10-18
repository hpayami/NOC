"""Detection validation: replay a named sample *offline* through the rules the agent currently
runs and report which signatures fired. Nothing is sent on the wire; the sample never leaves the
sensor; the platform derives the verdict. A sample name is a bare file name inside the configured
directory — never a path."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .suricata import Runner, default_runner

SAMPLE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FAST_SID = re.compile(r"\[\d+:(\d+):\d+\]")


@dataclass
class ValidationResult:
    fired_sids: list[int]
    engine_version: str | None
    error: str | None
    duration_ms: int

    def payload(self, running_bundle_sha: str | None) -> dict:
        return {
            "firedSids": self.fired_sids[:10000],
            "rulesBundleSha256": running_bundle_sha,
            "engineVersion": self.engine_version,
            "error": self.error,
            "durationMs": self.duration_ms,
        }


class ValidationRunner:
    def __init__(
        self,
        samples_dir: Path | None,
        rules_file: Path,
        runner: Runner = default_runner,
        suricata_bin: str = "suricata",
        clock=time.monotonic,
    ):
        self.samples_dir = samples_dir
        self.rules_file = rules_file
        self.runner = runner
        self.suricata_bin = suricata_bin
        self.clock = clock

    def sample_path(self, ref: str) -> Path | None:
        """The sample file for `ref`, or None when the ref is not a bare name inside the directory."""
        if not self.samples_dir or not SAMPLE_REF.match(ref):
            return None
        p = (self.samples_dir / ref).resolve()
        try:
            p.relative_to(self.samples_dir.resolve())
        except ValueError:
            return None
        return p if p.is_file() else None

    def engine_version(self) -> str | None:
        code, out, _ = self.runner([self.suricata_bin, "-V"])
        if code != 0:
            return None
        m = re.search(r"(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else (out.strip()[:64] or None)

    def run(self, ref: str) -> ValidationResult:
        start = self.clock()

        def ms() -> int:
            return int((self.clock() - start) * 1000)

        if not self.samples_dir:
            return ValidationResult([], None, "no sample directory configured on this sensor", ms())
        path = self.sample_path(ref)
        if path is None:
            return ValidationResult([], None, f"sample {ref!r} is not available on this sensor", ms())
        if not self.rules_file.is_file():
            return ValidationResult([], None, "no rules bundle on disk", ms())
        version = self.engine_version()
        with tempfile.TemporaryDirectory(prefix="noc-validate-") as tmp:
            cmd = [
                self.suricata_bin,
                "-r", str(path),
                "-S", str(self.rules_file),
                "-l", tmp,
                "-k", "none",
                "--runmode", "single",
            ]
            code, out, err = self.runner(cmd)
            if code != 0:
                return ValidationResult([], version, f"suricata exited {code}: {(err or out).strip()[:400]}", ms())
            fired = self._collect(Path(tmp))
        return ValidationResult(sorted(fired), version, None, ms())

    @staticmethod
    def _collect(outdir: Path) -> set[int]:
        fired: set[int] = set()
        eve = outdir / "eve.json"
        if eve.is_file():
            with eve.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("event_type") == "alert":
                        sid = (rec.get("alert") or {}).get("signature_id")
                        if isinstance(sid, int) and sid > 0:
                            fired.add(sid)
        fast = outdir / "fast.log"
        if fast.is_file():
            for line in fast.read_text(encoding="utf-8", errors="replace").splitlines():
                m = FAST_SID.search(line)
                if m:
                    fired.add(int(m.group(1)))
        return fired


def cleanup_tmp(prefix: str = "noc-validate-") -> None:
    """Best effort removal of leftovers from an interrupted run."""
    base = Path(tempfile.gettempdir())
    for p in base.glob(f"{prefix}*"):
        shutil.rmtree(p, ignore_errors=True)
