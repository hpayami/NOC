"""Configuration from the environment. Nothing here is a credential: the sensor credential is
read from / written to NOC_CREDENTIAL_FILE after enrolment and never logged."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(v: str | None, default: bool) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(v: str | None, default: int, lo: int, hi: int) -> int:
    try:
        n = int(v) if v not in (None, "") else default
    except ValueError:
        n = default
    return max(lo, min(hi, n))


@dataclass
class Config:
    api_url: str = "http://127.0.0.1:4000"
    enrolment_token: str | None = None
    credential_file: Path = field(default_factory=lambda: Path("/var/lib/noc-agent/credential"))
    state_dir: Path = field(default_factory=lambda: Path("/var/lib/noc-agent"))
    rules_file: Path = field(default_factory=lambda: Path("/var/lib/suricata/rules/noc-managed.rules"))
    suricata_socket: Path = field(default_factory=lambda: Path("/var/run/suricata/suricata-command.socket"))
    eve_log: Path | None = field(default_factory=lambda: Path("/var/log/suricata/eve.json"))
    heartbeat_interval: int = 30
    bundle_interval: int = 60
    directive_interval: int = 15
    eve_batch_lines: int = 500
    eve_batch_bytes: int = 1_000_000
    ips_apply_hook: Path | None = None
    validation_samples_dir: Path | None = None
    validation_interval: int = 30
    inline_capable: bool = False
    hostname: str = field(default_factory=lambda: os.uname().nodename if hasattr(os, "uname") else "sensor")
    agent_version: str = "0.1.0"
    ca_file: Path | None = None
    http_timeout: float = 10.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        e = os.environ if env is None else env
        g = e.get
        hook = g("NOC_IPS_APPLY_HOOK")
        eve = g("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")
        return cls(
            api_url=g("NOC_API_URL", "http://127.0.0.1:4000").rstrip("/"),
            enrolment_token=g("NOC_ENROLMENT_TOKEN") or None,
            credential_file=Path(g("NOC_CREDENTIAL_FILE", "/var/lib/noc-agent/credential")),
            state_dir=Path(g("NOC_STATE_DIR", "/var/lib/noc-agent")),
            rules_file=Path(g("SURICATA_RULES_FILE", "/var/lib/suricata/rules/noc-managed.rules")),
            suricata_socket=Path(g("SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket")),
            eve_log=Path(eve) if eve else None,
            heartbeat_interval=_int(g("NOC_HEARTBEAT_INTERVAL"), 30, 5, 300),
            bundle_interval=_int(g("NOC_BUNDLE_INTERVAL"), 60, 10, 3600),
            directive_interval=_int(g("NOC_DIRECTIVE_INTERVAL"), 15, 5, 300),
            eve_batch_lines=_int(g("NOC_EVE_BATCH_LINES"), 500, 1, 5000),
            eve_batch_bytes=_int(g("NOC_EVE_BATCH_BYTES"), 1_000_000, 10_000, 4_000_000),
            ips_apply_hook=Path(hook) if hook else None,
            validation_samples_dir=Path(g("NOC_VALIDATION_SAMPLES_DIR")) if g("NOC_VALIDATION_SAMPLES_DIR") else None,
            validation_interval=_int(g("NOC_VALIDATION_INTERVAL"), 30, 10, 600),
            inline_capable=_bool(g("SENSOR_INLINE_CAPABLE"), False),
            hostname=g("NOC_SENSOR_HOSTNAME") or (os.uname().nodename if hasattr(os, "uname") else "sensor"),
            agent_version=g("NOC_AGENT_VERSION", "0.1.0"),
            ca_file=Path(g("NOC_CA_FILE")) if g("NOC_CA_FILE") else None,
            http_timeout=float(g("NOC_HTTP_TIMEOUT", "10")),
        )
