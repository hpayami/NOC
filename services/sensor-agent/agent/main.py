"""Agent loop: enrol once, then heartbeat, fetch/apply the rule bundle (ETag-cached), fetch/apply/
acknowledge the inline-prevention directive, and ship EVE. Every statement to the platform comes
from something the agent observed; failures are reported, never masked."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform as _platform
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .client import ApiClient, ApiError
from .config import Config
from .eve import EveShipper
from .ips import IpsApplier
from .suricata import SuricataAdapter

log = logging.getLogger("noc-agent")


@dataclass
class AgentState:
    bundle_etag: str | None = None
    running_bundle_sha: str | None = None  # only set after a successful reload
    last_bundle_detail: str | None = None
    directive_key: tuple[str | None, int] | None = None
    last_heartbeat: float = 0.0
    last_bundle: float = 0.0
    last_directive: float = 0.0
    errors: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        log.warning(msg)
        self.errors.append(msg)
        del self.errors[:-50]


class Agent:
    def __init__(
        self,
        cfg: Config,
        client: ApiClient | None = None,
        suricata: SuricataAdapter | None = None,
        ips: IpsApplier | None = None,
        eve: EveShipper | None = None,
        clock: Any = time.monotonic,
    ):
        self.cfg = cfg
        self.client = client or ApiClient(cfg.api_url, cfg.http_timeout, str(cfg.ca_file) if cfg.ca_file else None)
        self.suricata = suricata or SuricataAdapter(cfg.rules_file, cfg.suricata_socket)
        self.ips = ips or IpsApplier(cfg.ips_apply_hook, cfg.inline_capable)
        self.eve = eve or (
            EveShipper(cfg.eve_log, cfg.state_dir / "eve.checkpoint", cfg.eve_batch_lines, cfg.eve_batch_bytes)
            if cfg.eve_log
            else None
        )
        self.clock = clock
        self.state = AgentState()
        self._load_state()

    # ---- persistence ------------------------------------------------------------------------
    def _state_file(self) -> Path:
        return self.cfg.state_dir / "agent-state.json"

    def _load_state(self) -> None:
        try:
            doc = json.loads(self._state_file().read_text())
            self.state.bundle_etag = doc.get("bundle_etag")
            self.state.running_bundle_sha = doc.get("running_bundle_sha")
            dk = doc.get("directive_key")
            self.state.directive_key = (dk[0], int(dk[1])) if dk else None
        except (OSError, ValueError, TypeError):
            pass

    def _save_state(self) -> None:
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file().with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "bundle_etag": self.state.bundle_etag,
                    "running_bundle_sha": self.state.running_bundle_sha,
                    "directive_key": list(self.state.directive_key) if self.state.directive_key else None,
                }
            )
        )
        os.replace(tmp, self._state_file())

    # ---- enrolment --------------------------------------------------------------------------
    def ensure_credential(self) -> bool:
        if self.client.credential:
            return True
        try:
            cred = self.cfg.credential_file.read_text().strip()
            if cred:
                self.client.credential = cred
                return True
        except OSError:
            pass
        if not self.cfg.enrolment_token:
            self.state.error("no credential and no NOC_ENROLMENT_TOKEN: cannot enrol")
            return False
        try:
            res = self.client.enrol(
                self.cfg.enrolment_token,
                self.cfg.hostname,
                {
                    "os": _platform.system() or "unknown",
                    "osVersion": _platform.release() or "unknown",
                    "kernel": _platform.version()[:64] or "unknown",
                    "arch": _platform.machine() or "unknown",
                },
                self.cfg.agent_version,
            )
        except (ApiError, OSError) as err:
            self.state.error(f"enrolment failed: {err}")
            return False
        self.cfg.credential_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.cfg.credential_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(res["credential"])
        log.info("enrolled as sensor %s", res["sensorId"])
        return True

    # ---- one cycle --------------------------------------------------------------------------
    def heartbeat(self) -> None:
        st = self.suricata.engine_state()
        payload = {
            "state": st.state,
            "detail": st.detail or self.state.last_bundle_detail,
            "engineVersion": st.engine_version,
            "packetsCaptured": st.packets_captured,
            "packetsDropped": st.packets_dropped,
            "rulesBundleSha256": self.state.running_bundle_sha,
            "inlineCapable": bool(self.cfg.inline_capable and self.cfg.ips_apply_hook),
        }
        self.client.heartbeat(payload)

    def sync_rules(self) -> None:
        res = self.client.rules_bundle(self.state.bundle_etag)
        if res.status == 304:
            return
        bundle = res.body
        self.suricata.write_bundle(bundle)
        ok, detail = self.suricata.reload_rules()
        if ok:
            self.state.running_bundle_sha = bundle["bundleSha256"]
            self.state.bundle_etag = res.headers.get("etag")
            self.state.last_bundle_detail = None
            log.info("rules bundle %s applied (%d rules)", bundle["bundleSha256"][:12], bundle["ruleCount"])
        else:
            # The file is on disk but the engine did not pick it up: keep reporting the old digest
            # and retry on the next cycle (no ETag so the bundle is fetched again).
            self.state.bundle_etag = None
            self.state.last_bundle_detail = f"rules written but reload failed: {detail}"[:512]
            self.state.error(self.state.last_bundle_detail)
        self._save_state()

    def sync_directive(self) -> None:
        d = self.client.ips_directive()
        key = (d.get("policyId"), int(d.get("version", 0)))
        if key == self.state.directive_key:
            return
        applied, detail = self.ips.apply(d)
        self.client.ips_ack(key[0], key[1], applied, detail)
        self.state.directive_key = key
        self._save_state()
        (log.info if applied else log.warning)("directive %s v%s: applied=%s %s", d.get("mode"), key[1], applied, detail)

    def ship_eve(self) -> None:
        if not self.eve:
            return
        for _ in range(20):  # bounded catch-up per cycle
            report = self.eve.ship_once(self.client.ingest_eve)
            if not report:
                break

    def run_once(self) -> None:
        if not self.ensure_credential():
            return
        now = self.clock()
        for name, interval, fn, stamp in (
            ("heartbeat", self.cfg.heartbeat_interval, self.heartbeat, "last_heartbeat"),
            ("rules", self.cfg.bundle_interval, self.sync_rules, "last_bundle"),
            ("directive", self.cfg.directive_interval, self.sync_directive, "last_directive"),
        ):
            if now - getattr(self.state, stamp) < interval and getattr(self.state, stamp) != 0.0:
                continue
            try:
                fn()
                setattr(self.state, stamp, now)
            except (ApiError, OSError) as err:
                self.state.error(f"{name}: {err}")
        try:
            self.ship_eve()
        except (ApiError, OSError) as err:
            self.state.error(f"eve: {err}")

    def run_forever(self, tick: float = 5.0) -> None:
        while True:
            self.run_once()
            time.sleep(tick)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NOC reference sensor agent")
    ap.add_argument("--once", action="store_true", help="run one cycle and exit")
    ap.add_argument("--tick", type=float, default=5.0)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    agent = Agent(Config.from_env())
    if args.once:
        agent.run_once()
        return 0 if not agent.state.errors else 1
    agent.run_forever(args.tick)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
