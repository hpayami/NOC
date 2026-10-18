"""End-to-end agent behaviour against an in-process mock of the sensor-facing API. Nothing here
touches a real Suricata: the adapter gets a fake `suricatasc` runner and the IPS hook is a file."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agent.client import ApiClient, ApiError
from agent.config import Config
from agent.eve import EveShipper
from agent.ips import IpsApplier
from agent.main import Agent
from agent.suricata import SuricataAdapter

CRED = "c" * 64
BUNDLE = {
    "engine": "suricata",
    "sensorId": "00000000-0000-4000-8000-000000000001",
    "site": "dc1",
    "generatedAt": "2026-10-18T10:00:00.000Z",
    "bundleSha256": "a" * 64,
    "ruleCount": 1,
    "rules": [
        {
            "id": "00000000-0000-4000-8000-000000000002",
            "source": "custom",
            "externalId": "1:9000001",
            "revision": 1,
            "contentSha256": "b" * 64,
            "content": 'alert tcp any any -> any 4444 (msg:"C2"; sid:9000001; rev:1;)',
        }
    ],
}
IDS = {
    "mode": "ids",
    "policyId": None,
    "version": 0,
    "action": "drop",
    "protectedCidrs": [],
    "excludedCidrs": [],
    "ruleRefs": [],
    "expiresAt": None,
    "failOpen": True,
    "issuedAt": "2026-10-18T10:00:00.000Z",
}


class MockApi:
    """Records every call; `directive` and `bundle` can be swapped between cycles."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None, dict]] = []
        self.bundle = BUNDLE
        self.directive = IDS
        self.eve_fail = False
        self.server = HTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()

    def _handler(self):
        api = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _body(self):
                n = int(self.headers.get("content-length") or 0)
                return self.rfile.read(n) if n else b""

            def _send(self, status, body=None, headers=None):
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if body is not None:
                    data = json.dumps(body).encode()
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_header("content-length", "0")
                    self.end_headers()

            def do_POST(self):
                raw = self._body()
                try:
                    body = json.loads(raw) if raw and self.headers.get("content-type", "").startswith("application/json") else None
                except ValueError:
                    body = None
                hdr = {k.lower(): v for k, v in self.headers.items()}
                api.calls.append(("POST", self.path, body if body is not None else {"raw": raw.decode()}, hdr))
                if self.path == "/api/v1/agents/enrol":
                    if body.get("enrolmentToken") != "t" * 40:
                        return self._send(401, {"error": {"message": "bad token"}})
                    return self._send(201, {"sensorId": BUNDLE["sensorId"], "credential": CRED, "heartbeatIntervalSeconds": 30})
                if hdr.get("x-sensor-credential") != CRED:
                    return self._send(401, {"error": {"message": "unauthenticated"}})
                if self.path == "/api/v1/agents/heartbeat":
                    return self._send(204)
                if self.path == "/api/v1/agents/ips-ack":
                    return self._send(204)
                if self.path == "/api/v1/ingest/suricata/eve":
                    if api.eve_fail:
                        return self._send(503, {"error": {"message": "down"}})
                    lines = [x for x in raw.decode().split("\n") if x.strip()]
                    return self._send(202, {"received": len(lines), "accepted": len(lines)})
                return self._send(404, {"error": {"message": "nope"}})

            def do_GET(self):
                hdr = {k.lower(): v for k, v in self.headers.items()}
                api.calls.append(("GET", self.path, None, hdr))
                if hdr.get("x-sensor-credential") != CRED:
                    return self._send(401, {"error": {"message": "unauthenticated"}})
                if self.path == "/api/v1/agents/rules-bundle":
                    etag = f'"{api.bundle["bundleSha256"]}"'
                    if hdr.get("if-none-match") == etag:
                        return self._send(304, None, {"etag": etag})
                    return self._send(200, api.bundle, {"etag": etag})
                if self.path == "/api/v1/agents/ips-directive":
                    return self._send(200, api.directive)
                return self._send(404, {"error": {"message": "nope"}})

        return H


class FakeSc:
    """Fake suricatasc runner: records commands, can be told to fail reloads."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.fail_reload = False
        self.down = False

    def __call__(self, cmd: list[str]):
        c = cmd[2]
        self.commands.append(c)
        if self.down:
            return 1, "", "connect: no such file"
        if c == "reload-rules":
            return (1, "", "reload refused") if self.fail_reload else (0, '{"message":"done","return":"OK"}', "")
        if c == "uptime":
            return 0, '{"message":1234,"return":"OK"}', ""
        if c == "version":
            return 0, '{"message":"7.0.6 RELEASE","return":"OK"}', ""
        if c == "dump-counters":
            return 0, json.dumps({"message": {"capture": {"kernel_packets": 1000, "kernel_drops": 10}}}), ""
        return 1, "", "unknown"


@pytest.fixture()
def api():
    m = MockApi()
    yield m
    m.close()


def make_agent(api: MockApi, tmp: Path, **over) -> tuple[Agent, FakeSc]:
    kw = {"enrolment_token": "t" * 40, **over}
    cfg = Config(
        api_url=api.url,
        credential_file=tmp / "cred",
        state_dir=tmp / "state",
        rules_file=tmp / "rules" / "noc.rules",
        suricata_socket=tmp / "sock",
        eve_log=tmp / "eve.json",
        heartbeat_interval=5,
        bundle_interval=5,
        directive_interval=5,
        **kw,
    )
    sc = FakeSc()
    client = ApiClient(cfg.api_url, timeout=5)
    agent = Agent(
        cfg,
        client=client,
        suricata=SuricataAdapter(cfg.rules_file, cfg.suricata_socket, runner=sc),
        ips=IpsApplier(cfg.ips_apply_hook, cfg.inline_capable),
        eve=EveShipper(cfg.eve_log, cfg.state_dir / "eve.checkpoint", 2, 10_000),
        clock=lambda: 1000.0,
    )
    return agent, sc


def posts(api: MockApi, path: str):
    return [c[2] for c in api.calls if c[0] == "POST" and c[1] == path]


def test_enrols_once_heartbeats_applies_bundle_and_acks_detect_only(api, tmp_path):
    agent, sc = make_agent(api, tmp_path)
    agent.run_once()
    assert agent.state.errors == []
    # Enrolment happened once and the credential is persisted with 0600 — the token is never reused.
    assert len(posts(api, "/api/v1/agents/enrol")) == 1
    assert (tmp_path / "cred").read_text() == CRED
    assert oct(os.stat(tmp_path / "cred").st_mode & 0o777) == "0o600"
    # Heartbeat reports what suricatasc said; no bundle digest before the first successful reload.
    hb = posts(api, "/api/v1/agents/heartbeat")[0]
    assert hb["state"] == "healthy"
    assert hb["engineVersion"] == "7.0.6 RELEASE"
    assert hb["packetsCaptured"] == 1000 and hb["packetsDropped"] == 10
    assert hb["rulesBundleSha256"] is None
    assert hb["inlineCapable"] is False
    # Bundle written and reloaded; the running digest is now known and the ETag retained.
    rules = (tmp_path / "rules" / "noc.rules").read_text()
    assert "sid:9000001" in rules and BUNDLE["bundleSha256"] in rules
    assert "reload-rules" in sc.commands
    assert agent.state.running_bundle_sha == BUNDLE["bundleSha256"]
    # Detect-only directive acknowledged as applied.
    ack = posts(api, "/api/v1/agents/ips-ack")[0]
    assert ack == {"policyId": None, "version": 0, "applied": True, "detail": "detect-only: no inline configuration active"}

    # Second cycle: no re-enrolment, bundle fetch answered 304, directive unchanged → no new ack.
    agent.state.last_heartbeat = agent.state.last_bundle = agent.state.last_directive = 0.0
    agent.run_once()
    assert len(posts(api, "/api/v1/agents/enrol")) == 1
    gets = [c for c in api.calls if c[0] == "GET" and c[1] == "/api/v1/agents/rules-bundle"]
    assert gets[-1][3].get("if-none-match") == f'"{BUNDLE["bundleSha256"]}"'
    assert len(posts(api, "/api/v1/agents/ips-ack")) == 1
    assert posts(api, "/api/v1/agents/heartbeat")[-1]["rulesBundleSha256"] == BUNDLE["bundleSha256"]

    # A fresh agent process reloads its state: still no re-enrolment, still the same digest.
    again, _ = make_agent(api, tmp_path)
    assert again.state.running_bundle_sha == BUNDLE["bundleSha256"]
    assert again.ensure_credential() is True
    assert len(posts(api, "/api/v1/agents/enrol")) == 1


def test_reload_failure_never_claims_the_new_bundle(api, tmp_path):
    agent, sc = make_agent(api, tmp_path)
    sc.fail_reload = True
    agent.run_once()
    assert agent.state.running_bundle_sha is None
    assert agent.state.bundle_etag is None  # fetched again next cycle
    assert any("reload failed" in e for e in agent.state.errors)
    agent.state.last_heartbeat = 0.0
    agent.run_once()
    hb = posts(api, "/api/v1/agents/heartbeat")[-1]
    assert hb["rulesBundleSha256"] is None
    assert "reload failed" in hb["detail"]


def test_inline_directive_is_refused_without_operator_hook_and_applied_with_it(api, tmp_path):
    api.directive = {**IDS, "mode": "ips", "policyId": "00000000-0000-4000-8000-00000000000a", "version": 3, "protectedCidrs": ["10.0.0.0/8"], "ruleRefs": ["1:9000001"]}
    agent, _ = make_agent(api, tmp_path)
    agent.run_once()
    ack = posts(api, "/api/v1/agents/ips-ack")[-1]
    assert ack["applied"] is False and "inline-capable" in ack["detail"]
    # Declared capable but no hook: still refused, with the reason.
    agent2, _ = make_agent(api, tmp_path / "b", inline_capable=True)
    agent2.run_once()
    ack2 = posts(api, "/api/v1/agents/ips-ack")[-1]
    assert ack2["applied"] is False and "NOC_IPS_APPLY_HOOK" in ack2["detail"]
    # With a hook that succeeds: applied, heartbeat advertises inline capability, hook got the directive.
    hook = tmp_path / "hook.sh"
    hook.write_text("#!/bin/sh\ncat > \"$0.last\"\necho applied-by-hook\n")
    hook.chmod(0o755)
    agent3, _ = make_agent(api, tmp_path / "c", inline_capable=True, ips_apply_hook=hook)
    agent3.run_once()
    ack3 = posts(api, "/api/v1/agents/ips-ack")[-1]
    assert ack3 == {"policyId": api.directive["policyId"], "version": 3, "applied": True, "detail": "applied-by-hook"}
    assert json.loads((tmp_path / "hook.sh.last").read_text())["mode"] == "ips"
    assert posts(api, "/api/v1/agents/heartbeat")[-1]["inlineCapable"] is True
    # A failing hook reports the failure (platform then keeps / returns the sensor to detect-only).
    hook.write_text("#!/bin/sh\necho boom >&2\nexit 2\n")
    api.directive = {**api.directive, "version": 4}
    agent3.state.last_directive = 0.0
    agent3.run_once()
    ack4 = posts(api, "/api/v1/agents/ips-ack")[-1]
    assert ack4["applied"] is False and "hook exit 2: boom" in ack4["detail"]


def test_non_fail_open_directive_is_refused(tmp_path):
    applier = IpsApplier(None, False)
    assert applier.apply({**IDS, "failOpen": False}) == (False, "directive is not fail-open; refusing to apply")


def test_engine_down_is_reported_failed(api, tmp_path):
    agent, sc = make_agent(api, tmp_path)
    sc.down = True
    agent.run_once()
    hb = posts(api, "/api/v1/agents/heartbeat")[-1]
    assert hb["state"] == "failed"
    assert "connect" in hb["detail"]


def test_eve_shipping_checkpoints_only_on_acceptance_and_survives_rotation(api, tmp_path):
    agent, _ = make_agent(api, tmp_path)
    log = tmp_path / "eve.json"
    log.write_text('{"event_type":"alert","n":1}\n{"event_type":"alert","n":2}\n{"event_type":"alert","n":3}\n{"partial":')
    agent.run_once()
    sent = posts(api, "/api/v1/ingest/suricata/eve")
    assert [len(s["raw"].split("\n")) for s in sent] == [2, 1]  # batches of 2, partial line held back
    assert json.loads((tmp_path / "state" / "eve.checkpoint").read_text())["offset"] == len(
        '{"event_type":"alert","n":1}\n{"event_type":"alert","n":2}\n{"event_type":"alert","n":3}\n'
    )
    # API failure: nothing advances; after recovery the same lines are sent, not skipped.
    with open(log, "a") as f:
        f.write('"x"}\n{"event_type":"alert","n":4}\n')
    api.eve_fail = True
    agent.run_once()
    assert any("eve" in e for e in agent.state.errors)
    before = json.loads((tmp_path / "state" / "eve.checkpoint").read_text())["offset"]
    api.eve_fail = False
    agent.run_once()
    assert posts(api, "/api/v1/ingest/suricata/eve")[-1]["raw"].count("\n") == 1  # partial+n4 → 2 lines
    assert json.loads((tmp_path / "state" / "eve.checkpoint").read_text())["offset"] > before
    # Rotation: a new, smaller file restarts from zero.
    log.unlink()
    log.write_text('{"event_type":"alert","n":5}\n')
    agent.run_once()
    assert posts(api, "/api/v1/ingest/suricata/eve")[-1]["raw"] == '{"event_type":"alert","n":5}'


def test_bad_enrolment_token_is_an_error_not_a_crash(api, tmp_path):
    agent, _ = make_agent(api, tmp_path, enrolment_token="wrong" * 8)
    agent.run_once()
    assert agent.state.errors and "enrolment failed" in agent.state.errors[0]
    assert not (tmp_path / "cred").exists()
    with pytest.raises(ApiError):
        ApiClient(api.url).heartbeat({"state": "healthy"})
