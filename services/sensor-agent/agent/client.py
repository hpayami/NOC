"""Thin HTTP client for the sensor-facing API (urllib only). Every call has a timeout; errors
carry the status so the caller can decide between retry and reporting."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class ApiError(Exception):
    def __init__(self, status: int, body: str, url: str):
        super().__init__(f"HTTP {status} from {url}: {body[:200]}")
        self.status = status
        self.body = body


@dataclass
class Response:
    status: int
    body: Any
    headers: dict[str, str]


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 10.0, ca_file: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.credential: str | None = None
        self._ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        ok: tuple[int, ...] = (200, 201, 202, 204),
    ) -> Response:
        url = f"{self.base_url}{path}"
        h = {"accept": "application/json", "user-agent": "noc-sensor-agent"}
        if self.credential:
            h["x-sensor-credential"] = self.credential
        if headers:
            h.update(headers)
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as res:
                raw = res.read()
                status = res.status
                hdrs = {k.lower(): v for k, v in res.headers.items()}
        except urllib.error.HTTPError as err:
            raw = err.read()
            status = err.code
            hdrs = {k.lower(): v for k, v in err.headers.items()}
        if status not in ok:
            raise ApiError(status, raw.decode("utf-8", "replace"), url)
        parsed: Any = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except ValueError:
                parsed = raw.decode("utf-8", "replace")
        return Response(status, parsed, hdrs)

    def _json(self, method: str, path: str, payload: Any, **kw: Any) -> Response:
        return self._request(
            method,
            path,
            body=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json"},
            **kw,
        )

    # ---- sensor-facing endpoints -------------------------------------------------------------
    def enrol(self, token: str, hostname: str, platform: dict[str, str], agent_version: str) -> dict[str, Any]:
        res = self._json(
            "POST",
            "/api/v1/agents/enrol",
            {
                "enrolmentToken": token,
                "hostname": hostname,
                "platform": platform,
                "agentVersion": agent_version,
            },
        )
        self.credential = res.body["credential"]
        return res.body

    def heartbeat(self, payload: dict[str, Any]) -> None:
        self._json("POST", "/api/v1/agents/heartbeat", payload)

    def rules_bundle(self, etag: str | None) -> Response:
        headers = {"if-none-match": etag} if etag else {}
        return self._request("GET", "/api/v1/agents/rules-bundle", headers=headers, ok=(200, 304))

    def ips_directive(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/agents/ips-directive").body

    def ips_ack(self, policy_id: str | None, version: int, applied: bool, detail: str | None) -> None:
        self._json(
            "POST",
            "/api/v1/agents/ips-ack",
            {"policyId": policy_id, "version": version, "applied": applied, "detail": (detail or "")[:512] or None},
        )

    def ingest_eve(self, ndjson: bytes) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/v1/ingest/suricata/eve",
            body=ndjson,
            headers={"content-type": "application/x-ndjson"},
            ok=(202,),
        ).body
