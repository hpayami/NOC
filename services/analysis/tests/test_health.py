from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)


def test_health_and_ready():
    for path in ("/health", "/ready"):
        res = client.get(path)
        assert res.status_code == 200
        assert res.json()["status"] == "ok"
        assert res.headers["x-request-id"]
        assert res.headers["x-content-type-options"] == "nosniff"


def test_status_is_advisory_and_model_free():
    res = client.get("/api/v1/analysis/status")
    assert res.status_code == 200
    body = res.json()
    assert body["advisory_only"] is True
    assert [m["name"] for m in body["models"]] == ["robust-baseline"]
    assert body["models"][0]["kind"] == "statistical_baseline"
    assert body["models"][0]["state"] == "advisory"
    assert "no labelled evaluation" in body["models"][0]["evaluation"]
    assert body["external_model_apis_allowed"] is False


def test_internal_token_enforced_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "internal_token", "a-long-enough-internal-token-value")
    assert client.get("/api/v1/analysis/status").status_code == 401
    assert client.get("/api/v1/analysis/status", headers={"x-internal-token": "wrong"}).status_code == 401
    ok = client.get(
        "/api/v1/analysis/status", headers={"x-internal-token": "a-long-enough-internal-token-value"}
    )
    assert ok.status_code == 200


def test_request_id_is_propagated():
    res = client.get("/health", headers={"x-request-id": "abc-123"})
    assert res.headers["x-request-id"] == "abc-123"
