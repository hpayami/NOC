from fastapi.testclient import TestClient

from app.baseline import MIN_HISTORY_POINTS, robust_z, score_features, squash
from app.main import app

client = TestClient(app)


def test_flat_history_scores_low_for_ordinary_values_and_high_for_spikes():
    history = [10.0] * 24
    score, _scored = score_features({"events": (history, 10.0)})
    assert score == 0.0
    spike, scored_spike = score_features({"events": (history, 400.0)})
    assert spike > 0.9
    assert scored_spike[0].feature == "events"
    assert scored_spike[0].z > 100


def test_robust_to_outliers_in_history():
    history = [5.0] * 30 + [900.0, 950.0]  # two past spikes must not inflate the baseline
    med, _mad, z = robust_z(history, 6.0)
    assert med == 5.0
    assert abs(z) < 1.5
    assert squash(0) == 0 and 0.49 < squash(4.0) < 0.51


def test_contributions_sum_to_one_and_explain_the_score():
    features = {
        "events": ([20.0] * 24, 21.0),
        "distinct_ports": ([3.0] * 24, 60.0),
        "distinct_peers": ([4.0] * 24, 4.0),
    }
    score, scored = score_features(features)
    assert score > 0.8
    assert abs(sum(f.contribution for f in scored) - 1.0) < 1e-6
    assert max(scored, key=lambda f: f.contribution).feature == "distinct_ports"


def test_endpoint_refuses_insufficient_history_honestly():
    body = {
        "subject_type": "asset",
        "subject_id": "a1",
        "feature_set_version": "asset-hourly-v1",
        "features": [{"name": "events", "history": [1.0] * (MIN_HISTORY_POINTS - 1), "current": 50}],
    }
    res = client.post("/api/v1/analysis/score", json=body)
    assert res.status_code == 422
    assert res.json()["detail"]["code"] == "insufficient_history"
    body["features"][0]["history"] = [1.0] * MIN_HISTORY_POINTS
    ok = client.post("/api/v1/analysis/score", json=body)
    assert ok.status_code == 200
    out = ok.json()
    assert out["advisory"] is True
    assert out["model_name"] == "robust-baseline"
    assert 0 <= out["score"] <= 1
    assert out["explanation"][0]["feature"] == "events"
