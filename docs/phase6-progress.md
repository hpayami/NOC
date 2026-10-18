# Phase 6 — progress log

## Slice 1 — Advisory ML: statistical baseline scoring (2026-10-18)

**Invariant kept:** model output is advisory. The API refuses a non-advisory result from the
service (`advisory !== true` → 502), stores results only for people to read, and nothing — no
alert, incident, response action or policy — is created from a score. The integration test
asserts that after a high score the alert and incident queues are still empty.

**Delivered**

- `services/analysis/app/baseline.py`: `robust-baseline@1.0.0` — per-feature median/MAD baseline
  over a subject's own history, robust z-score, monotonic squash into [0, 1) (0.5 at |z| = 4),
  contributions normalised to sum to 1, `InsufficientHistory` below 12 points. Pure Python, no
  learned parameters, no external calls. `POST /api/v1/analysis/score` (internal token when
  configured) returns the score with a per-feature explanation; a short history is a 422 with
  `insufficient_history`, not a guess. `GET /api/v1/analysis/status` now lists the model with an
  honest evaluation record: _none — unsupervised baseline; no labelled evaluation exists_.
- `apps/api/src/ml/service.ts` + `routes/ml.ts` (`/api/v1/ml`): features are built from the
  platform's own event store — hourly buckets over the last 168 h per asset (`events`,
  `distinct_dst_ports`, `distinct_peers`, `detections`), quiet hours as explicit zeros — and sent
  to the service; results are stored in `ml_inference_results` with inputs, explanation, window
  and evidence reference, and audited (`ml.score`). `GET /status` reports reachability (an
  unreachable service is a state with its error, not a crash; probe cached 60 s), the model
  register and the stored result count. `POST /score` (`ml.manage`) scores one asset (422 when it
  has no events), `POST /score/batch` scores the most active assets and reports per-asset skips,
  `GET /results` (`ml.read`) lists with subject/min-score filters. `ANALYSIS_URL` and
  `ANALYSIS_INTERNAL_TOKEN` configure the bridge; blue-team engineers gained `ml.manage`.
- Schema (`0010_phase6_ml_advisory`): `ml_inference_results`. Capability `ml.analytics` is
  **dynamic**: `not_configured` while the service is unreachable (with the reason), `degraded`
  when reachable with no models, `available` with the advisory wording.
- Web **ML Analytics**: service state and model register with the evaluation text, advisory
  banner, "data sent to external model APIs: no", score-one / score-batch for `ml.manage`, stored
  results with the per-feature explanation (current vs median, z).

**Verified**

Python: 4 new tests (flat history → 0 / spike → > 0.9, outlier-robust baseline, contributions
sum to one and name the right feature, endpoint refuses short history). API: 3 integration tests
against an in-process stub that implements the service contract — status/capability honesty and
RBAC, feature building (168 buckets, median 5 vs current 300), stored explanation, audit, _no
alert/incident created_, batch skips; unreachable service → reported state, `not_configured`
capability, 503 on scoring. Totals: shared 98, API 87, web 4, pytest 8; e2e 5/5 (blue-team
test now also checks the ML page: advisory banner, reachability state, no fabricated scores).

**Not delivered / limitations**

No learned models (and therefore no evaluation data); features are network-count baselines only;
no scheduled scoring (explicit request only — deliberate until the operator has seen the
baseline behaviour); no per-asset model persistence (baseline is recomputed from history each
time, which is the honest choice for a median/MAD model).
