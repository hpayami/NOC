import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .baseline import (
    MIN_HISTORY_POINTS,
    MODEL_NAME,
    MODEL_VERSION,
    InsufficientHistory,
    score_features,
)
from .config import settings

log = logging.getLogger("noc-analysis")
logging.basicConfig(
    level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_for_environment()
    log.info("noc-analysis starting (environment=%s)", settings.environment)
    yield


app = FastAPI(
    title="NOC Analysis Service",
    version=settings.version,
    description="Advisory security analytics. Statistical baselines only; results never trigger enforcement.",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-Id"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    log.info(
        '{"requestId":"%s","method":"%s","path":"%s","status":%d,"durationMs":%.2f}',
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        (time.perf_counter() - started) * 1000,
    )
    return response


class Health(BaseModel):
    status: Literal["ok"]
    service: Literal["noc-analysis"]
    version: str


class ModelStatus(BaseModel):
    name: str
    version: str
    state: Literal["not_trained", "advisory", "disabled"]
    kind: Literal["statistical_baseline", "learned"]
    # Honest evaluation record: a baseline has no held-out evaluation; a learned model must have one.
    evaluation: str
    min_history_points: int


class AnalysisStatus(BaseModel):
    service: Literal["noc-analysis"]
    environment: str
    advisory_only: Literal[True]
    external_model_apis_allowed: bool
    models: list[ModelStatus]


@app.get("/health", response_model=Health)
def health() -> Health:
    return Health(status="ok", service="noc-analysis", version=settings.version)


@app.get("/ready", response_model=Health)
def ready() -> Health:
    # No downstream dependencies in Phase 0; readiness equals liveness.
    return Health(status="ok", service="noc-analysis", version=settings.version)


def require_internal_token(x_internal_token: str | None) -> None:
    if settings.internal_token and x_internal_token != settings.internal_token:
        raise HTTPException(status_code=401, detail="internal token required")


@app.get("/api/v1/analysis/status", response_model=AnalysisStatus)
def analysis_status(x_internal_token: str | None = Header(default=None)) -> AnalysisStatus:
    require_internal_token(x_internal_token)
    # Honest register: the only model is an unsupervised robust baseline; nothing is "trained".
    return AnalysisStatus(
        service="noc-analysis",
        environment=settings.environment,
        advisory_only=True,
        external_model_apis_allowed=settings.allow_external_model_apis,
        models=[
            ModelStatus(
                name=MODEL_NAME,
                version=MODEL_VERSION,
                state="advisory",
                kind="statistical_baseline",
                evaluation="none: unsupervised median/MAD baseline per subject; no labelled evaluation exists",
                min_history_points=MIN_HISTORY_POINTS,
            )
        ],
    )


class FeatureInput(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    history: list[float] = Field(max_length=4096)
    current: float


class ScoreRequest(BaseModel):
    subject_type: Literal["asset", "flow", "alert", "dns_query"]
    subject_id: str = Field(min_length=1, max_length=128)
    feature_set_version: str = Field(min_length=1, max_length=64)
    features: list[FeatureInput] = Field(min_length=1, max_length=32)


class Contribution(BaseModel):
    feature: str
    contribution: float
    current: float
    median: float
    mad: float
    z: float


class ScoreResponse(BaseModel):
    model_name: str
    model_version: str
    feature_set_version: str
    subject_type: str
    subject_id: str
    score: float = Field(ge=0, le=1)
    advisory: Literal[True]
    explanation: list[Contribution]


@app.post("/api/v1/analysis/score", response_model=ScoreResponse)
def score(body: ScoreRequest, x_internal_token: str | None = Header(default=None)) -> ScoreResponse:
    require_internal_token(x_internal_token)
    try:
        value, scored = score_features({f.name: (f.history, f.current) for f in body.features})
    except InsufficientHistory as e:
        # 422: the request is well-formed, the subject simply has no usable baseline yet.
        raise HTTPException(
            status_code=422,
            detail={
                "code": "insufficient_history",
                "feature": e.feature,
                "points": e.points,
                "required": MIN_HISTORY_POINTS,
            },
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=422, detail={"code": "unscorable", "message": str(e)}) from e
    return ScoreResponse(
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_set_version=body.feature_set_version,
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        score=value,
        advisory=True,
        explanation=[
            Contribution(
                feature=f.feature,
                contribution=round(f.contribution, 4),
                current=f.current,
                median=f.median,
                mad=round(f.mad, 4),
                z=round(f.z, 4),
            )
            for f in scored
        ],
    )
