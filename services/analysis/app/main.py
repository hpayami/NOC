import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

from .config import settings

log = logging.getLogger("noc-analysis")
logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}')


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.validate_for_environment()
    log.info("noc-analysis starting (environment=%s)", settings.environment)
    yield


app = FastAPI(
    title="NOC Analysis Service",
    version=settings.version,
    description="Advisory security analytics. Phase 0 exposes health only; no models are loaded.",
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
    # Honest register: no models exist yet. Phase 6 adds versioned models with evaluation records.
    return AnalysisStatus(
        service="noc-analysis",
        environment=settings.environment,
        advisory_only=True,
        external_model_apis_allowed=settings.allow_external_model_apis,
        models=[],
    )
