from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated process configuration. No defaults point at external services."""

    model_config = SettingsConfigDict(env_prefix="ANALYSIS_", extra="ignore")

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    environment: str = Field(default="development", pattern="^(development|test|production)$")
    version: str = "0.1.0-phase0"
    # Telemetry never leaves the deployment by default; an explicit opt-in is a Phase 6 decision.
    allow_external_model_apis: bool = False
    # Shared secret the API uses to call this service. Required outside development.
    internal_token: str | None = Field(default=None, min_length=24)

    def validate_for_environment(self) -> None:
        if self.environment == "production" and not self.internal_token:
            raise ValueError("ANALYSIS_INTERNAL_TOKEN is required in production")


settings = Settings()
