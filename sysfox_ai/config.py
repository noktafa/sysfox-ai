"""Pydantic Settings for sysfox-ai configuration."""

import os
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration via environment variables (or .env file)."""

    # --- LLM Provider ---
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o"

    # --- SSH ---
    SSH_USER: str = "root"
    SSH_KEY_PATH: str = str(Path.home() / ".ssh" / "id_rsa")
    SSH_CONNECT_TIMEOUT: int = 10
    SSH_COMMAND_TIMEOUT: int = 30

    # --- Dreamer Server IPs (public) — must be set via env vars or .env ---
    POC_LB_HOST: str = ""
    POC_APP1_HOST: str = ""
    POC_APP2_HOST: str = ""
    POC_RABBITMQ_HOST: str = ""
    POC_CONSUMER_HOST: str = ""
    POC_POSTGRESQL_HOST: str = ""
    POC_ELK_HOST: str = ""

    # --- Engine Limits ---
    MAX_DIAGNOSTIC_STEPS: int = 20
    MAX_OUTPUT_CHARS: int = 8000
    MAX_HISTORY_MESSAGES: int = 80

    # --- API ---
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # --- Logging ---
    LOG_DIR: str = str(Path.home() / ".sysfox-ai" / "logs")

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()


def validate_settings() -> list[str]:
    """Return list of missing required settings. Empty list means all OK."""
    missing = []
    if not settings.OPENAI_API_KEY:
        missing.append("OPENAI_API_KEY")
    host_fields = [
        "POC_LB_HOST", "POC_APP1_HOST", "POC_APP2_HOST",
        "POC_RABBITMQ_HOST", "POC_CONSUMER_HOST",
        "POC_POSTGRESQL_HOST", "POC_ELK_HOST",
    ]
    for field in host_fields:
        if not getattr(settings, field):
            missing.append(field)
    return missing
