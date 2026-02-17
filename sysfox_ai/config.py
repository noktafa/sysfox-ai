"""Pydantic Settings for sysfox-ai configuration."""

import os
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration via environment variables (or .env file)."""

    # --- LLM Provider ---
    OPENAI_API_KEY: str = "dummy"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o"

    # --- SSH ---
    SSH_USER: str = "root"
    SSH_KEY_PATH: str = str(Path.home() / ".ssh" / "id_rsa")
    SSH_CONNECT_TIMEOUT: int = 10
    SSH_COMMAND_TIMEOUT: int = 30

    # --- Dreamer Server IPs (public) ---
    POC_LB_HOST: str = "46.101.153.18"
    POC_APP1_HOST: str = "46.101.238.171"
    POC_APP2_HOST: str = "139.59.153.72"
    POC_RABBITMQ_HOST: str = "46.101.230.91"
    POC_CONSUMER_HOST: str = "46.101.141.153"
    POC_POSTGRESQL_HOST: str = "167.71.52.146"
    POC_ELK_HOST: str = "46.101.180.12"

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
