"""Entry point: python -m sysfox_ai"""

import sys

import uvicorn

from sysfox_ai.config import settings, validate_settings

if __name__ == "__main__":
    missing = validate_settings()
    if missing:
        print(f"ERROR: Missing required config (set via env vars or .env):", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "sysfox_ai.app:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level="info",
    )
