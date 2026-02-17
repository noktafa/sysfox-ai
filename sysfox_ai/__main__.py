"""Entry point: python -m sysfox_ai"""

import uvicorn

from sysfox_ai.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "sysfox_ai.app:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level="info",
    )
