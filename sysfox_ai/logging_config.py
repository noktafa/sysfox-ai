"""Structured JSONL logging — forked from sysadmin-ai.

Adapted for FastAPI: request-scoped correlation IDs, no K8s stderr logic.
"""

import os
import json
import logging
from datetime import datetime, timezone
from contextvars import ContextVar

from sysfox_ai.config import settings

# Request-scoped correlation ID
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(cid: str):
    _correlation_id.set(cid)


def get_correlation_id() -> str:
    return _correlation_id.get()


class JSONLFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects (JSONL)."""

    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": get_correlation_id(),
            "event": record.msg if isinstance(record.msg, str) else "unknown",
            "data": record.__dict__.get("data", {}),
        }
        return json.dumps(entry, default=str)


def setup_logging(log_dir=None):
    """Configure a JSONL file logger.

    Returns the logger instance. Logs write to:
    ``<log_dir>/sysfox_ai.jsonl``
    """
    log_dir = log_dir or settings.LOG_DIR
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, "sysfox_ai.jsonl")

    logger = logging.getLogger("sysfox_ai")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(JSONLFormatter())
    logger.addHandler(handler)

    return logger


def log_event(event, data=None):
    """Emit a structured log entry (with secret redaction)."""
    from sysfox_ai.safety import redact_data

    logger = logging.getLogger("sysfox_ai")
    record = logger.makeRecord(
        name="sysfox_ai",
        level=logging.INFO,
        fn="",
        lno=0,
        msg=event,
        args=(),
        exc_info=None,
    )
    record.data = redact_data(data or {})
    logger.handle(record)
