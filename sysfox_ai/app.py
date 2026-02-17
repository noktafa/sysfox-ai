"""FastAPI application — routes, lifespan (SSH pool + OpenAI client)."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from openai import OpenAI

from sysfox_ai.config import settings
from sysfox_ai.executor import SSHConnectionPool
from sysfox_ai.inventory import get_server_ips
from sysfox_ai.engine import DiagnosticEngine
from sysfox_ai.models import DiagnoseRequest, DiagnoseResponse, HealthResponse
from sysfox_ai.logging_config import setup_logging, set_correlation_id, log_event


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create OpenAI client + SSH pool. Shutdown: close pool."""
    # Setup logging
    setup_logging()

    # Create OpenAI client
    client = OpenAI(
        api_key=settings.OPENAI_API_KEY,
        base_url=settings.OPENAI_BASE_URL,
    )
    app.state.openai_client = client

    # Create SSH connection pool
    server_ips = get_server_ips()
    pool = SSHConnectionPool(server_ips)
    try:
        pool.connect_all()
    except Exception:
        pass  # Connections will be retried on first use
    app.state.ssh_pool = pool

    # Create diagnostic engine
    app.state.engine = DiagnosticEngine(client=client, ssh_pool=pool)

    log_event("app_start", {
        "llm_model": settings.OPENAI_MODEL,
        "llm_base_url": settings.OPENAI_BASE_URL,
        "servers": list(server_ips.keys()),
    })

    yield

    # Shutdown
    pool.close_all()
    log_event("app_shutdown", {})


app = FastAPI(
    title="sysfox-ai",
    description="Diagnostic agent for Dreamer banking infrastructure",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Inject a correlation ID for request-scoped logging."""
    cid = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    set_correlation_id(cid)
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = cid
    return response


@app.post("/api/v1/diagnose", response_model=DiagnoseResponse)
async def diagnose(request: DiagnoseRequest):
    """Run a diagnostic session against the dreamer infrastructure."""
    if request.correlation_id:
        set_correlation_id(request.correlation_id)

    log_event("diagnose_request", {
        "question": request.question,
        "max_steps": request.max_steps,
    })

    engine: DiagnosticEngine = app.state.engine
    response = engine.run(request)
    return response


@app.get("/api/v1/health", response_model=HealthResponse)
async def health():
    """Check SSH connectivity and LLM provider status."""
    pool: SSHConnectionPool = app.state.ssh_pool
    ssh_status = pool.check_connectivity()

    all_connected = all(ssh_status.values())
    status = "healthy" if all_connected else "degraded"

    return HealthResponse(
        status=status,
        ssh_connections=ssh_status,
        llm_provider=settings.OPENAI_BASE_URL,
        llm_model=settings.OPENAI_MODEL,
    )
