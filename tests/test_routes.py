"""FastAPI route tests — TestClient for API endpoints."""

import pytest
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from sysfox_ai.models import DiagnoseRequest, DiagnoseResponse, DiagnosticFinding, Severity, HealthResponse
from sysfox_ai.executor import SSHConnectionPool
from sysfox_ai.engine import DiagnosticEngine
from sysfox_ai.logging_config import set_correlation_id


@pytest.fixture
def mock_ssh_pool():
    pool = MagicMock(spec=SSHConnectionPool)
    pool.check_connectivity.return_value = {
        "poc-lb": True,
        "poc-app1": True,
        "poc-app2": True,
        "poc-rabbitmq": True,
        "poc-consumer": True,
        "poc-postgresql": True,
        "poc-elk": True,
    }
    return pool


@pytest.fixture
def mock_engine():
    engine = MagicMock(spec=DiagnosticEngine)
    engine.run.return_value = DiagnoseResponse(
        diagnosis_id="test-id",
        question="test question",
        findings=[DiagnosticFinding(
            severity=Severity.LOW,
            component="system",
            server="all",
            summary="All healthy",
            evidence=["test"],
        )],
        affected_components=[],
        root_cause="No issues",
        reasoning_trace=["Step 1: checked"],
        llm_model="gpt-4o",
        steps_taken=1,
        duration_seconds=1.5,
    )
    return engine


def _build_test_app(mock_ssh_pool, mock_engine):
    """Build a self-contained test app with mocked dependencies."""

    @asynccontextmanager
    async def test_lifespan(app: FastAPI):
        app.state.ssh_pool = mock_ssh_pool
        app.state.openai_client = MagicMock()
        app.state.engine = mock_engine
        yield

    test_app = FastAPI(lifespan=test_lifespan)

    @test_app.middleware("http")
    async def cid_middleware(request: Request, call_next):
        import uuid
        cid = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        set_correlation_id(cid)
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = cid
        return response

    @test_app.post("/api/v1/diagnose", response_model=DiagnoseResponse)
    async def diagnose(request: DiagnoseRequest):
        if request.correlation_id:
            set_correlation_id(request.correlation_id)
        engine = test_app.state.engine
        return engine.run(request)

    @test_app.get("/api/v1/health", response_model=HealthResponse)
    async def health():
        pool = test_app.state.ssh_pool
        ssh_status = pool.check_connectivity()
        all_connected = all(ssh_status.values())
        from sysfox_ai.config import settings
        return HealthResponse(
            status="healthy" if all_connected else "degraded",
            ssh_connections=ssh_status,
            llm_provider=settings.OPENAI_BASE_URL,
            llm_model=settings.OPENAI_MODEL,
        )

    return test_app


@pytest.fixture
def client(mock_ssh_pool, mock_engine):
    test_app = _build_test_app(mock_ssh_pool, mock_engine)
    with TestClient(test_app) as tc:
        yield tc


class TestHealthEndpoint:
    """Test GET /api/v1/health."""

    def test_health_returns_status(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert "ssh_connections" in data
        assert data["llm_model"] != ""

    def test_health_degraded(self, client, mock_ssh_pool):
        mock_ssh_pool.check_connectivity.return_value = {
            "poc-lb": True,
            "poc-app1": False,
            "poc-app2": True,
            "poc-rabbitmq": True,
            "poc-consumer": True,
            "poc-postgresql": True,
            "poc-elk": True,
        }
        response = client.get("/api/v1/health")
        data = response.json()
        assert data["status"] == "degraded"
        assert data["ssh_connections"]["poc-app1"] is False


class TestDiagnoseEndpoint:
    """Test POST /api/v1/diagnose."""

    def test_diagnose_basic(self, client):
        response = client.post(
            "/api/v1/diagnose",
            json={"question": "Is the system healthy?"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["diagnosis_id"] == "test-id"
        assert data["question"] == "test question"
        assert len(data["findings"]) == 1
        assert data["root_cause"] == "No issues"

    def test_diagnose_with_scope(self, client):
        response = client.post(
            "/api/v1/diagnose",
            json={
                "question": "Why is nginx slow?",
                "scope": {
                    "servers": ["poc-lb"],
                    "components": ["nginx_lb"],
                    "time_range": "last 1 hour"
                },
                "max_steps": 10,
            }
        )
        assert response.status_code == 200

    def test_diagnose_with_correlation_id(self, client):
        response = client.post(
            "/api/v1/diagnose",
            json={
                "question": "Trace request abc-123",
                "correlation_id": "abc-123",
            }
        )
        assert response.status_code == 200

    def test_diagnose_missing_question(self, client):
        response = client.post("/api/v1/diagnose", json={})
        assert response.status_code == 422

    def test_diagnose_max_steps_validation(self, client):
        response = client.post(
            "/api/v1/diagnose",
            json={"question": "test", "max_steps": 0}
        )
        assert response.status_code == 422

    def test_correlation_id_header(self, client):
        response = client.get(
            "/api/v1/health",
            headers={"X-Correlation-ID": "my-trace-id"}
        )
        assert response.status_code == 200
        assert "X-Correlation-ID" in response.headers
