"""Pydantic request/response models for the diagnostic API."""

from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DiagnosticScope(BaseModel):
    """Optional scope to narrow the diagnosis."""
    servers: list[str] | None = None
    components: list[str] | None = None
    time_range: str | None = None


class DiagnoseRequest(BaseModel):
    """Request body for POST /api/v1/diagnose."""
    question: str
    scope: DiagnosticScope | None = None
    correlation_id: str | None = None
    max_steps: int = Field(default=20, ge=1, le=50)


class DiagnosticFinding(BaseModel):
    """A single diagnostic finding."""
    severity: Severity
    component: str
    server: str
    summary: str
    evidence: list[str] = Field(default_factory=list)


class DiagnoseResponse(BaseModel):
    """Response body for POST /api/v1/diagnose."""
    diagnosis_id: str
    question: str
    findings: list[DiagnosticFinding] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    root_cause: str = ""
    reasoning_trace: list[str] = Field(default_factory=list)
    llm_model: str = ""
    steps_taken: int = 0
    duration_seconds: float = 0.0


class HealthResponse(BaseModel):
    """Response body for GET /api/v1/health."""
    status: str
    ssh_connections: dict[str, bool] = Field(default_factory=dict)
    llm_provider: str = ""
    llm_model: str = ""
