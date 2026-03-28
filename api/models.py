from pydantic import BaseModel
from typing import Literal, Any
from enum import Enum


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    safe = "safe"


class SuspicionScore(BaseModel):
    package: str
    version: str
    score: int
    reasons: list[str]


class RuntimeReport(BaseModel):
    package: str
    networkCalls: list[dict] = []
    fileSystemWrites: list[dict] = []
    fileSystemReads: list[dict] = []
    envVarAccess: list[dict] = []
    cpuAnomaly: bool = False
    cpuUserRatioMax: float = 0.0
    errors: list[str] = []
    timestamp: int = 0


class ThreatReport(BaseModel):
    severity: Severity
    behaviors: list[str]
    summary: str
    explanation: str


class PackageResult(BaseModel):
    package: str
    version: str
    triage_score: int
    triage_reasons: list[str]
    severity: Severity | None = None
    behaviors: list[str] = []
    summary: str = ""
    explanation: str = ""
    runtime: RuntimeReport | None = None
    status: Literal["queued", "running", "complete", "error"] = "queued"
    error: str | None = None


class AuditRequest(BaseModel):
    package_json: dict[str, Any]


class AuditResponse(BaseModel):
    audit_id: str
    total_packages: int
    message: str


class AuditSummary(BaseModel):
    audit_id: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    safe: int
    error: int
