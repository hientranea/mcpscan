from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, HttpUrl
from datetime import datetime


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ScanRequest(BaseModel):
    repo_url: HttpUrl


class ScanResponse(BaseModel):
    job_id: str
    status: ScanStatus
    message: str


class ScanResultSummary(BaseModel):
    score_explanation: str
    findings: Dict[str, int]
    risk_level: RiskLevel


class ScanResult(BaseModel):
    job_id: str
    status: ScanStatus
    repo_url: HttpUrl
    created_at: datetime
    completed_at: Optional[datetime] = None
    score: Optional[int] = None
    summary: Optional[ScanResultSummary] = None
    raw_results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class SemgrepFinding(BaseModel):
    rule_id: str
    message: str
    path: str
    line: int
    severity: str


class DependencyVulnerability(BaseModel):
    package_name: str
    vulnerable_version: str
    fixed_version: Optional[str]
    severity: str
    description: str
    references: List[str]


class ScanJob(BaseModel):
    job_id: str
    repo_url: HttpUrl
    status: ScanStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
