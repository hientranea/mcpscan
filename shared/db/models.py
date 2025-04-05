from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from sqlmodel import Field, SQLModel, Relationship, JSON, Column


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


class Package(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    name: str
    repo_url: str
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    versions: List["PackageVersion"] = Relationship(back_populates="package")


class PackageVersion(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    package_id: UUID = Field(foreign_key="package.id")
    version: str
    commit_hash: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    package: Package = Relationship(back_populates="versions")
    scan_jobs: List["ScanJob"] = Relationship(back_populates="package_version")


class ScanJob(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    package_version_id: Optional[UUID] = Field(
        default=None, foreign_key="packageversion.id"
    )
    repo_url: str
    status: ScanStatus = Field(default=ScanStatus.QUEUED)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    package_version: Optional[PackageVersion] = Relationship(back_populates="scan_jobs")
    scan_result: Optional["ScanResult"] = Relationship(back_populates="scan_job")


class ScanResult(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_job_id: UUID = Field(foreign_key="scanjob.id")
    score: int
    risk_level: RiskLevel
    score_explanation: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    scan_job: ScanJob = Relationship(back_populates="scan_result")
    findings: List["Finding"] = Relationship(back_populates="scan_result")
    vulnerabilities: List["Vulnerability"] = Relationship(back_populates="scan_result")


class Finding(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_result_id: UUID = Field(foreign_key="scanresult.id")
    type: str  # semgrep, dependency, etc.
    rule_id: Optional[str] = None
    severity: str
    message: str
    path: str
    line: Optional[int] = None
    meta_info: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))

    scan_result: ScanResult = Relationship(back_populates="findings")


class Vulnerability(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    scan_result_id: UUID = Field(foreign_key="scanresult.id")
    package_name: str
    vulnerable_version: str
    fixed_version: Optional[str] = None
    severity: str
    description: str
    references: List[str] = Field(default=[], sa_column=Column(JSON))

    scan_result: ScanResult = Relationship(back_populates="vulnerabilities")
