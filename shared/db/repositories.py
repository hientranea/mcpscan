from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from uuid import UUID
from sqlmodel import Session, select
from shared.db.models import (
    Package,
    PackageVersion,
    ScanJob,
    ScanResult,
    Finding,
    Vulnerability,
    ScanStatus,
    RiskLevel,
)


class PackageRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self, name: str, repo_url: str, description: Optional[str] = None
    ) -> Package:
        package = Package(name=name, repo_url=repo_url, description=description)
        self.session.add(package)
        self.session.commit()
        self.session.refresh(package)
        return package

    def get_by_id(self, package_id: UUID) -> Optional[Package]:
        return self.session.get(Package, package_id)

    def get_by_name(self, name: str) -> Optional[Package]:
        statement = select(Package).where(Package.name == name)
        results = self.session.exec(statement)
        return results.first()

    def get_by_repo_url(self, repo_url: str) -> Optional[Package]:
        statement = select(Package).where(Package.repo_url == repo_url)
        results = self.session.exec(statement)
        return results.first()

    def list_all(self, skip: int = 0, limit: int = 100) -> List[Package]:
        statement = select(Package).offset(skip).limit(limit)
        results = self.session.exec(statement)
        return results.all()


class PackageVersionRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self, package_id: UUID, version: str, commit_hash: Optional[str] = None
    ) -> PackageVersion:
        package_version = PackageVersion(
            package_id=package_id, version=version, commit_hash=commit_hash
        )
        self.session.add(package_version)
        self.session.commit()
        self.session.refresh(package_version)
        return package_version

    def get_by_id(self, version_id: UUID) -> Optional[PackageVersion]:
        return self.session.get(PackageVersion, version_id)

    def get_by_package_and_version(
        self, package_id: UUID, version: str
    ) -> Optional[PackageVersion]:
        statement = select(PackageVersion).where(
            (PackageVersion.package_id == package_id)
            & (PackageVersion.version == version)
        )
        results = self.session.exec(statement)
        return results.first()

    def list_versions_for_package(self, package_id: UUID) -> List[PackageVersion]:
        statement = select(PackageVersion).where(
            PackageVersion.package_id == package_id
        )
        results = self.session.exec(statement)
        return results.all()


class ScanJobRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self, repo_url: str, package_version_id: Optional[UUID] = None
    ) -> ScanJob:
        scan_job = ScanJob(
            repo_url=repo_url,
            package_version_id=package_version_id,
            status=ScanStatus.QUEUED,
        )
        self.session.add(scan_job)
        self.session.commit()
        self.session.refresh(scan_job)
        return scan_job

    def get_by_id(self, job_id: UUID) -> Optional[ScanJob]:
        return self.session.get(ScanJob, job_id)

    def update_status(
        self, job_id: UUID, status: ScanStatus, error: Optional[str] = None
    ) -> Optional[ScanJob]:
        job = self.get_by_id(job_id)
        if not job:
            return None

        job.status = status

        if status == ScanStatus.RUNNING and not job.started_at:
            job.started_at = datetime.utcnow()

        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            job.completed_at = datetime.utcnow()

        if error:
            job.error = error

        self.session.add(job)
        self.session.commit()
        self.session.refresh(job)
        return job

    def list_by_status(self, status: ScanStatus, limit: int = 100) -> List[ScanJob]:
        statement = select(ScanJob).where(ScanJob.status == status).limit(limit)
        results = self.session.exec(statement)
        return results.all()

    def list_by_package_version(self, package_version_id: UUID) -> List[ScanJob]:
        statement = select(ScanJob).where(
            ScanJob.package_version_id == package_version_id
        )
        results = self.session.exec(statement)
        return results.all()


class ScanResultRepository:
    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        scan_job_id: UUID,
        score: int,
        risk_level: RiskLevel,
        score_explanation: str,
    ) -> ScanResult:
        scan_result = ScanResult(
            scan_job_id=scan_job_id,
            score=score,
            risk_level=risk_level,
            score_explanation=score_explanation,
        )
        self.session.add(scan_result)
        self.session.commit()
        self.session.refresh(scan_result)
        return scan_result

    def get_by_id(self, result_id: UUID) -> Optional[ScanResult]:
        return self.session.get(ScanResult, result_id)

    def get_by_scan_job_id(self, scan_job_id: UUID) -> Optional[ScanResult]:
        statement = select(ScanResult).where(ScanResult.scan_job_id == scan_job_id)
        results = self.session.exec(statement)
        return results.first()


class FindingRepository:
    def __init__(self, session: Session):
        self.session = session

    def bulk_create(self, findings: List[Dict]) -> List[Finding]:
        # If any of the dictionaries contain 'metadata', rename it to 'meta_info'
        for finding in findings:
            if "metadata" in finding:
                finding["meta_info"] = finding.pop("metadata")

        finding_objects = [Finding(**finding) for finding in findings]
        self.session.add_all(finding_objects)
        self.session.commit()
        for finding in finding_objects:
            self.session.refresh(finding)
        return finding_objects

    def get_by_scan_result_id(self, scan_result_id: UUID) -> List[Finding]:
        statement = select(Finding).where(Finding.scan_result_id == scan_result_id)
        results = self.session.exec(statement)
        return results.all()


class VulnerabilityRepository:
    def __init__(self, session: Session):
        self.session = session

    def bulk_create(self, vulnerabilities: List[Dict]) -> List[Vulnerability]:
        vulnerability_objects = [Vulnerability(**vuln) for vuln in vulnerabilities]
        self.session.add_all(vulnerability_objects)
        self.session.commit()
        for vuln in vulnerability_objects:
            self.session.refresh(vuln)
        return vulnerability_objects

    def get_by_scan_result_id(self, scan_result_id: UUID) -> List[Vulnerability]:
        statement = select(Vulnerability).where(
            Vulnerability.scan_result_id == scan_result_id
        )
        results = self.session.exec(statement)
        return results.all()
