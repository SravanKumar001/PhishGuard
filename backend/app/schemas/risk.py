from enum import StrEnum

from pydantic import BaseModel


class URLRisk(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class EvidenceSourceType(StrEnum):
    url = "url"
    email_header = "email_header"
    email_body = "email_body"
    attachment = "attachment"


class AssessmentStatus(StrEnum):
    findings_present = "findings_present"
    no_indicators = "no_indicators"
    insufficient_evidence = "insufficient_evidence"


class EvidenceReference(BaseModel):
    source_id: str
    source_type: EvidenceSourceType
    finding_index: int


class AggregatedFinding(BaseModel):
    rule_id: str
    title: str
    severity: URLRisk
    explanation: str
    evidence: dict[str, object]
    evidence_references: list[EvidenceReference]


class RiskAssessment(BaseModel):
    rules_version: str
    status: AssessmentStatus
    risk_level: URLRisk | None
    risk_points: int
    findings: list[AggregatedFinding]
    source_count: int
    summary: str
    uncertainty: str
    scoring_note: str
