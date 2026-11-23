from pydantic import BaseModel, Field

from app.schemas.risk import RiskAssessment, URLRisk


class URLAnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class URLFinding(BaseModel):
    rule_id: str
    title: str
    severity: URLRisk
    explanation: str
    evidence: dict[str, object]


class URLAnalysisRead(BaseModel):
    normalized_url: str
    valid_syntax: bool
    hostname: str | None
    registrable_domain: str | None
    risk_level: URLRisk
    uncertainty: str
    findings: list[URLFinding]
    risk_assessment: RiskAssessment
    recommended_actions: list[str]
    limitations: list[str]
