from pydantic import BaseModel, Field

from app.schemas.risk import RiskAssessment, URLRisk


class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=1_000_000)


class EmailAddress(BaseModel):
    display_name: str
    address: str


class EmailLink(BaseModel):
    url: str
    display_text: str | None = None


class EmailAttachmentMetadata(BaseModel):
    filename: str | None
    content_type: str
    disposition: str | None
    size_bytes: int
    dangerous_extension: bool


class AuthenticationEvidence(BaseModel):
    authserv_id: str
    header_value: str
    trusted: bool


class EmailFinding(BaseModel):
    rule_id: str
    title: str
    severity: URLRisk
    explanation: str
    evidence: dict[str, object]


class EmailAnalysisRead(BaseModel):
    from_addresses: list[EmailAddress]
    reply_to: list[EmailAddress]
    return_path: list[EmailAddress]
    to: list[EmailAddress]
    subject: str | None
    date: str | None
    received_headers: list[str]
    authentication_results: list[AuthenticationEvidence]
    message_id: str | None
    text_body: str
    links: list[EmailLink]
    attachments: list[EmailAttachmentMetadata]
    risk_level: URLRisk
    uncertainty: str
    findings: list[EmailFinding]
    risk_assessment: RiskAssessment
    recommended_actions: list[str]
    limitations: list[str]
