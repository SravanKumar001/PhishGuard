from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.combined_analysis import CombinedAnalysisRead
from app.schemas.investigation import InvestigationRead
from app.schemas.risk import URLRisk


class InvestigationListRead(BaseModel):
    items: list[InvestigationRead]
    total: int
    offset: int
    limit: int


class SubmissionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    content: str
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    submission_id: str | None
    rule_id: str
    severity: URLRisk
    title: str
    explanation: str
    evidence: dict[str, object]
    created_at: datetime


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    format: str
    payload: dict[str, object]
    created_at: datetime


class InvestigationNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class InvestigationNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    body: str
    created_at: datetime


class UserPreferencesUpdate(BaseModel):
    theme: Literal["system", "light", "dark"] = "system"
    compact_mode: bool = False


class UserPreferencesRead(UserPreferencesUpdate):
    updated_at: datetime | None = None


class DashboardStatsRead(BaseModel):
    investigation_count: int
    investigations_by_status: dict[str, int]
    findings_by_severity: dict[str, int]


class InvestigationAnalysisRead(CombinedAnalysisRead):
    investigation_id: str
    submission_ids: list[str]
    report_id: str
