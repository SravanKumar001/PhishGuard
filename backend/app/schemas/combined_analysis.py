from typing import Annotated

from pydantic import BaseModel, Field, model_validator

from app.schemas.email_analysis import EmailAnalysisRead
from app.schemas.risk import RiskAssessment
from app.schemas.url_analysis import URLAnalysisRead


class CombinedAnalysisRequest(BaseModel):
    urls: list[Annotated[str, Field(min_length=1, max_length=4096)]] = Field(
        default_factory=list,
        max_length=50,
    )
    raw_email: str | None = Field(default=None, min_length=1, max_length=1_000_000)

    @model_validator(mode="after")
    def require_evidence(self) -> "CombinedAnalysisRequest":
        if not self.urls and self.raw_email is None:
            raise ValueError("Provide at least one URL or an email message.")
        return self


class CombinedAnalysisRead(BaseModel):
    url_results: list[URLAnalysisRead]
    email_result: EmailAnalysisRead | None
    risk_assessment: RiskAssessment
