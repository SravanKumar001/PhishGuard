from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

InvestigationStatus = Literal[
    "new",
    "investigating",
    "confirmed_phishing",
    "benign",
    "needs_review",
    "closed",
]


class InvestigationCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10_000)


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=10_000)
    status: InvestigationStatus | None = None


class InvestigationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
