import json
from io import BytesIO
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.email_analyzer import (
    MAX_EMAIL_BYTES,
    EmailTooLargeError,
    build_email_finding_sources,
)
from app.analysis.email_analyzer import (
    analyze_email as run_email_analysis,
)
from app.analysis.url_analyzer import analyze_url as run_url_analysis
from app.api.dependencies import get_current_user
from app.db.session import get_db
from app.models import (
    AuditEvent,
    DetectionFinding,
    Investigation,
    InvestigationNote,
    Report,
    Submission,
    User,
)
from app.schemas.combined_analysis import CombinedAnalysisRead, CombinedAnalysisRequest
from app.schemas.email_analysis import EmailAnalysisRead, EmailAnalysisRequest
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationRead,
    InvestigationStatus,
    InvestigationUpdate,
)
from app.schemas.risk import EvidenceSourceType
from app.schemas.url_analysis import URLAnalysisRead, URLAnalysisRequest
from app.schemas.workflow import (
    DashboardStatsRead,
    FindingRead,
    InvestigationAnalysisRead,
    InvestigationListRead,
    InvestigationNoteCreate,
    InvestigationNoteRead,
    ReportRead,
    SubmissionRead,
)
from app.services.investigation_workflow import persist_analysis
from app.services.risk_aggregation import FindingSource, aggregate_findings

router = APIRouter(prefix="/api")
_INVESTIGATION_STATUSES: tuple[InvestigationStatus, ...] = (
    "new",
    "investigating",
    "confirmed_phishing",
    "benign",
    "needs_review",
    "closed",
)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "PhishGuard API"}


@router.post("/analyze/url", response_model=URLAnalysisRead)
def analyze_url(
    payload: URLAnalysisRequest,
    _user: Annotated[User, Depends(get_current_user)],
) -> URLAnalysisRead:
    return run_url_analysis(payload.url)


@router.post("/analyze/email", response_model=EmailAnalysisRead)
def analyze_email(
    payload: EmailAnalysisRequest,
    _user: Annotated[User, Depends(get_current_user)],
) -> EmailAnalysisRead:
    try:
        return run_email_analysis(payload.raw_email)
    except EmailTooLargeError as error:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(error),
        ) from error


@router.post("/analyze/email/file", response_model=EmailAnalysisRead)
async def analyze_email_file(
    _user: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
) -> EmailAnalysisRead:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        await file.close()
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .eml files are supported.",
        )
    try:
        raw_email = await file.read(MAX_EMAIL_BYTES + 1)
    finally:
        await file.close()
    if len(raw_email) > MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Email message exceeds the {MAX_EMAIL_BYTES}-byte limit.",
        )
    return run_email_analysis(raw_email)


@router.post("/analyze", response_model=CombinedAnalysisRead)
def analyze_combined(
    payload: CombinedAnalysisRequest,
    _user: Annotated[User, Depends(get_current_user)],
) -> CombinedAnalysisRead:
    return _run_combined_analysis(payload)


def _run_combined_analysis(payload: CombinedAnalysisRequest) -> CombinedAnalysisRead:
    url_results = [run_url_analysis(url) for url in payload.urls]
    email_result = None
    if payload.raw_email is not None:
        try:
            email_result = run_email_analysis(payload.raw_email)
        except EmailTooLargeError as error:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=str(error),
            ) from error

    sources = [
        FindingSource(
            source_id=f"url:{index}",
            source_type=EvidenceSourceType.url,
            findings=result.findings,
        )
        for index, result in enumerate(url_results)
    ]
    if email_result is not None:
        sources.extend(build_email_finding_sources(email_result.findings))
    assessment = aggregate_findings(sources)
    return CombinedAnalysisRead(
        url_results=url_results,
        email_result=email_result,
        risk_assessment=assessment,
    )


def _run_combined_with_email(
    email_result: EmailAnalysisRead,
) -> CombinedAnalysisRead:
    assessment = aggregate_findings(build_email_finding_sources(email_result.findings))
    return CombinedAnalysisRead(
        url_results=[],
        email_result=email_result,
        risk_assessment=assessment,
    )


def _owned_investigation(
    db: Session,
    user: User,
    investigation_id: str,
) -> Investigation:
    investigation = db.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.user_id == user.id,
        )
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


@router.post(
    "/investigations",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation(
    payload: InvestigationCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Investigation:
    investigation = Investigation(
        user_id=user.id,
        title=payload.title.strip(),
        description=payload.description,
    )
    if not investigation.title:
        raise HTTPException(status_code=422, detail="Title must not be blank.")
    db.add(investigation)
    db.flush()
    db.add(
        AuditEvent(
            investigation_id=investigation.id,
            actor_id=user.id,
            action="investigation.created",
            entity_type="investigation",
            entity_id=investigation.id,
        )
    )
    db.commit()
    db.refresh(investigation)
    return investigation


@router.post(
    "/investigations/{investigation_id}/analyze",
    response_model=InvestigationAnalysisRead,
    status_code=status.HTTP_201_CREATED,
)
def analyze_investigation(
    investigation_id: str,
    payload: CombinedAnalysisRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> InvestigationAnalysisRead:
    investigation = _owned_investigation(db, user, investigation_id)
    analysis = _run_combined_analysis(payload)
    submissions, report = persist_analysis(db, investigation, user.id, analysis)
    db.commit()
    return InvestigationAnalysisRead(
        **analysis.model_dump(),
        investigation_id=investigation.id,
        submission_ids=[submission.id for submission in submissions],
        report_id=report.id,
    )


@router.post(
    "/investigations/{investigation_id}/analyze/email/file",
    response_model=InvestigationAnalysisRead,
    status_code=status.HTTP_201_CREATED,
)
async def analyze_investigation_email_file(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
) -> InvestigationAnalysisRead:
    investigation = _owned_investigation(db, user, investigation_id)
    if not file.filename or not file.filename.lower().endswith(".eml"):
        await file.close()
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .eml files are supported.",
        )
    try:
        raw_email = await file.read(MAX_EMAIL_BYTES + 1)
    finally:
        await file.close()
    if len(raw_email) > MAX_EMAIL_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Email message exceeds the {MAX_EMAIL_BYTES}-byte limit.",
        )

    analysis = _run_combined_with_email(run_email_analysis(raw_email))
    submissions, report = persist_analysis(db, investigation, user.id, analysis)
    db.commit()
    return InvestigationAnalysisRead(
        **analysis.model_dump(),
        investigation_id=investigation.id,
        submission_ids=[submission.id for submission in submissions],
        report_id=report.id,
    )


@router.get("/investigations", response_model=InvestigationListRead)
def list_investigations(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    status_filter: Annotated[InvestigationStatus | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=160)] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> InvestigationListRead:
    filters = [Investigation.user_id == user.id]
    if status_filter is not None:
        filters.append(Investigation.status == status_filter)
    if q is not None and q.strip():
        search = f"%{q.strip()}%"
        filters.append(
            (Investigation.title.ilike(search))
            | (Investigation.description.ilike(search))
        )

    total = db.scalar(
        select(func.count()).select_from(Investigation).where(*filters)
    ) or 0
    statement = (
        select(Investigation)
        .where(*filters)
        .order_by(Investigation.created_at.desc(), Investigation.id)
        .offset(offset)
        .limit(limit)
    )
    return InvestigationListRead(
        items=list(db.scalars(statement)),
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/dashboard/stats", response_model=DashboardStatsRead)
def dashboard_stats(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> DashboardStatsRead:
    status_counts = {
        row[0]: row[1]
        for row in db.execute(
            select(Investigation.status, func.count())
            .where(Investigation.user_id == user.id)
            .group_by(Investigation.status)
        )
    }
    severity_counts = {
        row[0]: row[1]
        for row in db.execute(
            select(DetectionFinding.severity, func.count())
            .join(Investigation, Investigation.id == DetectionFinding.investigation_id)
            .where(Investigation.user_id == user.id)
            .group_by(DetectionFinding.severity)
        )
    }
    return DashboardStatsRead(
        investigation_count=sum(status_counts.values()),
        investigations_by_status={
            value: status_counts.get(value, 0) for value in _INVESTIGATION_STATUSES
        },
        findings_by_severity={
            "low": severity_counts.get("low", 0),
            "medium": severity_counts.get("medium", 0),
            "high": severity_counts.get("high", 0),
            "critical": severity_counts.get("critical", 0),
        },
    )


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
def get_investigation(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Investigation:
    return _owned_investigation(db, user, investigation_id)


@router.patch("/investigations/{investigation_id}", response_model=InvestigationRead)
def update_investigation(
    investigation_id: str,
    payload: InvestigationUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Investigation:
    investigation = _owned_investigation(db, user, investigation_id)
    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=422, detail="At least one field must be provided.")
    if any(field in updates and updates[field] is None for field in ("title", "status")):
        raise HTTPException(status_code=422, detail="Title and status cannot be null.")
    if "title" in updates:
        updates["title"] = updates["title"].strip()
        if not updates["title"]:
            raise HTTPException(status_code=422, detail="Title must not be blank.")
    for field, value in updates.items():
        setattr(investigation, field, value)
    db.add(
        AuditEvent(
            investigation_id=investigation.id,
            actor_id=user.id,
            action="investigation.updated",
            entity_type="investigation",
            entity_id=investigation.id,
            details={"fields": sorted(updates)},
        )
    )
    db.commit()
    db.refresh(investigation)
    return investigation


@router.delete("/investigations/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    investigation = _owned_investigation(db, user, investigation_id)
    db.delete(investigation)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/investigations/{investigation_id}/submissions",
    response_model=list[SubmissionRead],
)
def list_submissions(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[Submission]:
    _owned_investigation(db, user, investigation_id)
    return list(
        db.scalars(
            select(Submission)
            .where(Submission.investigation_id == investigation_id)
            .order_by(Submission.created_at, Submission.id)
        )
    )


@router.get(
    "/investigations/{investigation_id}/findings",
    response_model=list[FindingRead],
)
def list_findings(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[DetectionFinding]:
    _owned_investigation(db, user, investigation_id)
    return list(
        db.scalars(
            select(DetectionFinding)
            .where(DetectionFinding.investigation_id == investigation_id)
            .order_by(DetectionFinding.created_at, DetectionFinding.id)
        )
    )


@router.post(
    "/investigations/{investigation_id}/notes",
    response_model=InvestigationNoteRead,
    status_code=status.HTTP_201_CREATED,
)
def create_investigation_note(
    investigation_id: str,
    payload: InvestigationNoteCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> InvestigationNote:
    investigation = _owned_investigation(db, user, investigation_id)
    body = payload.body.strip()
    if not body:
        raise HTTPException(status_code=422, detail="Note must not be blank.")
    note = InvestigationNote(investigation_id=investigation.id, body=body)
    db.add(note)
    db.add(
        AuditEvent(
            investigation_id=investigation.id,
            actor_id=user.id,
            action="note.created",
            entity_type="investigation_note",
            details={},
        )
    )
    db.commit()
    db.refresh(note)
    return note


@router.get(
    "/investigations/{investigation_id}/notes",
    response_model=list[InvestigationNoteRead],
)
def list_investigation_notes(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> list[InvestigationNote]:
    _owned_investigation(db, user, investigation_id)
    return list(
        db.scalars(
            select(InvestigationNote)
            .where(InvestigationNote.investigation_id == investigation_id)
            .order_by(InvestigationNote.created_at, InvestigationNote.id)
        )
    )


@router.get(
    "/investigations/{investigation_id}/reports/latest",
    response_model=ReportRead,
)
def get_latest_report(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Report:
    _owned_investigation(db, user, investigation_id)
    report = db.scalar(
        select(Report)
        .where(Report.investigation_id == investigation_id)
        .order_by(Report.created_at.desc(), Report.id.desc())
        .limit(1)
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.get("/investigations/{investigation_id}/reports/{report_id}/download")
def download_report(
    investigation_id: str,
    report_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    _owned_investigation(db, user, investigation_id)
    report = db.scalar(
        select(Report).where(
            Report.id == report_id,
            Report.investigation_id == investigation_id,
        )
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return Response(
        content=json.dumps(report.payload, indent=2, sort_keys=True),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="phishguard-report-{report.id}.json"'
        },
    )


@router.get(
    "/investigations/{investigation_id}/reports/{report_id}/download.pdf"
)
def download_pdf_report(
    investigation_id: str,
    report_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
) -> Response:
    _owned_investigation(db, user, investigation_id)
    report = db.scalar(
        select(Report).where(
            Report.id == report_id,
            Report.investigation_id == investigation_id,
        )
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")

    pdf_buffer = BytesIO()
    pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter
    y = height - 54

    pdf.setTitle("PhishGuard Investigation Report")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(54, y, "PhishGuard Investigation Report")
    y -= 30

    assessment = report.payload.get("risk_assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}
    pdf.setFont("Helvetica", 10)
    pdf.drawString(54, y, f"Report ID: {report.id}")
    y -= 16
    pdf.drawString(54, y, f"Rules version: {assessment.get('rules_version', 'unknown')}")
    y -= 16
    pdf.drawString(54, y, f"Risk level: {assessment.get('risk_level') or 'undetermined'}")
    y -= 16
    pdf.drawString(54, y, f"Risk points: {assessment.get('risk_points', 0)}")
    y -= 24

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(54, y, "Findings")
    y -= 18
    pdf.setFont("Helvetica", 9)

    findings = assessment.get("findings", [])
    if not isinstance(findings, list) or not findings:
        pdf.drawString(54, y, "No findings were recorded.")
        y -= 14
    else:
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if y < 72:
                pdf.showPage()
                y = height - 54
                pdf.setFont("Helvetica", 9)
            title = str(finding.get("title", "Unnamed finding"))
            severity = str(finding.get("severity", "unknown")).upper()
            pdf.setFont("Helvetica-Bold", 9)
            pdf.drawString(54, y, f"[{severity}] {title[:90]}")
            y -= 13
            explanation = str(finding.get("explanation", ""))
            words = explanation.split()
            line = ""
            pdf.setFont("Helvetica", 9)
            for word in words:
                candidate = f"{line} {word}".strip()
                if pdf.stringWidth(candidate, "Helvetica", 9) > width - 108:
                    pdf.drawString(54, y, line)
                    y -= 12
                    line = word
                    if y < 72:
                        pdf.showPage()
                        y = height - 54
                else:
                    line = candidate
            if line:
                pdf.drawString(54, y, line)
                y -= 16

    if y < 96:
        pdf.showPage()
        y = height - 54
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(54, y, "Limitations")
    y -= 16
    pdf.setFont("Helvetica", 9)
    limitations = (
        "Deterministic heuristic assessment, not a calibrated probability or proof of safety.",
        "No live DNS, reputation, webpage, redirect, attachment execution, or third-party AI checks.",
        "Raw email bodies and embedded URLs are not included in persisted report payloads.",
    )
    for limitation in limitations:
        pdf.drawString(54, y, limitation[:105])
        y -= 14

    pdf.save()
    pdf_bytes = pdf_buffer.getvalue()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="phishguard-report-{report.id}.pdf"'
        },
    )
