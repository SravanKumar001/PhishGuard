from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from app.models import (
    AuditEvent,
    DetectionFinding,
    ExtractedIndicator,
    Investigation,
    Report,
    Submission,
)
from app.schemas.combined_analysis import CombinedAnalysisRead


def persist_analysis(
    db: Session,
    investigation: Investigation,
    actor_id: str,
    analysis: CombinedAnalysisRead,
) -> tuple[list[Submission], Report]:
    submissions: list[Submission] = []
    submission_by_source: dict[str, Submission] = {}
    seen_indicators: set[tuple[str, str]] = set()

    for index, result in enumerate(analysis.url_results):
        submission = Submission(
            investigation_id=investigation.id,
            kind="url",
            content=result.normalized_url,
        )
        db.add(submission)
        db.flush()
        submissions.append(submission)
        submission_by_source[f"url:{index}"] = submission

        if result.hostname:
            try:
                ipaddress.ip_address(result.hostname)
                indicator_kind = "ip"
            except ValueError:
                indicator_kind = "domain"
            _add_indicator(
                db,
                investigation,
                submission,
                indicator_kind,
                result.hostname,
                seen_indicators,
            )
        if result.registrable_domain:
            _add_indicator(
                db,
                investigation,
                submission,
                "domain",
                result.registrable_domain,
                seen_indicators,
            )

    email_result = analysis.email_result
    if email_result is not None:
        submission = Submission(
            investigation_id=investigation.id,
            kind="email",
            content="Email analyzed; raw message content is not retained.",
        )
        db.add(submission)
        db.flush()
        submissions.append(submission)
        for source_type in ("email_header", "email_body", "attachment", "url"):
            submission_by_source[f"email:{source_type}"] = submission

        sender_domains = {
            address.address.rpartition("@")[2].lower().rstrip(".")
            for address in email_result.from_addresses
            if "@" in address.address
        }
        for domain in sorted(sender_domains):
            _add_indicator(
                db,
                investigation,
                submission,
                "domain",
                domain,
                seen_indicators,
            )

    db.flush()
    for finding in analysis.risk_assessment.findings:
        source_id = (
            finding.evidence_references[0].source_id
            if finding.evidence_references
            else None
        )
        submission = submission_by_source.get(source_id) if source_id else None
        db.add(
            DetectionFinding(
                investigation_id=investigation.id,
                submission_id=submission.id if submission else None,
                rule_id=finding.rule_id,
                severity=finding.severity.value,
                title=finding.title,
                explanation=finding.explanation,
                evidence={
                    "details": finding.evidence,
                    "evidence_references": [
                        reference.model_dump(mode="json")
                        for reference in finding.evidence_references
                    ],
                },
            )
        )

    email_summary = None
    if email_result is not None:
        email_summary = {
            "sender_domains": sorted(
                {
                    address.address.rpartition("@")[2].lower().rstrip(".")
                    for address in email_result.from_addresses
                    if "@" in address.address
                }
            ),
            "attachment_count": len(email_result.attachments),
            "link_count": len(email_result.links),
            "risk_level": email_result.risk_level.value,
            "findings": [
                finding.model_dump(mode="json") for finding in email_result.findings
            ],
            "uncertainty": email_result.uncertainty,
        }
    report_payload: dict[str, object] = {
        "rules_version": analysis.risk_assessment.rules_version,
        "risk_assessment": analysis.risk_assessment.model_dump(mode="json"),
        "url_results": [
            {
                "normalized_url": result.normalized_url,
                "hostname": result.hostname,
                "registrable_domain": result.registrable_domain,
                "risk_level": result.risk_level.value,
                "uncertainty": result.uncertainty,
                "findings": [
                    finding.model_dump(mode="json") for finding in result.findings
                ],
            }
            for result in analysis.url_results
        ],
        "email_summary": email_summary,
        "retention_note": (
            "Raw email bodies, headers, and embedded link URLs are not retained."
        ),
    }
    report = Report(
        investigation_id=investigation.id,
        format="json",
        payload=report_payload,
    )
    db.add(report)
    db.add(
        AuditEvent(
            investigation_id=investigation.id,
            actor_id=actor_id,
            action="analysis.persisted",
            entity_type="report",
            details={
                "url_count": len(analysis.url_results),
                "email_present": email_result is not None,
                "finding_count": len(analysis.risk_assessment.findings),
            },
        )
    )
    db.flush()
    return submissions, report


def _add_indicator(
    db: Session,
    investigation: Investigation,
    submission: Submission,
    kind: str,
    value: str,
    seen: set[tuple[str, str]],
) -> None:
    normalized = value.casefold()
    key = (kind, normalized)
    if key in seen:
        return
    seen.add(key)
    db.add(
        ExtractedIndicator(
            investigation_id=investigation.id,
            submission_id=submission.id,
            kind=kind,
            value=value,
            normalized_value=normalized,
        )
    )
