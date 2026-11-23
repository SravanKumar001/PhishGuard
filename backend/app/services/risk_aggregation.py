import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from app.schemas.risk import (
    AggregatedFinding,
    AssessmentStatus,
    EvidenceReference,
    EvidenceSourceType,
    RiskAssessment,
    URLRisk,
)

RULES_VERSION = "1.0.0"
_SEVERITY_WEIGHTS = {
    URLRisk.low: 1,
    URLRisk.medium: 3,
    URLRisk.high: 7,
    URLRisk.critical: 10,
}


class FindingLike(Protocol):
    rule_id: str
    title: str
    severity: URLRisk
    explanation: str
    evidence: dict[str, object]


@dataclass(frozen=True)
class FindingSource:
    source_id: str
    source_type: EvidenceSourceType
    findings: Sequence[FindingLike]


def _risk_level(findings: Sequence[AggregatedFinding]) -> URLRisk:
    high_count = sum(item.severity == URLRisk.high for item in findings)
    medium_count = sum(item.severity == URLRisk.medium for item in findings)
    low_count = sum(item.severity == URLRisk.low for item in findings)
    if any(item.severity == URLRisk.critical for item in findings):
        return URLRisk.critical
    if high_count >= 3 or (high_count >= 2 and medium_count >= 4):
        return URLRisk.critical
    if high_count >= 1 or medium_count >= 4:
        return URLRisk.high
    if medium_count >= 1 or low_count >= 3:
        return URLRisk.medium
    return URLRisk.low


def _finding_key(finding: FindingLike) -> tuple[str, str]:
    serialized_evidence = json.dumps(
        finding.evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return finding.rule_id, serialized_evidence


def aggregate_findings(sources: Sequence[FindingSource]) -> RiskAssessment:
    aggregated: dict[tuple[str, str], AggregatedFinding] = {}
    for source in sources:
        for index, finding in enumerate(source.findings):
            key = _finding_key(finding)
            reference = EvidenceReference(
                source_id=source.source_id,
                source_type=source.source_type,
                finding_index=index,
            )
            existing = aggregated.get(key)
            if existing is None:
                aggregated[key] = AggregatedFinding(
                    rule_id=finding.rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    explanation=finding.explanation,
                    evidence=finding.evidence,
                    evidence_references=[reference],
                )
            else:
                if _SEVERITY_WEIGHTS[finding.severity] > _SEVERITY_WEIGHTS[existing.severity]:
                    existing.severity = finding.severity
                    existing.explanation = finding.explanation
                if reference not in existing.evidence_references:
                    existing.evidence_references.append(reference)

    findings = sorted(
        aggregated.values(),
        key=lambda item: (
            -_SEVERITY_WEIGHTS[item.severity],
            item.rule_id,
            json.dumps(item.evidence, sort_keys=True, separators=(",", ":")),
        ),
    )
    if not sources:
        return RiskAssessment(
            rules_version=RULES_VERSION,
            status=AssessmentStatus.insufficient_evidence,
            risk_level=None,
            risk_points=0,
            findings=[],
            source_count=0,
            summary="No evidence was submitted for analysis.",
            uncertainty="No conclusion about safety can be drawn without evidence.",
            scoring_note="Risk points are transparent rule weights, not a probability.",
        )

    risk_level = _risk_level(findings)
    points = min(100, sum(_SEVERITY_WEIGHTS[item.severity] for item in findings))
    status = (
        AssessmentStatus.findings_present
        if findings
        else AssessmentStatus.no_indicators
    )
    summary = (
        f"{len(findings)} unique rule finding(s) require review."
        if findings
        else "No indicators were found by the configured local rules."
    )
    return RiskAssessment(
        rules_version=RULES_VERSION,
        status=status,
        risk_level=risk_level,
        risk_points=points,
        findings=findings,
        source_count=len(sources),
        summary=summary,
        uncertainty=(
            "No indicators are not proof of safety; external reputation and destination behavior were not checked."
        ),
        scoring_note=(
            "Points use fixed weights per unique finding (low=1, medium=3, high=7, critical=10), capped at 100. They are not a probability."
        ),
    )
