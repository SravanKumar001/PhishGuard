from app.schemas.risk import (
    AssessmentStatus,
    EvidenceSourceType,
    URLRisk,
)
from app.schemas.url_analysis import URLFinding
from app.services.risk_aggregation import FindingSource, aggregate_findings


def _finding(severity: URLRisk) -> URLFinding:
    return URLFinding(
        rule_id="host.ip_address",
        title="IP-address hostname",
        severity=severity,
        explanation="The destination uses an IP address.",
        evidence={"hostname": "192.0.2.1"},
    )


def test_duplicate_findings_are_suppressed_but_retain_evidence_references() -> None:
    assessment = aggregate_findings(
        [
            FindingSource("url:0", EvidenceSourceType.url, [_finding(URLRisk.medium)]),
            FindingSource("email:links", EvidenceSourceType.url, [_finding(URLRisk.high)]),
        ]
    )

    assert assessment.status == AssessmentStatus.findings_present
    assert assessment.risk_level == URLRisk.high
    assert assessment.risk_points == 7
    assert len(assessment.findings) == 1
    assert assessment.findings[0].severity == URLRisk.high
    assert len(assessment.findings[0].evidence_references) == 2
    assert assessment.rules_version


def test_no_indicators_and_missing_sources_are_not_safety_claims() -> None:
    analyzed_empty = aggregate_findings(
        [FindingSource("url:0", EvidenceSourceType.url, [])]
    )
    missing = aggregate_findings([])

    assert analyzed_empty.status == AssessmentStatus.no_indicators
    assert analyzed_empty.risk_level == URLRisk.low
    assert "not proof of safety" in analyzed_empty.uncertainty
    assert missing.status == AssessmentStatus.insufficient_evidence
    assert missing.risk_level is None


def test_risk_points_are_deterministic_and_not_probability() -> None:
    sources = [
        FindingSource(
            "url:0",
            EvidenceSourceType.url,
            [_finding(URLRisk.low), _finding(URLRisk.medium)],
        )
    ]

    first = aggregate_findings(sources)
    second = aggregate_findings(sources)

    assert first.model_dump() == second.model_dump()
    assert first.risk_points == 3
    assert "not a probability" in first.scoring_note
