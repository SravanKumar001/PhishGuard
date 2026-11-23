import json
import socket
from pathlib import Path

import pytest

from app.analysis.url_analyzer import analyze_url
from app.schemas.risk import URLRisk

_CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "url_cases.json").read_text(encoding="utf-8")
)


def test_labeled_url_fixture_suite() -> None:
    for case in _CASES:
        result = analyze_url(case["url"])
        rule_ids = {finding.rule_id for finding in result.findings}

        assert result.risk_level.value == case["expected_risk"], case["id"]
        assert set(case["required_rules"]) <= rule_ids, case["id"]

def test_benign_url_uses_public_suffix_and_has_no_strong_indicators() -> None:
    result = analyze_url("https://www.example.co.uk/help")

    assert result.valid_syntax
    assert result.hostname == "www.example.co.uk"
    assert result.registrable_domain == "example.co.uk"
    assert result.risk_level == URLRisk.low
    assert result.findings == []


def test_ip_host_port_and_redirects_produce_explainable_high_risk() -> None:
    result = analyze_url(
        "http://192.0.2.10:8443/login?next=one&redirect=two"
    )
    rule_ids = {finding.rule_id for finding in result.findings}

    assert result.risk_level == URLRisk.high
    assert {"host.ip_address", "url.unusual_port", "url.redirect_parameters"} <= rule_ids
    assert result.registrable_domain is None
    assert result.limitations[1].startswith("No DNS")


def test_userinfo_brand_mismatch_and_sensitive_query_are_handled_safely() -> None:
    result = analyze_url(
        "https://paypal.com@evil.example/path?token=secret"
    )
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "url.userinfo" in rule_ids
    assert "secret" not in result.normalized_url
    assert "paypal.com@" not in result.normalized_url

    brand_result = analyze_url("https://paypal-login.example.com/login/verify")
    assert "host.brand_term_mismatch" in {
        finding.rule_id for finding in brand_result.findings
    }
    assert brand_result.risk_level == URLRisk.high


def test_mixed_script_and_invalid_url_are_reported_without_network_access() -> None:
    idn_result = analyze_url("https://раypal.com/")
    assert idn_result.valid_syntax
    assert idn_result.hostname.startswith("xn--")
    assert "host.mixed_script_lookalike" in {
        finding.rule_id for finding in idn_result.findings
    }

    punycode_result = analyze_url("https://xn--e1afmkfd.example.com/")
    assert "host.idn_punycode" in {
        finding.rule_id for finding in punycode_result.findings
    }

    invalid_result = analyze_url("javascript:alert(1)")
    assert not invalid_result.valid_syntax
    assert invalid_result.risk_level == URLRisk.medium
    assert any(finding.rule_id == "url.invalid_syntax" for finding in invalid_result.findings)


def test_combined_weak_signals_and_structural_encoding_are_reported() -> None:
    long_url = analyze_url(
        "http://a.b.c.d.e.example.com/" + "x" * 2050
    )
    long_rule_ids = {finding.rule_id for finding in long_url.findings}
    assert long_url.risk_level == URLRisk.medium
    assert "url.combined_weak_signals" in long_rule_ids
    assert "url.excessive_length" in long_rule_ids

    encoded_url = analyze_url("https://example.com/%00")
    assert "url.encoded_characters" in {
        finding.rule_id for finding in encoded_url.findings
    }


def test_analysis_does_not_resolve_or_fetch_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject_network(*args, **kwargs):
        raise AssertionError("URL analysis must not make network requests.")

    monkeypatch.setattr(socket, "getaddrinfo", reject_network)
    monkeypatch.setattr(socket, "create_connection", reject_network)

    result = analyze_url("https://example.com/")

    assert result.valid_syntax
