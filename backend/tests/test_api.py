import pytest
from fastapi.testclient import TestClient


def test_health_endpoint_returns_service_status(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "PhishGuard API"}


def test_investigation_crud(authenticated_client: TestClient) -> None:
    created = authenticated_client.post(
        "/api/investigations",
        json={"title": "Suspicious message", "description": "Review sender and links."},
    )
    assert created.status_code == 201
    investigation = created.json()
    investigation_id = investigation["id"]
    assert investigation["status"] == "new"

    listing = authenticated_client.get("/api/investigations")
    assert [item["id"] for item in listing.json()["items"]] == [investigation_id]

    updated = authenticated_client.patch(
        f"/api/investigations/{investigation_id}",
        json={"status": "investigating", "title": "Message review"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert updated.json()["title"] == "Message review"

    deleted = authenticated_client.delete(f"/api/investigations/{investigation_id}")
    assert deleted.status_code == 204
    assert authenticated_client.get(f"/api/investigations/{investigation_id}").status_code == 404


@pytest.mark.parametrize(
    "title",
    ["   ", "x" * 161],
)
def test_invalid_title_is_rejected(authenticated_client: TestClient, title: str) -> None:
    response = authenticated_client.post("/api/investigations", json={"title": title})

    assert response.status_code == 422


def test_invalid_status_and_empty_update_are_rejected(authenticated_client: TestClient) -> None:
    investigation_id = authenticated_client.post(
        "/api/investigations", json={"title": "Investigation"}
    ).json()["id"]

    invalid_status = authenticated_client.patch(
        f"/api/investigations/{investigation_id}", json={"status": "unknown"}
    )
    empty_update = authenticated_client.patch(f"/api/investigations/{investigation_id}", json={})

    assert invalid_status.status_code == 422
    assert empty_update.status_code == 422


def test_url_analysis_endpoint_is_authenticated_and_returns_findings(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/api/analyze/url",
        json={"url": "http://192.0.2.10/login"},
    )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "high"
    assert "host.ip_address" in {
        finding["rule_id"] for finding in response.json()["findings"]
    }


def test_combined_analysis_aggregates_url_and_email_evidence(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post(
        "/api/analyze",
        json={
            "urls": [
                "https://www.example.com/",
                "http://192.0.2.10/login",
            ],
            "raw_email": (
                "From: Alice <alice@example.com>\r\n"
                "Subject: Verify your account\r\n\r\n"
                "Use http://192.0.2.10/login to continue."
            ),
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert len(result["url_results"]) == 2
    assert result["email_result"] is not None
    assert result["risk_assessment"]["status"] == "findings_present"
    assert result["risk_assessment"]["risk_level"] == "critical"
    assert "not a probability" in result["risk_assessment"]["scoring_note"]


def test_combined_analysis_rejects_missing_evidence(
    authenticated_client: TestClient,
) -> None:
    response = authenticated_client.post("/api/analyze", json={})

    assert response.status_code == 422


def test_persisted_analysis_reports_and_notes_omit_raw_email_content(
    authenticated_client: TestClient,
) -> None:
    investigation_id = authenticated_client.post(
        "/api/investigations", json={"title": "Persisted assessment"}
    ).json()["id"]
    body_marker = "private-body-marker-731"
    query_secret = "private-token-marker-842"
    raw_email = (
        "From: analyst@sender.example\r\n"
        "Subject: Urgent account notice\r\n\r\n"
        f"Review this message {body_marker} and visit "
        f"https://example.com/login?access_token={query_secret}"
    )

    analyzed = authenticated_client.post(
        f"/api/investigations/{investigation_id}/analyze",
        json={
            "urls": [f"https://example.com/login?access_token={query_secret}"],
            "raw_email": raw_email,
        },
    )
    assert analyzed.status_code == 201
    result = analyzed.json()
    assert len(result["submission_ids"]) == 2
    assert result["report_id"]

    submissions = authenticated_client.get(
        f"/api/investigations/{investigation_id}/submissions"
    ).json()
    assert len(submissions) == 2
    assert body_marker not in str(submissions)
    assert query_secret not in str(submissions)
    assert any("raw message content is not retained" in item["content"] for item in submissions)

    report_response = authenticated_client.get(
        f"/api/investigations/{investigation_id}/reports/latest"
    )
    assert report_response.status_code == 200
    report_text = report_response.text
    assert body_marker not in report_text
    assert query_secret not in report_text
    assert "Raw email bodies" in report_text

    downloaded = authenticated_client.get(
        f"/api/investigations/{investigation_id}/reports/{result['report_id']}/download"
    )
    assert downloaded.status_code == 200
    assert "attachment;" in downloaded.headers["content-disposition"]
    assert body_marker not in downloaded.text

    note = authenticated_client.post(
        f"/api/investigations/{investigation_id}/notes",
        json={"body": "  Reviewed sender mismatch.  "},
    )
    assert note.status_code == 201
    assert note.json()["body"] == "Reviewed sender mismatch."
    assert len(
        authenticated_client.get(
            f"/api/investigations/{investigation_id}/notes"
        ).json()
    ) == 1

    pdf = authenticated_client.get(
        f"/api/investigations/{investigation_id}/reports/{result['report_id']}/download.pdf"
    )
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")
    assert "attachment;" in pdf.headers["content-disposition"]


def test_investigation_search_status_pagination_and_dashboard_stats(
    authenticated_client: TestClient,
) -> None:
    first = authenticated_client.post(
        "/api/investigations", json={"title": "Quarterly phishing review"}
    ).json()["id"]
    second = authenticated_client.post(
        "/api/investigations", json={"title": "Benign invoice"}
    ).json()["id"]
    authenticated_client.patch(
        f"/api/investigations/{second}",
        json={"status": "benign"},
    )

    filtered = authenticated_client.get(
        "/api/investigations",
        params={"q": "phishing", "status": "new", "offset": 0, "limit": 1},
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert [item["id"] for item in filtered.json()["items"]] == [first]

    stats = authenticated_client.get("/api/dashboard/stats")
    assert stats.status_code == 200
    assert stats.json()["investigation_count"] == 2
    assert stats.json()["investigations_by_status"]["new"] == 1
    assert stats.json()["investigations_by_status"]["benign"] == 1


def test_email_file_analysis_is_persisted_and_preferences_are_user_scoped(
    authenticated_client: TestClient,
) -> None:
    investigation_id = authenticated_client.post(
        "/api/investigations", json={"title": "Uploaded message"}
    ).json()["id"]
    message = b"From: sender@example.com\r\nSubject: Notice\r\n\r\nPlease review."
    analyzed = authenticated_client.post(
        f"/api/investigations/{investigation_id}/analyze/email/file",
        files={"file": ("message.eml", message, "message/rfc822")},
    )
    assert analyzed.status_code == 201
    assert len(analyzed.json()["submission_ids"]) == 1
    assert len(
        authenticated_client.get(
            f"/api/investigations/{investigation_id}/submissions"
        ).json()
    ) == 1

    defaults = authenticated_client.get("/api/auth/preferences")
    assert defaults.status_code == 200
    assert defaults.json()["theme"] == "system"
    updated = authenticated_client.put(
        "/api/auth/preferences",
        json={"theme": "dark", "compact_mode": True},
    )
    assert updated.status_code == 200
    assert updated.json()["theme"] == "dark"
    assert updated.json()["compact_mode"] is True
    assert authenticated_client.get("/api/auth/preferences").json()["theme"] == "dark"
