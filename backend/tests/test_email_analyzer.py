from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app.analysis.email_analyzer import (
    MAX_EMAIL_BYTES,
    EmailTooLargeError,
    analyze_email,
)


def test_plain_email_headers_and_links_are_extracted_as_untrusted_evidence() -> None:
    raw_email = (
        "From: Alice <alice@example.com>\r\n"
        "Reply-To: reply@different.example\r\n"
        "Return-Path: <bounce@mail.example.net>\r\n"
        "To: analyst@example.com\r\n"
        "Subject: Project update\r\n"
        "Date: Fri, 21 Nov 2025 10:00:00 +0000\r\n"
        "Received: by mx.example.net\r\n"
        "Authentication-Results: mx.example.net; spf=pass; dkim=pass\r\n"
        "Message-ID: <message@example.com>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Please review https://www.example.com/news.\r\n"
    )

    result = analyze_email(raw_email)

    assert result.from_addresses[0].address == "alice@example.com"
    assert result.reply_to[0].address == "reply@different.example"
    assert result.return_path[0].address == "bounce@mail.example.net"
    assert result.received_headers == ["by mx.example.net"]
    assert result.authentication_results[0].trusted is False
    assert result.links[0].url == "https://www.example.com/news"
    assert "email.reply_to_mismatch" in {finding.rule_id for finding in result.findings}


def test_multipart_email_extracts_html_links_and_inert_attachment_metadata() -> None:
    message = EmailMessage()
    message["From"] = "PayPal Support <alert@evil.example>"
    message["Reply-To"] = "reply@other.example"
    message["Subject"] = "Urgent account notice"
    message["Received"] = "by mx.example.net"
    message["Authentication-Results"] = "mx.example.net; dkim=pass"
    message.set_content("Please verify your account immediately.")
    message.add_alternative(
        """
        <html><body>
          <script>alert('not executed')</script>
          <a href="http://192.0.2.10/login">Verify your account</a>
        </body></html>
        """,
        subtype="html",
    )
    message.add_attachment(
        b"do not open",
        maintype="application",
        subtype="octet-stream",
        filename="statement.xlsm",
    )

    result = analyze_email(message.as_bytes())
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "email.display_name_brand_mismatch" in rule_ids
    assert "email.reply_to_mismatch" in rule_ids
    assert "email.credential_collection_language" in rule_ids
    assert "email.suspicious_links" in rule_ids
    assert result.authentication_results[0].trusted is False
    assert result.attachments[0].filename == "statement.xlsm"
    assert result.attachments[0].dangerous_extension
    assert result.attachments[0].size_bytes == len(b"do not open")
    assert "not executed" not in result.text_body
    assert "No URL was resolved" in result.limitations[1]


def test_malformed_email_is_labeled_and_oversized_input_is_rejected() -> None:
    malformed = (
        "Content-Type: multipart/mixed; boundary=broken\r\n\r\n"
        "--broken\r\nContent-Type: text/plain\r\n\r\nunterminated"
    )
    result = analyze_email(malformed)
    assert result.risk_level.value == "medium"
    assert any(finding.rule_id == "email.missing_from" for finding in result.findings)

    with pytest.raises(EmailTooLargeError):
        analyze_email(b"x" * (MAX_EMAIL_BYTES + 1))


def test_pasted_email_and_eml_upload_endpoints(authenticated_client: TestClient):
    raw_email = "From: Alice <alice@example.com>\r\nSubject: Hello\r\n\r\nA plain message."
    pasted = authenticated_client.post(
        "/api/analyze/email",
        json={"raw_email": raw_email},
    )
    uploaded = authenticated_client.post(
        "/api/analyze/email/file",
        files={"file": ("message.eml", raw_email.encode(), "message/rfc822")},
    )
    oversized = authenticated_client.post(
        "/api/analyze/email/file",
        files={
            "file": (
                "oversized.eml",
                b"x" * (MAX_EMAIL_BYTES + 1),
                "message/rfc822",
            )
        },
    )
    unsupported = authenticated_client.post(
        "/api/analyze/email/file",
        files={"file": ("message.txt", raw_email.encode(), "text/plain")},
    )

    assert pasted.status_code == 200
    assert uploaded.status_code == 200
    assert oversized.status_code == 413
    assert unsupported.status_code == 415
    authenticated_client.cookies.clear()
    assert (
        authenticated_client.post("/api/analyze/email", json={"raw_email": raw_email}).status_code
        == 401
    )
