import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

from app.analysis.url_analyzer import analyze_url
from app.schemas.email_analysis import (
    AuthenticationEvidence,
    EmailAddress,
    EmailAnalysisRead,
    EmailAttachmentMetadata,
    EmailFinding,
    EmailLink,
)
from app.schemas.risk import EvidenceSourceType, RiskAssessment, URLRisk
from app.services.risk_aggregation import FindingSource, aggregate_findings

MAX_EMAIL_BYTES = 1_000_000
MAX_MIME_PARTS = 500
MAX_LINKS = 100
_DANGEROUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".pptm",
    ".ps1",
    ".rar",
    ".scr",
    ".sh",
    ".vbs",
    ".wsf",
    ".zip",
    ".7z",
    ".xlsm",
    ".docm",
    ".xlam",
}
_BRANDS = {
    "amazon",
    "apple",
    "docusign",
    "facebook",
    "google",
    "microsoft",
    "netflix",
    "paypal",
}
_URGENCY_TERMS = (
    "action required",
    "account suspended",
    "immediately",
    "urgent",
    "within 24 hours",
    "final notice",
)
_CREDENTIAL_PHRASES = (
    "confirm your password",
    "enter your password",
    "verify your account",
    "verify your password",
    "sign in to restore",
    "credentials",
)
_FINANCIAL_PHRASES = (
    "bank details",
    "change payment",
    "gift card",
    "invoice payment",
    "wire transfer",
    "payment details",
)
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


class EmailTooLargeError(ValueError):
    pass


class _HTMLTextAndLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[EmailLink] = []
        self._active_link: list[str] | None = None
        self._active_url: str | None = None
        self._ignored_elements: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "template"}:
            self._ignored_elements.append(tag.lower())
            return
        if self._ignored_elements:
            return
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self._active_link = []
            self._active_url = href.strip()

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_elements:
            if self._ignored_elements[-1] == tag.lower():
                self._ignored_elements.pop()
            return
        if tag.lower() == "a" and self._active_url is not None:
            display_text = " ".join(self._active_link or []).strip() or None
            self.links.append(EmailLink(url=self._active_url, display_text=display_text))
            self._active_link = None
            self._active_url = None

    def handle_data(self, data: str) -> None:
        if self._ignored_elements:
            return
        self.text.append(data)
        if self._active_link is not None:
            self._active_link.append(data)


def _finding(
    rule_id: str,
    title: str,
    severity: URLRisk,
    explanation: str,
    evidence: dict[str, object] | None = None,
) -> EmailFinding:
    return EmailFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        explanation=explanation,
        evidence=evidence or {},
    )


def build_email_finding_sources(
    findings: list[EmailFinding],
    source_id_prefix: str = "email",
) -> list[FindingSource]:
    grouped: dict[EvidenceSourceType, list[EmailFinding]] = {}
    for finding in findings:
        if "attachment" in finding.rule_id:
            source_type = EvidenceSourceType.attachment
        elif "link" in finding.rule_id:
            source_type = EvidenceSourceType.url
        elif any(
            term in finding.rule_id
            for term in ("urgency", "credential", "financial")
        ):
            source_type = EvidenceSourceType.email_body
        else:
            source_type = EvidenceSourceType.email_header
        grouped.setdefault(source_type, []).append(finding)

    if not grouped:
        grouped[EvidenceSourceType.email_body] = []
    return [
        FindingSource(
            source_id=f"{source_id_prefix}:{source_type.value}",
            source_type=source_type,
            findings=source_findings,
        )
        for source_type, source_findings in grouped.items()
    ]


def _build_risk_assessment(findings: list[EmailFinding]) -> RiskAssessment:
    return aggregate_findings(build_email_finding_sources(findings))


def _addresses(message: Message, header_name: str) -> list[EmailAddress]:
    values = message.get_all(header_name, [])
    return [
        EmailAddress(display_name=name, address=address)
        for name, address in getaddresses([str(value) for value in values])
        if address
    ]


def _decode_text_part(part: Message) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except (LookupError, TypeError, UnicodeDecodeError):
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _domain_for_address(address: str) -> str | None:
    _, separator, domain = address.rpartition("@")
    return domain.lower().rstrip(".") if separator and domain else None


def _malformed_result() -> EmailAnalysisRead:
    finding = _finding(
        "email.malformed",
        "Malformed email message",
        URLRisk.medium,
        "The message could not be parsed safely; the available evidence is incomplete.",
    )
    risk_assessment = _build_risk_assessment([finding])
    return EmailAnalysisRead(
        from_addresses=[],
        reply_to=[],
        return_path=[],
        to=[],
        subject=None,
        date=None,
        received_headers=[],
        authentication_results=[],
        message_id=None,
        text_body="",
        links=[],
        attachments=[],
        risk_level=risk_assessment.risk_level or URLRisk.low,
        risk_assessment=risk_assessment,
        uncertainty="The message was malformed, so this is an incomplete assessment.",
        findings=[finding],
        recommended_actions=[
            "Preserve the original message and inspect it with a trusted mail client.",
        ],
        limitations=["No attachment was opened or executed."],
    )


def analyze_email(raw_email: str | bytes) -> EmailAnalysisRead:
    raw_bytes = raw_email if isinstance(raw_email, bytes) else raw_email.encode("utf-8", "replace")
    if len(raw_bytes) > MAX_EMAIL_BYTES:
        raise EmailTooLargeError(f"Email message exceeds the {MAX_EMAIL_BYTES}-byte limit.")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        parts = []
        parts_truncated = False
        for index, part in enumerate(message.walk()):
            if index >= MAX_MIME_PARTS:
                parts_truncated = True
                break
            parts.append(part)
    except (RecursionError, ValueError):
        return _malformed_result()

    findings: list[EmailFinding] = []
    from_addresses = _addresses(message, "From")
    reply_to = _addresses(message, "Reply-To")
    return_path = _addresses(message, "Return-Path")
    to = _addresses(message, "To")
    if not from_addresses:
        findings.append(
            _finding(
                "email.missing_from",
                "Missing or unreadable From header",
                URLRisk.medium,
                "The message does not contain a parseable sender address.",
            )
        )
    if len(from_addresses) > 1 or len(message.get_all("From", [])) > 1:
        findings.append(
            _finding(
                "email.multiple_from",
                "Multiple From identities",
                URLRisk.medium,
                "The message contains more than one From address or header.",
                {"from_address_count": len(from_addresses)},
            )
        )

    sender_domains = {
        domain for item in from_addresses if (domain := _domain_for_address(item.address))
    }
    reply_domains = {
        domain for item in reply_to if (domain := _domain_for_address(item.address))
    }
    if sender_domains and reply_domains and sender_domains.isdisjoint(reply_domains):
        findings.append(
            _finding(
                "email.reply_to_mismatch",
                "From and Reply-To domains differ",
                URLRisk.medium,
                "Replies would be directed to a different domain than the displayed sender.",
                {
                    "from_domains": sorted(sender_domains),
                    "reply_to_domains": sorted(reply_domains),
                },
            )
        )

    return_path_domains = {
        domain for item in return_path if (domain := _domain_for_address(item.address))
    }
    if sender_domains and return_path_domains and sender_domains.isdisjoint(return_path_domains):
        findings.append(
            _finding(
                "email.return_path_mismatch",
                "From and Return-Path domains differ",
                URLRisk.low,
                "The envelope return path differs from the displayed sender; this can be legitimate mailing infrastructure.",
                {
                    "from_domains": sorted(sender_domains),
                    "return_path_domains": sorted(return_path_domains),
                },
            )
        )

    sender_domain_analyses = {
        domain: analyze_url(f"https://{domain}/") for domain in sender_domains
    }
    sender_domain_rules = {
        "host.idn_punycode",
        "host.idn_unicode",
        "host.mixed_script_lookalike",
        "host.brand_term_mismatch",
        "host.excessive_length",
        "host.ip_address",
    }
    for domain, analysis in sender_domain_analyses.items():
        for item in analysis.findings:
            if item.rule_id in sender_domain_rules:
                findings.append(
                    _finding(
                        f"email.sender_{item.rule_id.replace('.', '_')}",
                        f"Suspicious sender domain: {item.title}",
                        item.severity,
                        item.explanation,
                        {"sender_domain": domain, "source_rule": item.rule_id},
                    )
                )

    if from_addresses:
        sender_domain = _domain_for_address(from_addresses[0].address)
        display_name = from_addresses[0].display_name.casefold()
        matched_brands = sorted(
            brand for brand in _BRANDS if re.search(rf"(?<![a-z]){brand}(?![a-z])", display_name)
        )
        if sender_domain and matched_brands:
            sender_analysis = sender_domain_analyses[sender_domain]
            sender_domain_label = (
                sender_analysis.registrable_domain.split(".", 1)[0]
                if sender_analysis.registrable_domain
                else None
            )
            if sender_domain_label not in matched_brands:
                findings.append(
                    _finding(
                        "email.display_name_brand_mismatch",
                        "Brand display name does not match sender domain",
                        URLRisk.high,
                        "The display name contains a known brand, but the sender address uses a different registrable domain.",
                        {
                            "brand_terms": matched_brands,
                            "sender_domain": sender_domain,
                            "registrable_domain": sender_analysis.registrable_domain,
                        },
                    )
                )

    date_value = str(message.get("Date")) if message.get("Date") is not None else None
    if date_value:
        try:
            parsedate_to_datetime(date_value)
        except (TypeError, ValueError, OverflowError):
            findings.append(
                _finding(
                    "email.invalid_date",
                    "Invalid Date header",
                    URLRisk.low,
                    "The Date header could not be parsed as a valid email date.",
                )
            )

    auth_results: list[AuthenticationEvidence] = []
    for header in message.get_all("Authentication-Results", []):
        value = str(header)
        authserv_id = value.split(";", 1)[0].strip().lower()
        auth_results.append(
            AuthenticationEvidence(
                authserv_id=authserv_id,
                header_value=value,
                trusted=False,
            )
        )
    if auth_results:
        findings.append(
            _finding(
                "email.untrusted_authentication_results",
                "Authentication results are unverified",
                URLRisk.low,
                "Authentication-Results headers in submitted content can be forged and are not treated as verified.",
                {"header_count": len(auth_results)},
            )
        )

    defects = sorted({type(defect).__name__ for part in parts for defect in part.defects})
    if defects:
        findings.append(
            _finding(
                "email.parser_defects",
                "Email parser reported structural defects",
                URLRisk.low,
                "The message contains malformed or nonconforming MIME structure.",
                {"defect_types": defects},
            )
        )
    if parts_truncated:
        findings.append(
            _finding(
                "email.mime_part_limit",
                "MIME part count truncated",
                URLRisk.low,
                "Only the first 500 MIME parts were inspected.",
            )
        )

    text_chunks: list[str] = []
    html_links: list[EmailLink] = []
    attachments: list[EmailAttachmentMetadata] = []
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True)
        size_bytes = len(payload) if isinstance(payload, bytes) else 0
        if filename or disposition == "attachment":
            extension = "." + filename.rsplit(".", 1)[-1].casefold() if filename and "." in filename else ""
            dangerous = extension in _DANGEROUS_EXTENSIONS
            attachments.append(
                EmailAttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    disposition=disposition,
                    size_bytes=size_bytes,
                    dangerous_extension=dangerous,
                )
            )
            if dangerous:
                findings.append(
                    _finding(
                        "email.dangerous_attachment_extension",
                        "Potentially dangerous attachment extension",
                        URLRisk.medium,
                        "The attachment filename uses an extension commonly associated with executable or macro-enabled content. The attachment was not opened.",
                        {"extension": extension},
                    )
                )
            continue

        if content_type == "text/plain":
            text_chunks.append(_decode_text_part(part))
        elif content_type == "text/html":
            html_parser = _HTMLTextAndLinks()
            html_parser.feed(_decode_text_part(part))
            html_parser.close()
            text_chunks.extend(html_parser.text)
            html_links.extend(html_parser.links)

    body = "\n".join(chunk for chunk in text_chunks if chunk).strip()
    lowered_body = f"{message.get('Subject', '')}\n{body}".casefold()
    urgency_terms = [term for term in _URGENCY_TERMS if term in lowered_body]
    if urgency_terms:
        severity = URLRisk.medium if len(urgency_terms) >= 2 else URLRisk.low
        findings.append(
            _finding(
                "email.urgency_language",
                "Urgency language",
                severity,
                "The subject or body uses language that pressures the recipient to act quickly.",
                {"matched_phrases": urgency_terms},
            )
        )

    credential_phrases = [term for term in _CREDENTIAL_PHRASES if term in lowered_body]
    if credential_phrases:
        findings.append(
            _finding(
                "email.credential_collection_language",
                "Credential collection language",
                URLRisk.medium,
                "The message asks the recipient to verify, enter, or restore account credentials.",
                {"matched_phrases": credential_phrases},
            )
        )

    financial_phrases = [term for term in _FINANCIAL_PHRASES if term in lowered_body]
    if financial_phrases:
        findings.append(
            _finding(
                "email.financial_request_language",
                "Financial request language",
                URLRisk.medium if len(financial_phrases) >= 2 else URLRisk.low,
                "The message refers to payment, bank details, gift cards, or wire transfers.",
                {"matched_phrases": financial_phrases},
            )
        )

    links = list(html_links[:MAX_LINKS])
    links_truncated = len(html_links) > MAX_LINKS
    known_urls = {link.url for link in links}
    for match in _URL_PATTERN.finditer(body):
        value = match.group(0).rstrip(".,;:!?)]}")
        url = f"https://{value}" if value.lower().startswith("www.") else value
        if url not in known_urls:
            if len(links) >= MAX_LINKS:
                links_truncated = True
                break
            links.append(EmailLink(url=url))
            known_urls.add(url)
    if links_truncated:
        findings.append(
            _finding(
                "email.link_limit",
                "Email link count truncated",
                URLRisk.low,
                "Only the first 100 links were retained for analysis.",
            )
        )

    link_analyses = [analyze_url(link.url) for link in links]
    suspicious_links = [
        (index, analysis)
        for index, analysis in enumerate(link_analyses)
        if analysis.risk_level in {URLRisk.medium, URLRisk.high, URLRisk.critical}
    ]
    if suspicious_links:
        severity = (
            URLRisk.high
            if any(
                analysis.risk_level in {URLRisk.high, URLRisk.critical}
                for _, analysis in suspicious_links
            )
            else URLRisk.medium
        )
        findings.append(
            _finding(
                "email.suspicious_links",
                "Suspicious linked URL indicators",
                severity,
                "One or more embedded links triggered local URL indicators; no link was opened.",
                {
                    "link_indexes": [index for index, _ in suspicious_links],
                    "rule_ids": sorted(
                        {
                            finding.rule_id
                            for _, analysis in suspicious_links
                            for finding in analysis.findings
                        }
                    ),
                },
            )
        )

    sender_registrable_domains = {
        analysis.registrable_domain for analysis in sender_domain_analyses.values()
    } - {None}
    linked_domains = {
        analysis.registrable_domain for analysis in link_analyses if analysis.registrable_domain
    }
    mismatched_link_domains = sorted(linked_domains - sender_registrable_domains)
    if sender_registrable_domains and mismatched_link_domains:
        findings.append(
            _finding(
                "email.sender_link_domain_mismatch",
                "Linked domains differ from sender domain",
                URLRisk.low,
                "At least one linked domain differs from the sender domain. This is common in legitimate email and is not proof of phishing.",
                {"sender_domains": sorted(sender_registrable_domains), "linked_domains": mismatched_link_domains},
            )
        )

    risk_assessment = _build_risk_assessment(findings)
    risk_level = risk_assessment.risk_level or URLRisk.low
    if risk_level in {URLRisk.high, URLRisk.critical}:
        actions = [
            "Do not reply, open attachments, or enter credentials from this message.",
            "Verify the sender and request through a separate trusted channel.",
            "Preserve the original message for investigation.",
        ]
    elif risk_level == URLRisk.medium:
        actions = [
            "Review the sender, headers, links, and attachment metadata before taking action.",
            "Verify requests for credentials or money through a separate trusted channel.",
        ]
    else:
        actions = [
            "No strong phishing indicators were found in the parsed content; this does not prove the message is safe.",
        ]

    return EmailAnalysisRead(
        from_addresses=from_addresses,
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        subject=str(message.get("Subject")) if message.get("Subject") is not None else None,
        date=date_value,
        received_headers=[str(value) for value in message.get_all("Received", [])],
        authentication_results=auth_results,
        message_id=str(message.get("Message-ID")) if message.get("Message-ID") is not None else None,
        text_body=body,
        links=links,
        attachments=attachments,
        risk_level=risk_level,
        risk_assessment=risk_assessment,
        uncertainty=(
            "Only the submitted headers and content were inspected; authentication results and sender claims are not independently verified."
        ),
        findings=findings,
        recommended_actions=actions,
        limitations=[
            "HTML was parsed as inert text; scripts and attachments were not executed or opened.",
            "No URL was resolved, fetched, or followed.",
            "Authentication-Results headers supplied in the message are treated as untrusted.",
        ],
    )
