import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract

from app.schemas.risk import EvidenceSourceType, URLRisk
from app.schemas.url_analysis import (
    URLAnalysisRead,
    URLFinding,
)
from app.services.risk_aggregation import FindingSource, aggregate_findings

_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)
_SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}
_BRANDS = {
    "adobe",
    "amazon",
    "apple",
    "bankofamerica",
    "docusign",
    "dropbox",
    "facebook",
    "google",
    "microsoft",
    "netflix",
    "paypal",
}
_CREDENTIAL_TERMS = {
    "account",
    "authenticate",
    "billing",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}
_REDIRECT_KEYS = {"continue", "next", "redirect", "return", "returnto", "url"}
_SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "auth_token",
    "authorization",
    "code",
    "key",
    "password",
    "session",
    "sessionid",
    "token",
}
_MIXED_SCRIPT_MARKERS = ("CYRILLIC", "GREEK")


def _finding(
    rule_id: str,
    title: str,
    severity: URLRisk,
    explanation: str,
    evidence: dict[str, object],
) -> URLFinding:
    return URLFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        explanation=explanation,
        evidence=evidence,
    )


def _ascii_hostname(hostname: str) -> str:
    return hostname.rstrip(".").encode("idna").decode("ascii").lower()


def _valid_hostname(hostname: str) -> bool:
    if not hostname or any(char.isspace() or ord(char) < 33 for char in hostname):
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    try:
        ascii_hostname = _ascii_hostname(hostname)
    except UnicodeError:
        return False
    if not ascii_hostname or len(ascii_hostname) > 253:
        return False
    return all(
        len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in ascii_hostname.split(".")
    )


def _mixed_script_lookalikes(hostname: str) -> list[str]:
    matches = []
    for label in hostname.split("."):
        scripts = {
            marker
            for char in label
            for marker in _MIXED_SCRIPT_MARKERS
            if marker in unicodedata.name(char, "")
        }
        contains_ascii = any("a" <= char.lower() <= "z" for char in label)
        if scripts and contains_ascii:
            matches.append(label)
    return matches


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    left_index = 0
    right_index = 0
    edits = 0
    while left_index < len(left) and right_index < len(right):
        if left[left_index] == right[right_index]:
            left_index += 1
            right_index += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(left) > len(right):
            left_index += 1
        elif len(right) > len(left):
            right_index += 1
        else:
            left_index += 1
            right_index += 1
    return edits + (left_index < len(left)) + (right_index < len(right)) <= 1


def _normalized_url(parts, hostname: str | None, port: int | None) -> str:
    netloc = parts.netloc.rsplit("@", 1)[-1]
    if hostname:
        try:
            host = _ascii_hostname(hostname)
        except UnicodeError:
            host = hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host if port is None else f"{host}:{port}"

    query = urlencode(
        [
            (key, "[redacted]" if key.lower() in _SENSITIVE_QUERY_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, query, parts.fragment))


def _registrable_domain(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        result = _SUFFIX_EXTRACTOR(hostname)
        return result.top_domain_under_public_suffix or None


def analyze_url(raw_url: str) -> URLAnalysisRead:
    url = raw_url.strip()
    findings: list[URLFinding] = []
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        parts = urlsplit("")
        hostname = None
        port = None
        findings.append(
            _finding(
                "url.malformed",
                "Malformed URL",
                URLRisk.medium,
                "The URL could not be parsed safely.",
                {"input_length": len(url)},
            )
        )

    valid_syntax = bool(
        hostname
        and parts.scheme.lower() in {"http", "https"}
        and _valid_hostname(hostname)
    )
    if not valid_syntax and not any(item.rule_id == "url.malformed" for item in findings):
        findings.append(
            _finding(
                "url.invalid_syntax",
                "Invalid URL syntax",
                URLRisk.medium,
                "A valid HTTP or HTTPS URL with a valid hostname is required for reliable analysis.",
                {"scheme": parts.scheme.lower(), "hostname_present": bool(hostname)},
            )
        )

    ascii_hostname = None
    if hostname:
        try:
            ascii_hostname = _ascii_hostname(hostname)
        except UnicodeError:
            valid_syntax = False

    try:
        normalized_url = _normalized_url(parts, hostname, port)
    except (UnicodeError, ValueError):
        normalized_url = url

    if parts.scheme.lower() == "http" and hostname:
        findings.append(
            _finding(
                "transport.http",
                "Unencrypted HTTP",
                URLRisk.low,
                "The URL uses HTTP, so traffic is not protected by TLS. This alone does not establish phishing.",
                {},
            )
        )

    if "@" in parts.netloc:
        findings.append(
            _finding(
                "url.userinfo",
                "User information in URL authority",
                URLRisk.high,
                "Text before @ can disguise the hostname shown to a reader.",
                {"authority_contains_userinfo": True},
            )
        )

    is_ip_address = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            pass
    if is_ip_address:
        findings.append(
            _finding(
                "host.ip_address",
                "IP-address hostname",
                URLRisk.high,
                "The destination is addressed directly by IP instead of a domain name.",
                {"hostname": ascii_hostname},
            )
        )

    if hostname and len(hostname) > 100:
        findings.append(
            _finding(
                "host.excessive_length",
                "Unusually long hostname",
                URLRisk.medium,
                "The hostname is unusually long and may be difficult to inspect.",
                {"hostname_length": len(hostname)},
            )
        )
    if len(url) > 2048:
        findings.append(
            _finding(
                "url.excessive_length",
                "Unusually long URL",
                URLRisk.low,
                "The URL is longer than typical browser navigation URLs.",
                {"url_length": len(url)},
            )
        )

    if hostname and ascii_hostname:
        labels = hostname.rstrip(".").split(".")
        if len(labels) >= 6 and not is_ip_address:
            findings.append(
                _finding(
                    "host.deep_subdomains",
                    "Deep subdomain structure",
                    URLRisk.low,
                    "The hostname contains many labels before its registrable domain.",
                    {"label_count": len(labels)},
                )
            )

        if "xn--" in ascii_hostname:
            findings.append(
                _finding(
                    "host.idn_punycode",
                    "Internationalized domain encoding",
                    URLRisk.low,
                    "The hostname contains a punycode label. Internationalized domains are not inherently malicious.",
                    {"punycode_present": True},
                )
            )
        elif any(ord(char) > 127 for char in hostname):
            findings.append(
                _finding(
                    "host.idn_unicode",
                    "Internationalized domain",
                    URLRisk.low,
                    "The hostname contains Unicode characters and may render differently across clients.",
                    {"unicode_hostname": True},
                )
            )

        lookalike_labels = _mixed_script_lookalikes(hostname)
        if lookalike_labels:
            findings.append(
                _finding(
                    "host.mixed_script_lookalike",
                    "Mixed-script hostname",
                    URLRisk.high,
                    "The hostname mixes Latin characters with Greek or Cyrillic characters that can resemble them.",
                    {"affected_labels": lookalike_labels},
                )
            )

        registrable_domain = _registrable_domain(hostname) if not is_ip_address else None
        suffix_result = _SUFFIX_EXTRACTOR(hostname) if not is_ip_address else None
        if registrable_domain and suffix_result:
            domain_label = suffix_result.domain.lower()
            hostname_tokens = {
                token
                for label in labels
                for token in re.split(r"[^a-z0-9]+", label.lower())
            }
            brand_matches = sorted(
                brand
                for brand in _BRANDS
                if brand in hostname_tokens
                and domain_label != brand
            )
            typosquat_matches = sorted(
                brand
                for brand in _BRANDS
                if len(brand) >= 6
                and domain_label != brand
                and _edit_distance_at_most_one(domain_label, brand)
            )
            brand_matches = sorted(set(brand_matches) | set(typosquat_matches))
            if brand_matches:
                findings.append(
                    _finding(
                        "host.brand_term_mismatch",
                        "Brand term outside matching registrable domain",
                        URLRisk.high,
                        "A known brand name appears in the hostname, but the registrable domain is different. This is an indicator, not proof of impersonation.",
                        {
                            "brand_terms": brand_matches,
                            "registrable_domain": registrable_domain,
                            "close_domain_match": bool(typosquat_matches),
                        },
                    )
                )

            if registrable_domain in _SHORTENERS:
                findings.append(
                    _finding(
                        "host.url_shortener",
                        "URL shortener",
                        URLRisk.low,
                        "The URL uses a known shortening service, so its final destination is not visible here. No redirect was followed.",
                        {"registrable_domain": registrable_domain},
                    )
                )

    standard_port = 443 if parts.scheme.lower() == "https" else 80
    if port is not None and port != standard_port:
        findings.append(
            _finding(
                "url.unusual_port",
                "Nonstandard destination port",
                URLRisk.medium,
                "The URL specifies a port that does not match the standard port for its scheme.",
                {"port": port},
            )
        )

    encoded_values = re.findall(r"%[0-9a-fA-F]{2}", url)
    suspicious_encodings = re.findall(r"%(?:00|2f|5c|40)", url, flags=re.IGNORECASE)
    if len(encoded_values) >= 5 or suspicious_encodings:
        findings.append(
            _finding(
                "url.encoded_characters",
                "Unusual percent-encoding",
                URLRisk.medium if suspicious_encodings else URLRisk.low,
                "The URL contains multiple or structurally significant percent-encoded characters.",
                {
                    "encoded_character_count": len(encoded_values),
                    "structural_encoding_present": bool(suspicious_encodings),
                },
            )
        )

    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    redirect_keys = sorted(
        key.lower() for key, _ in query_pairs if key.lower() in _REDIRECT_KEYS
    )
    if len(redirect_keys) >= 2:
        findings.append(
            _finding(
                "url.redirect_parameters",
                "Multiple redirect-related parameters",
                URLRisk.medium,
                "Several query parameters can be used to pass destinations to another page.",
                {"parameter_names": redirect_keys},
            )
        )

    searchable = f"{hostname or ''}{parts.path}{parts.query}".lower()
    credential_terms = sorted(
        term for term in _CREDENTIAL_TERMS if re.search(rf"(?<![a-z]){term}(?![a-z])", searchable)
    )
    if len(credential_terms) >= 2:
        findings.append(
            _finding(
                "url.credential_language",
                "Multiple credential-themed terms",
                URLRisk.medium,
                "The hostname or URL path combines multiple terms commonly used in account or credential prompts.",
                {"matched_terms": credential_terms},
            )
        )

    if parts.scheme.lower() == "http" and credential_terms:
        findings.append(
            _finding(
                "url.http_credential_prompt",
                "Credential-themed URL over HTTP",
                URLRisk.high,
                "The URL combines an HTTP connection with account or credential-themed terms.",
                {"matched_terms": credential_terms},
            )
        )

    weak_findings = [item.rule_id for item in findings if item.severity == URLRisk.low]
    if len(weak_findings) >= 3:
        findings.append(
            _finding(
                "url.combined_weak_signals",
                "Several weak indicators combined",
                URLRisk.medium,
                "Multiple individually weak indicators appear together and warrant manual review.",
                {"contributing_rules": weak_findings},
            )
        )

    risk_assessment = aggregate_findings(
        [
            FindingSource(
                source_id="url:submitted",
                source_type=EvidenceSourceType.url,
                findings=findings,
            )
        ]
    )
    risk_level = risk_assessment.risk_level or URLRisk.low

    if risk_level in {URLRisk.high, URLRisk.critical}:
        actions = [
            "Do not open the URL or enter credentials.",
            "Verify the claimed sender or organization through an independent trusted channel.",
            "Preserve the original message and URL for investigation.",
        ]
    elif risk_level == URLRisk.medium:
        actions = [
            "Inspect the sender and surrounding message context.",
            "Do not enter credentials or sensitive information until the destination is independently verified.",
        ]
    else:
        actions = [
            "No strong URL indicators were found; this does not prove the destination is safe.",
            "Verify unexpected requests through an independent trusted channel.",
        ]

    return URLAnalysisRead(
        normalized_url=normalized_url,
        valid_syntax=valid_syntax,
        hostname=ascii_hostname,
        registrable_domain=(
            _registrable_domain(hostname)
            if hostname and valid_syntax and not is_ip_address
            else None
        ),
        risk_level=risk_level,
        risk_assessment=risk_assessment,
        uncertainty=(
            "This result reflects only locally visible URL structure. Missing indicators or an unfamiliar hostname are not evidence of safety."
        ),
        findings=findings,
        recommended_actions=actions,
        limitations=[
            "This is deterministic heuristic analysis, not a statistically calibrated probability.",
            "No DNS, reputation, redirect, or webpage requests were made.",
        ],
    )
