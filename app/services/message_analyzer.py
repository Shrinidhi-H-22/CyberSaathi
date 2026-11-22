
import re

from app.services.url_analyzer import analyze_url


# Maximum message length accepted by the analyzer.
MAX_MESSAGE_LENGTH = 5000

# Maximum unique URLs to examine in one message.
MAX_LINKS_PER_MESSAGE = 10


# Rule 1: Identify urgent language.
URGENCY_PATTERN = re.compile(
    r"\b(?:urgent|immediately|act now|right away|"
    r"today only|final warning|within \d{1,3}\s+"
    r"(?:minutes?|hours?))\b",
    re.IGNORECASE
)


# Rule 2: Identify account-related threats.
ACCOUNT_THREAT_PATTERN = re.compile(
    r"\b(?:account|card)\b.{0,40}"
    r"\b(?:blocked|suspended|locked|deactivated)\b",
    re.IGNORECASE
)


# Rule 3: Identify requests for sensitive information.
SENSITIVE_TERMS = (
    r"(?:password|otp|one[- ]time password|upi pin|pin|"
    r"cvv|card number|card details|bank details|login details)"
)

SENSITIVE_REQUEST_PATTERNS = (
    re.compile(
        rf"\b(?:share|send|provide|enter|submit|confirm|type)"
        rf"\s+(?:(?:me|us)\s+)?(?:your\s+)?{SENSITIVE_TERMS}\b",
        re.IGNORECASE
    ),
    re.compile(
        rf"\b(?:your\s+)?{SENSITIVE_TERMS}\b"
        rf".{{0,30}}\b(?:share|send|provide|enter|submit|confirm|type)\b",
        re.IGNORECASE
    )
)


# Avoid flagging common safety advice.
NEGATED_ACTION_PATTERN = re.compile(
    r"\b(?:never|don['’]t|do not|shouldn['’]t|"
    r"should not|must not)\s*$",
    re.IGNORECASE
)


# Rule 4: Identify prize and reward bait.
PRIZE_PATTERN = re.compile(
    r"\b(?:you have won|you are a winner|lottery|"
    r"prize|claim (?:your )?(?:reward|prize))\b",
    re.IGNORECASE
)


# Extract HTTP, HTTPS and www links from messages.
URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[^\s<>()]+",
    re.IGNORECASE
)


def extract_urls(message):
    """
    Extract unique URLs from a message.

    Trailing punctuation is removed so that a period
    at the end of a sentence is not included in the URL.
    """

    extracted_urls = []
    seen_urls = set()

    for match in URL_PATTERN.finditer(message):

        candidate = match.group(0).rstrip(".,!?;:)]}")

        if not candidate:
            continue

        if candidate not in seen_urls:

            seen_urls.add(candidate)
            extracted_urls.append(candidate)

    return extracted_urls


def has_sensitive_information_request(message):
    """Check whether the message requests sensitive information."""

    for pattern in SENSITIVE_REQUEST_PATTERNS:

        for match in pattern.finditer(message):

            prefix = message[
                max(0, match.start() - 35):match.start()
            ]

            if NEGATED_ACTION_PATTERN.search(prefix):
                continue

            return True

    return False


def analyze_message(message):
    """
    Analyse a message and its extracted website links.

    This function uses local rule-based checks.
    It does not visit or contact any website.
    """

    if not isinstance(message, str):
        raise TypeError("Message must be text.")

    message = message.strip()

    if not message:
        raise ValueError("Please enter a message to analyze.")

    if len(message) > MAX_MESSAGE_LENGTH:
        raise ValueError(
            f"Message must not exceed {MAX_MESSAGE_LENGTH} characters."
        )

    findings = []
    message_indicator_score = 0

    # Check urgent language.
    if URGENCY_PATTERN.search(message):

        findings.append({
            "code": "urgent_language",
            "label": "Urgent wording",
            "description": (
                "The message uses urgent language that may "
                "pressure the recipient to act quickly."
            ),
            "points": 2
        })

        message_indicator_score += 2

    # Check account threats.
    if ACCOUNT_THREAT_PATTERN.search(message):

        findings.append({
            "code": "account_threat",
            "label": "Account-related threat",
            "description": (
                "The message suggests that an account or card "
                "may be blocked, suspended or locked."
            ),
            "points": 2
        })

        message_indicator_score += 2

    # Check sensitive information requests.
    sensitive_request = has_sensitive_information_request(message)

    if sensitive_request:

        findings.append({
            "code": "sensitive_information_request",
            "label": "Sensitive information requested",
            "description": (
                "The message appears to request information "
                "such as an OTP, password, PIN or card details. "
                "Never share these in response to an unsolicited message."
            ),
            "points": 4
        })

        message_indicator_score += 4

    # Check prize-related language.
    if PRIZE_PATTERN.search(message):

        findings.append({
            "code": "prize_bait",
            "label": "Prize or reward language",
            "description": (
                "The message uses prize or reward language "
                "that may be intended to attract attention."
            ),
            "points": 1
        })

        message_indicator_score += 1

    # Extract unique URLs from the message.
    extracted_urls = extract_urls(message)

    # Analyse no more than the configured number of links.
    urls_to_analyze = extracted_urls[:MAX_LINKS_PER_MESSAGE]

    link_analyses = []

    for link_number, extracted_url in enumerate(
        urls_to_analyze,
        start=1
    ):

        try:

            url_result = analyze_url(extracted_url)

            link_analyses.append({
                "link_number": link_number,
                "hostname": url_result["hostname"],
                "risk_level": url_result["risk_level"],
                "indicator_score": url_result["indicator_score"],
                "findings": url_result["findings"],
                "summary": url_result["summary"],
                "analysis_status": "completed"
            })

        except (ValueError, TypeError):

            # Keep the message analysis running even when one
            # extracted URL cannot be parsed.
            link_analyses.append({
                "link_number": link_number,
                "hostname": None,
                "risk_level": "Not analyzed",
                "indicator_score": 0,
                "findings": [],
                "summary": (
                    "This extracted link could not be structurally "
                    "analysed. Check it carefully before interacting."
                ),
                "analysis_status": "not_analyzed"
            })

    # Record the presence of links separately from their analysis.
    if extracted_urls:

        findings.append({
            "code": "link_present",
            "label": "Website links included",
            "description": (
                "The message contains website links. "
                "Their structural warning signs are examined "
                "separately in the link analysis below."
            ),
            "points": 0
        })

    # Calculate combined indicator scores.
    url_indicator_score = sum(
        item["indicator_score"]
        for item in link_analyses
    )

    combined_indicator_score = (
        message_indicator_score + url_indicator_score
    )

    # Determine whether any examined URL has High indicators.
    high_risk_url_found = any(
        item["risk_level"] == "High"
        for item in link_analyses
    )

    # Determine the combined preliminary risk category.
    if (
        sensitive_request
        or high_risk_url_found
        or combined_indicator_score >= 5
    ):

        risk_level = "High"

        summary = (
            "The message or one of its extracted links contains "
            "several concerning indicators. Do not share sensitive "
            "information or follow suspicious instructions. "
            "Verify independently through an official channel."
        )

    elif combined_indicator_score >= 2:

        risk_level = "Medium"

        summary = (
            "Some warning signs were found in the message "
            "or its extracted links. Check the information "
            "carefully before taking action."
        )

    else:

        risk_level = "Low"

        summary = (
            "These configured checks did not find strong warning "
            "signs. This does not prove that the message or "
            "its links are safe."
        )

    # Report if the message contained more links than the limit.
    links_not_analyzed = max(
        0,
        len(extracted_urls) - MAX_LINKS_PER_MESSAGE
    )

    if links_not_analyzed:

        summary += (
            f" Additionally, {links_not_analyzed} link(s) "
            "were not analysed because the per-message link limit "
            "was reached."
        )

    return {
        "risk_level": risk_level,
        "indicator_score": combined_indicator_score,
        "message_indicator_score": message_indicator_score,
        "url_indicator_score": url_indicator_score,
        "link_count": len(extracted_urls),
        "links_analyzed": len(link_analyses),
        "links_not_analyzed": links_not_analyzed,
        "findings": findings,
        "link_analyses": link_analyses,
        "summary": summary,
        "disclaimer": (
            "This is a preliminary rule-based analysis, not "
            "a definitive fraud verdict. Extracted links are "
            "examined structurally only. CyberSaathi does not "
            "visit websites or verify their ownership, reputation, "
            "DNS records, redirects, certificates or page content."
        )
    }
