
import re


# Maximum message size accepted by this analyzer.
MAX_MESSAGE_LENGTH = 5000


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


# Avoid flagging common safety advice such as
# "Never share your OTP".
NEGATED_ACTION_PATTERN = re.compile(
    r"\b(?:never|don['’]t|do not|shouldn['’]t|"
    r"should not|must not)\s*$",
    re.IGNORECASE
)


# Rule 4: Identify common prize and reward bait.
PRIZE_PATTERN = re.compile(
    r"\b(?:you have won|you are a winner|lottery|"
    r"prize|claim (?:your )?(?:reward|prize))\b",
    re.IGNORECASE
)


# Identify whether the message contains a website link.
URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[^\s<>()]+",
    re.IGNORECASE
)


def has_sensitive_information_request(message):
    """Check whether the message asks for sensitive information."""

    for pattern in SENSITIVE_REQUEST_PATTERNS:

        for match in pattern.finditer(message):

            prefix = message[max(0, match.start() - 35):match.start()]

            if NEGATED_ACTION_PATTERN.search(prefix):
                continue

            return True

    return False


def analyze_message(message):
    """
    Analyze a message using basic, explainable rules.

    Returns a dictionary containing:
    - risk_level
    - indicator_score
    - findings
    - summary
    - disclaimer
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
    indicator_score = 0

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

        indicator_score += 2

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

        indicator_score += 2

    # Check requests for sensitive information.
    sensitive_request = has_sensitive_information_request(message)

    if sensitive_request:

        findings.append({
            "code": "sensitive_information_request",
            "label": "Sensitive information requested",
            "description": (
                "The message appears to ask for information such "
                "as an OTP, password, PIN or card details. "
                "Never share these in response to an unsolicited message."
            ),
            "points": 4
        })

        indicator_score += 4

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

        indicator_score += 1

    # Identify links without claiming to verify them.
    if URL_PATTERN.search(message):

        findings.append({
            "code": "link_present",
            "label": "Website link included",
            "description": (
                "The message contains a website link. "
                "Its destination and reputation have not "
                "been checked by this message analyzer."
            ),
            "points": 0
        })

    # Calculate the preliminary risk category.
    if sensitive_request or indicator_score >= 5:
        risk_level = "High"

        summary = (
            "Several concerning indicators were found. "
            "Do not share sensitive information or follow "
            "the message's instructions. Verify independently "
            "through the organisation's official channel."
        )

    elif indicator_score >= 2:
        risk_level = "Medium"

        summary = (
            "Some warning signs were found. Check the sender "
            "through a trusted channel before taking action."
        )

    else:
        risk_level = "Low"

        summary = (
            "These basic checks did not find strong warning signs. "
            "This does not prove that the message is safe."
        )

    return {
        "risk_level": risk_level,
        "indicator_score": indicator_score,
        "findings": findings,
        "summary": summary,
        "disclaimer": (
            "This is a preliminary rule-based analysis, not "
            "a definitive fraud verdict. Sender identity, "
            "domain reputation and link destinations are "
            "not verified by this analyzer."
        )
    }
