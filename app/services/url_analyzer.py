
import ipaddress
import re

from urllib.parse import urlsplit


# Maximum URL length accepted by our analyzer.
MAX_URL_LENGTH = 2048


# Known URL-shortening services.
# These are indicators, not proof of malicious activity.
SHORTENER_DOMAINS = frozenset({
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "shorturl.at",
    "rb.gy"
})


def _parse_url(url):
    """
    Parse and perform basic structural validation.

    URLs without a scheme are treated as HTTPS.
    No network connection is made.
    """

    try:
        initial = urlsplit(url)
    except ValueError as error:
        raise ValueError("The URL format is invalid.") from error

    # Accept only HTTP and HTTPS.
    if initial.scheme:
        if initial.scheme.lower() in ("http", "https"):
            normalized_url = url
        elif re.match(
            r"^[A-Za-z0-9.-]+:\d+(?:/|$)",
            url
        ):
            # Allow a hostname with a port but no scheme.
            normalized_url = "https://" + url
        else:
            raise ValueError(
                "Only HTTP and HTTPS URLs are supported."
            )

    elif url.startswith("//"):
        normalized_url = "https:" + url

    else:
        normalized_url = "https://" + url

    # Parse the normalized URL and validate its hostname and port.
    try:
        parsed = urlsplit(normalized_url)
        hostname = parsed.hostname

        # Reject an explicitly supplied but empty port.
        host_port = parsed.netloc.rsplit("@", 1)[-1]

        if host_port.endswith(":"):
            raise ValueError("The URL contains an empty port.")

        # Validate the port number.
        parsed.port

    except ValueError as error:
        raise ValueError(
            "The URL contains an invalid hostname or port."
        ) from error

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Unsupported URL scheme.")

    if not parsed.netloc or not hostname:
        raise ValueError("The URL must contain a hostname.")

    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError("The URL must contain a valid hostname.")

    return parsed, hostname


def analyze_url(url):
    """
    Analyze URL characteristics using explainable rules.

    Returns:
        risk_level
        indicator_score
        findings
        summary
        disclaimer

    This function never visits the supplied URL.
    """

    if not isinstance(url, str):
        raise TypeError("URL must be text.")

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL to analyze.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError(
            f"URL must not exceed {MAX_URL_LENGTH} characters."
        )

    # Reject spaces and control characters.
    if any(
        character.isspace()
        or ord(character) < 32
        or ord(character) == 127
        for character in url
    ):
        raise ValueError(
            "The URL must not contain spaces or control characters."
        )

    # Reject backslashes because browsers and URL parsers
    # may interpret them differently.
    if "\\" in url:
        raise ValueError(
            "The URL must not contain backslashes."
        )

    parsed, hostname = _parse_url(url)

    findings = []
    indicator_score = 0

    def add_finding(code, label, description, points):
        nonlocal indicator_score

        findings.append({
            "code": code,
            "label": label,
            "description": description,
            "points": points
        })

        indicator_score += points

    # Rule 1: Embedded username or password.
    has_credentials = (
        parsed.username is not None
        or parsed.password is not None
    )

    if has_credentials:
        add_finding(
            "embedded_credentials",
            "Credentials embedded in URL",
            (
                "The URL contains username or password information "
                "before its hostname. This structure can disguise "
                "the actual destination."
            ),
            4
        )

    # Rule 2: Check whether the hostname is an IP address.
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True

    except ValueError:
        pass

    is_punycode = False
    ascii_hostname = hostname

    if not is_ip_address:

        try:
            ascii_hostname = (
                hostname.encode("idna")
                .decode("ascii")
                .lower()
            )

        except UnicodeError as error:
            raise ValueError(
                "The domain name contains invalid characters."
            ) from error

        labels = ascii_hostname.split(".")

        # Validate the basic hostname structure.
        if (
            len(ascii_hostname) > 253
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(
                    character.isalnum() or character == "-"
                    for character in label
                )
                for label in labels
            )
        ):
            raise ValueError("The domain name is invalid.")

        # Reject malformed dotted numeric IPv4-style addresses.
        if (
            len(labels) == 4
            and all(label.isdigit() for label in labels)
        ):
            raise ValueError("The IPv4 address is invalid.")

        # Rule 3: Identify Punycode labels.
        is_punycode = any(
            label.startswith("xn--")
            for label in labels
        )

    # Rule 4: Identify IP-address hostnames.
    if is_ip_address:
        add_finding(
            "ip_address_host",
            "IP address used as hostname",
            (
                "The URL uses a numeric IP address instead "
                "of a conventional domain name. This deserves "
                "additional scrutiny, but is not proof of fraud."
            ),
            4
        )

    # Rule 5: Identify Punycode domains.
    if is_punycode:
        add_finding(
            "punycode_domain",
            "Internationalised domain encoding",
            (
                "The domain contains a Punycode label beginning "
                "with xn--. Internationalised domains can be "
                "legitimate, but unusual lookalike characters "
                "deserve careful examination."
            ),
            3
        )

    # Rule 6: Identify known URL-shortening services.
    is_shortened_url = any(
        ascii_hostname == domain
        or ascii_hostname.endswith("." + domain)
        for domain in SHORTENER_DOMAINS
    )

    if is_shortened_url:
        add_finding(
            "shortened_url",
            "Known URL-shortening service",
            (
                "The URL uses a recognised shortening service. "
                "The final destination is hidden until the "
                "redirect is resolved."
            ),
            2
        )

    # Rule 7: Identify unencrypted HTTP.
    if parsed.scheme.lower() == "http":
        add_finding(
            "unencrypted_http",
            "Unencrypted HTTP connection",
            (
                "The URL uses HTTP rather than HTTPS. "
                "The connection does not provide HTTPS transport "
                "encryption. This alone does not establish "
                "that the website is malicious."
            ),
            1
        )

    # Determine the preliminary risk category.
    if has_credentials or indicator_score >= 5:

        risk_level = "High"

        summary = (
            "Several concerning URL characteristics were found. "
            "Avoid entering personal information and verify the "
            "destination independently."
        )

    elif indicator_score >= 2:

        risk_level = "Medium"

        summary = (
            "One or more URL characteristics deserve attention. "
            "Check the destination carefully before interacting "
            "with the website."
        )

    else:

        risk_level = "Low"

        summary = (
            "No configured URL warning patterns were detected. "
            "This does not prove that the website is safe."
        )

    return {
        "risk_level": risk_level,
        "indicator_score": indicator_score,
        "hostname": ascii_hostname,
        "findings": findings,
        "summary": summary,
        "disclaimer": (
            "This is a preliminary structural URL analysis. "
            "CyberSaathi does not visit the website or verify "
            "its ownership, reputation, DNS records, redirects, "
            "security certificate or page content."
        )
    }