
import os
import re
from urllib.parse import urlsplit

import requests


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
REQUEST_TIMEOUT = 8


def lookup_urlhaus(url, auth_key=None):
    """
    Check whether a URL is listed in URLhaus.

    URLs without a scheme are treated as HTTPS.

    Possible statuses:
    - found: URL exists in URLhaus
    - not_found: URL is not listed in URLhaus
    - unavailable: lookup could not be completed
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "status": "unavailable",
            "reason": "invalid_url",
        }

    url = url.strip()

    # Normalize URLs using the same scheme rules
    # as the structural URL analyzer.
    try:
        initial = urlsplit(url)

        if initial.scheme:

            if initial.scheme.lower() in ("http", "https"):
                normalized_url = url

            elif re.match(
                r"^[A-Za-z0-9.-]+:\d+(?:/|$)",
                url
            ):
                normalized_url = "https://" + url

            else:
                return {
                    "status": "unavailable",
                    "reason": "invalid_url",
                }

        elif url.startswith("//"):
            normalized_url = "https:" + url

        else:
            normalized_url = "https://" + url

        parsed_url = urlsplit(normalized_url)

        if (
            parsed_url.scheme.lower() not in ("http", "https")
            or not parsed_url.hostname
        ):
            return {
                "status": "unavailable",
                "reason": "invalid_url",
            }

        parsed_url.port

    except ValueError:
        return {
            "status": "unavailable",
            "reason": "invalid_url",
        }

    if auth_key is None:
        auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not isinstance(auth_key, str) or not auth_key.strip():
        return {
            "status": "unavailable",
            "reason": "not_configured",
        }

    headers = {
        "Auth-Key": auth_key.strip(),
    }

    data = {
        "url": normalized_url,
    }

    try:
        response = requests.post(
            URLHAUS_API_URL,
            data=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        response.raise_for_status()

    except requests.Timeout:
        return {
            "status": "unavailable",
            "reason": "timeout",
        }

    except requests.RequestException:
        return {
            "status": "unavailable",
            "reason": "request_error",
        }

    try:
        result = response.json()

    except ValueError:
        return {
            "status": "unavailable",
            "reason": "invalid_response",
        }

    if not isinstance(result, dict):
        return {
            "status": "unavailable",
            "reason": "invalid_response",
        }

    query_status = result.get("query_status")

    if query_status == "no_results":
        return {
            "status": "not_found",
            "source": "URLhaus",
        }

    if query_status == "ok":
        return {
            "status": "found",
            "source": "URLhaus",
            "url_status": result.get("url_status"),
            "threat": result.get("threat"),
            "date_added": result.get("date_added"),
            "reference": result.get("urlhaus_reference"),
        }

    return {
        "status": "unavailable",
        "reason": "unexpected_api_response",
    }
