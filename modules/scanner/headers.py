"""HTTP security header scanning."""

from __future__ import annotations

from typing import Any

import requests

from config import DEFAULT_TIMEOUT
from core.models import Finding


def check_security_headers(url: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    """Check a set of recommended HTTP security headers."""

    findings: list[Finding] = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    required = {
        "content-security-policy": ("Medium", "CSP is missing or weak; consider adding a strict policy."),
        "x-frame-options": ("Medium", "Frame embedding is not restricted; clickjacking risk may exist."),
        "x-content-type-options": ("Low", "Browser MIME sniffing may be allowed."),
        "referrer-policy": ("Low", "Referrer leakage may happen across pages."),
        "permissions-policy": ("Low", "Browser permissions are not restricted."),
        "strict-transport-security": ("High", "Transport security is not enforced for HTTPS."),
    }

    for header_name, (severity, description) in required.items():
        if header_name not in headers:
            findings.append(
                Finding(
                    title=f"Missing HTTP header: {header_name}",
                    severity=severity,
                    description=description,
                    evidence=f"Response from {url} does not include header '{header_name}'.",
                    recommendation="Add a restrictive policy to match the application's expected behavior and browser support.",
                    target=url,
                    category="headers",
                )
            )

    return findings
