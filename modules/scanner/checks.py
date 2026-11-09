"""Non-destructive security checks orchestration."""

from __future__ import annotations

import requests

from config import DEFAULT_TIMEOUT
from core.models import Finding


def run_non_destructive_checks(url: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    """Coordinate non-destructive checks that do not perform brute force or active exploitation."""

    findings: list[Finding] = []

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    if response.status_code == 200:
        content = response.text.lower()
        if "<input type=\"password\"" in content or "password" in content:
            findings.append(
                Finding(
                    title="Potentially sensitive login exposure",
                    severity="Medium",
                    description="The page appears to contain a password field or password-related material in the rendered content.",
                    evidence=f"The URL returned a 200 response and includes login-related markup or text.",
                    recommendation="Review whether login forms are exposed in a way that aligns with the approved application design and authentication policy.",
                    target=url,
                    category="auth",
                )
            )

    return findings
