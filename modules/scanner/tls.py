"""TLS and certificate metadata checks."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any

import requests

from config import DEFAULT_TIMEOUT
from core.models import Finding


def _extract_certificate_info(hostname: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            return {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "serialNumber": cert.get("serialNumber"),
                "version": cert.get("version"),
            }


def check_tls_metadata(url: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    """Collect passive TLS metadata and highlight weak certificate configurations."""

    findings: list[Finding] = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return findings

    host = response.url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    port = 443 if response.url.startswith("https://") else 80

    if response.url.startswith("https://"):
        try:
            cert = _extract_certificate_info(host, port)
        except Exception:
            return findings

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                delta = (expiry - datetime.utcnow()).days
                if delta < 30:
                    findings.append(
                        Finding(
                            title="TLS certificate expires soon",
                            severity="Medium",
                            description="The TLS certificate is due to expire within 30 days.",
                            evidence=f"Certificate for {host} expires on {not_after}.",
                            recommendation="Renew the certificate before it expires and monitor renewal schedules.",
                            target=url,
                            category="tls",
                        )
                    )
            except ValueError:
                pass

        subject = cert.get("subject")
        if subject:
            subject_summary = str(subject)
            if "CN=localhost" in subject_summary or "CN=example" in subject_summary.lower():
                findings.append(
                    Finding(
                        title="Certificate subject indicates a test or placeholder identity",
                        severity="Low",
                        description="The certificate subject appears to be a development or placeholder value.",
                        evidence=f"Certificate subject: {subject_summary}",
                        recommendation="Use an explicitly approved certificate subject that matches production identity and operational policy.",
                        target=url,
                        category="tls",
                    )
                )

    return findings
