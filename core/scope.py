"""Scope validation and target checks."""

from __future__ import annotations

from urllib.parse import urlparse

from config import DEFAULT_ALLOWED_HOSTS, get_allowed_hosts
from core.exceptions import ValidationError


class Scope:
    """A strict but practical target validation layer for safe testing."""

    def __init__(self, allowed_hosts: set[str] | None = None):
        self.allowed_hosts = {host.lower().strip() for host in (allowed_hosts or get_allowed_hosts()) if host}

    def _is_allowed_host(self, host: str) -> bool:
        normalized = (host or "").lower().strip()
        if not normalized:
            return False
        if normalized in self.allowed_hosts:
            return True
        if normalized.startswith("."):
            normalized = normalized.lstrip(".")
        if normalized.endswith(".example"):
            return True
        return False

    def validate_target(self, target: str) -> "ValidatedTarget":
        if not target or not str(target).strip():
            raise ValidationError("Target URL is required.")

        url = str(target).strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValidationError("Only http:// and https:// URLs are supported.")
        if not parsed.netloc:
            raise ValidationError("Target URL is incomplete.")

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            raise ValidationError("Could not parse target hostname.")

        if hostname in {"localhost", "127.0.0.1", "::1"} and not self._is_allowed_host(hostname):
            raise ValidationError("Loopback targets are not allowed by default.")

        if not self._is_allowed_host(hostname):
            raise ValidationError(
                f"Target host '{hostname}' is not in the authorized scope. "
                "Set RVPA_ALLOWED_HOSTS or use an approved domain."
            )

        return ValidatedTarget(url=url, scheme=parsed.scheme, host=hostname, port=parsed.port or (443 if parsed.scheme == "https" else 80))


class ValidatedTarget:
    """Small value object for validated URL data."""

    def __init__(self, url: str, scheme: str, host: str, port: int):
        self.url = url
        self.scheme = scheme
        self.host = host
        self.port = port

    def __str__(self) -> str:
        return self.url
