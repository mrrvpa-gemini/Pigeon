"""Scope validation and target checks."""

from __future__ import annotations

from urllib.parse import urlparse

from config import get_allowed_hosts
from core.exceptions import ValidationError


class Scope:
    """Strict target validation based on an explicit allowlist."""

    def __init__(self, allowed_hosts: set[str] | None = None):
        configured_hosts = get_allowed_hosts() if allowed_hosts is None else allowed_hosts
        self.allowed_hosts = {
            str(host).lower().strip().rstrip(".")
            for host in configured_hosts
            if str(host).strip()
        }

    def _is_allowed_host(self, host: str) -> bool:
        normalized = (host or "").lower().strip().rstrip(".")
        return bool(normalized) and normalized in self.allowed_hosts

    def validate_target(self, target: str) -> "ValidatedTarget":
        if not target or not str(target).strip():
            raise ValidationError("Target URL is required.")

        url = str(target).strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValidationError("Only http:// and https:// URLs are supported.")
        if not parsed.netloc:
            raise ValidationError("Target URL is incomplete.")
        if parsed.username is not None or parsed.password is not None:
            raise ValidationError("Credentials must not be embedded in the target URL.")

        hostname = (parsed.hostname or "").lower().strip().rstrip(".")
        if not hostname:
            raise ValidationError("Could not parse target hostname.")

        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ValidationError("Target URL contains an invalid port.") from exc
        if not 1 <= port <= 65535:
            raise ValidationError("Target URL port must be between 1 and 65535.")

        if not self._is_allowed_host(hostname):
            raise ValidationError(
                f"Target host '{hostname}' is not in the authorized scope. "
                "Add the exact authorized hostname to RVPA_ALLOWED_HOSTS."
            )

        return ValidatedTarget(url=url, scheme=parsed.scheme, host=hostname, port=port)


class ValidatedTarget:
    """Small value object for validated URL data."""

    def __init__(self, url: str, scheme: str, host: str, port: int):
        self.url = url
        self.scheme = scheme
        self.host = host
        self.port = port

    def __str__(self) -> str:
        return self.url
