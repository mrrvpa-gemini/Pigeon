"""Response metadata display."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResponseView:
    """Captures only metadata from an outbound response."""

    status_code: int
    reason: str
    headers: dict[str, str]

    def summary(self) -> dict[str, object]:
        safe_headers = {
            key: value for key, value in self.headers.items() if key.lower() not in {"set-cookie", "authorization", "www-authenticate"}
        }
        return {
            "status_code": self.status_code,
            "reason": self.reason,
            "headers": safe_headers,
        }
