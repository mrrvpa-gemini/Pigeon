"""Request metadata display."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RequestView:
    """Captures only metadata from an incoming HTTP request."""

    method: str
    target: str
    headers: dict[str, str]
    host: str

    def summary(self) -> dict[str, object]:
        return {
            "method": self.method,
            "target": self.target,
            "host": self.host,
            "headers": {
                key: value for key, value in self.headers.items() if key.lower() not in {"authorization", "cookie", "set-cookie", "proxy-authorization"}
            },
        }
