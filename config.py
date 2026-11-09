"""Configuration values for the Rvpa Pentest Toolkit."""

from __future__ import annotations

import os
from typing import Iterable

APP_NAME = "Rvpa Pentest Toolkit"
APP_VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10
DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8080
DEFAULT_REPORT_FILENAME = "report.html"
DEFAULT_VALIDATION_OUTPUT = "validation_results.json"

DEFAULT_ALLOWED_HOSTS: set[str] = {
    "authorized-target.example",
    "example.com",
    "localhost",
    "127.0.0.1",
    "::1",
}


def get_allowed_hosts() -> set[str]:
    raw = os.getenv("RVPA_ALLOWED_HOSTS", "")
    if not raw:
        return set(DEFAULT_ALLOWED_HOSTS)
    hosts = {item.strip().lower() for item in raw.split(",") if item.strip()}
    return hosts or set(DEFAULT_ALLOWED_HOSTS)


def ensure_safe_scope(scope: Iterable[str]) -> set[str]:
    return {str(item).strip().lower() for item in scope if str(item).strip()}
