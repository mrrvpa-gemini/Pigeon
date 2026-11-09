"""HTTP metadata collection helpers."""

from __future__ import annotations

from typing import Any

import requests

from config import DEFAULT_TIMEOUT


def fetch_http_metadata(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Collect non-invasive HTTP response metadata."""

    headers = {
        "User-Agent": "RvpaPentestToolkit/1.0 (+safe recon)",
        "Accept": "text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return {
            "status_code": response.status_code,
            "final_url": response.url,
            "content_type": response.headers.get("Content-Type"),
            "server": response.headers.get("Server"),
            "headers": dict(response.headers),
            "elapsed_seconds": round(response.elapsed.total_seconds(), 3),
            "redirect_count": len(response.history),
            "body_sample": response.text[:2000],
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "status_code": None,
            "final_url": url,
            "content_type": None,
            "server": None,
            "headers": {},
            "elapsed_seconds": None,
            "redirect_count": 0,
            "body_sample": "",
            "error": str(exc),
        }
