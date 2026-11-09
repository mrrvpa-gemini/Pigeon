"""Passive technology detection based on HTTP indicators."""

from __future__ import annotations

from typing import Any


def detect_technologies(headers: dict[str, Any], body_sample: str) -> list[str]:
    """Return a list of likely technologies inferred from headers and HTML markers."""

    technologies: list[str] = []
    hint_map = {
        "server": {
            "nginx": "nginx",
            "apache": "Apache HTTP Server",
            "gunicorn": "gunicorn",
            "werkzeug": "Werkzeug",
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "iis": "Internet Information Services",
        },
        "x-powered-by": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
        },
    }

    normalized_headers = {str(key).lower(): str(value).lower() for key, value in headers.items()}
    for key, mapping in hint_map.items():
        value = normalized_headers.get(key)
        if value:
            for needle, label in mapping.items():
                if needle in value:
                    technologies.append(label)

    if "aspnet" in body_sample.lower() or "__viewstate" in body_sample.lower():
        technologies.append("ASP.NET")
    if "wp-content" in body_sample.lower() or "wordpress" in body_sample.lower():
        technologies.append("WordPress")
    if "react" in body_sample.lower() or "__NEXT_DATA__" in body_sample.lower():
        technologies.append("React")

    # Deduplicate while preserving order.
    unique: list[str] = []
    for item in technologies:
        if item not in unique:
            unique.append(item)
    return unique
