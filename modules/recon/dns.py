"""DNS resolution helpers."""

from __future__ import annotations

import socket


def resolve_hostname(hostname: str) -> dict[str, object]:
    """Resolve a hostname to IP addresses without using invasive scanning."""

    host = (hostname or "").strip()
    if not host:
        return {"hostname": host, "addresses": [], "error": "Hostname is empty."}

    try:
        addresses = []
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in addresses:
                addresses.append(ip)
        return {"hostname": host, "addresses": addresses}
    except socket.gaierror as exc:
        return {"hostname": host, "addresses": [], "error": str(exc)}
