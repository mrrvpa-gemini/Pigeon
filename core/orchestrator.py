"""High-level orchestration for recon, scanning, validation, and reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import DEFAULT_REPORT_FILENAME, DEFAULT_VALIDATION_OUTPUT
from core.exceptions import ValidationError
from core.logger import get_logger
from core.models import Finding, ValidationResult
from core.scope import Scope
from modules.exploitation.validation import ValidationEngine
from modules.recon.dns import resolve_hostname
from modules.recon.http_info import fetch_http_metadata
from modules.recon.technologies import detect_technologies
from modules.reporting.html_report import generate_html_report
from modules.scanner.checks import run_non_destructive_checks
from modules.scanner.headers import check_security_headers
from modules.scanner.tls import check_tls_metadata
from modules.proxy.proxy_server import ProxyServer

LOGGER = get_logger("orchestrator")


class Orchestrator:
    """Coordinates safe testing tasks."""

    def __init__(self, allowed_hosts: set[str] | None = None):
        self.scope = Scope(allowed_hosts)

    def run_recon(self, target: str) -> dict[str, Any]:
        validated = self.scope.validate_target(target)
        dns_result = resolve_hostname(validated.host)
        http_result = fetch_http_metadata(validated.url)
        technologies = detect_technologies(http_result.get("headers", {}), http_result.get("body_sample", ""))

        return {
            "target": validated.url,
            "host": validated.host,
            "scheme": validated.scheme,
            "dns": dns_result,
            "http": http_result,
            "technologies": technologies,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    def run_scan(self, target: str) -> list[Finding]:
        validated = self.scope.validate_target(target)
        findings: list[Finding] = []

        findings.extend(check_security_headers(validated.url))
        findings.extend(check_tls_metadata(validated.url))
        findings.extend(run_non_destructive_checks(validated.url))

        deduped: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            key = f"{finding.title}:{finding.severity}:{finding.category}"
            if key in seen:
                continue
            deduped.append(finding)
            seen.add(key)
        return deduped

    def generate_html_report(self, target: str, findings: list[Finding], output_name: str = DEFAULT_REPORT_FILENAME) -> str:
        validated = self.scope.validate_target(target)
        report_path = Path(output_name)
        if report_path.parent and not report_path.parent.exists():
            report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path = report_path.resolve()
        html_report = generate_html_report(validated.url, findings, str(report_path))
        return str(report_path)

    def run_proxy(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        proxy = ProxyServer(host=host, port=port)
        proxy.serve_forever()

    def validate_finding(self, title: str, description: str, evidence: str, output_name: str = DEFAULT_VALIDATION_OUTPUT) -> dict[str, Any]:
        engine = ValidationEngine()
        result = engine.validate(title=title, description=description, evidence=evidence)
        output_path = Path(output_name)
        if output_path.parent and not output_path.parent.exists():
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        return result.to_dict()
