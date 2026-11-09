"""HTML report generation with escaping for safe rendering."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from core.models import Finding


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def generate_html_report(target: str, findings: Iterable[Finding], output_path: str) -> str:
    """Generate a responsive HTML report; escape values, not the generated markup."""

    finding_list = list(findings)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in finding_list:
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1

    rows_html = "".join(
        """
        <tr>
            <td>{title}</td>
            <td class="severity {severity}">{severity}</td>
            <td>{category}</td>
            <td>{description}</td>
            <td>{evidence}</td>
            <td>{recommendation}</td>
        </tr>
        """.format(
            title=_escape(item.title),
            severity=_escape(item.severity),
            category=_escape(item.category),
            description=_escape(item.description),
            evidence=_escape(item.evidence),
            recommendation=_escape(item.recommendation),
        )
        for item in finding_list
    )

    template_path = Path(__file__).with_name("templates") / "report.html"
    template = template_path.read_text(encoding="utf-8")
    rendered = template.format(
        generated_at=_escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
        target=_escape(target),
        total_findings=_escape(str(len(finding_list))),
        critical=_escape(str(severity_counts.get("Critical", 0))),
        high=_escape(str(severity_counts.get("High", 0))),
        medium=_escape(str(severity_counts.get("Medium", 0))),
        low=_escape(str(severity_counts.get("Low", 0))),
        info=_escape(str(severity_counts.get("Info", 0))),
        # rows_html contains only fixed markup plus individually escaped fields.
        rows=rows_html,
    )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    return str(output)
