import unittest

from modules.reporting.html_report import generate_html_report
from core.models import Finding


class ReportingTests(unittest.TestCase):
    def test_html_escaping(self):
        findings = [
            Finding(
                title="<script>alert(1)</script>",
                severity="High",
                description="<b>bad</b>",
                evidence="<img src=x onerror=alert(1)>",
                recommendation="Use escaping.",
                target="https://example.com",
                category="test",
            )
        ]
        path = "test_report.html"
        generate_html_report("https://example.com", findings, path)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)


if __name__ == "__main__":
    unittest.main()
