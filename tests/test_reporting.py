import os
import tempfile
import unittest

from modules.reporting.html_report import generate_html_report
from core.models import Finding


class ReportingTests(unittest.TestCase):
    def test_html_escaping_preserves_markup_and_escapes_values(self):
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
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "report.html")
            generate_html_report("https://example.com", findings, path)
            with open(path, "r", encoding="utf-8") as report_file:
                content = report_file.read()
        self.assertIn("<tr>", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", content)
        self.assertNotIn("<script>alert(1)</script>", content)


if __name__ == "__main__":
    unittest.main()
