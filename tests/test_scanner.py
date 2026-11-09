import unittest

from core.models import Finding
from modules.scanner.headers import check_security_headers


class ScannerTests(unittest.TestCase):
    def test_security_header_finding(self):
        findings = check_security_headers("https://example.com")
        self.assertIsInstance(findings, list)
        self.assertTrue(all(isinstance(item, Finding) for item in findings))


if __name__ == "__main__":
    unittest.main()
