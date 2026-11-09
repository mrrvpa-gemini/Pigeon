import unittest

from modules.recon.dns import resolve_hostname


class ReconTests(unittest.TestCase):
    def test_resolve_localhost(self):
        result = resolve_hostname("localhost")
        self.assertIn("hostname", result)
        self.assertEqual(result["hostname"], "localhost")


if __name__ == "__main__":
    unittest.main()
