import unittest

from core.scope import Scope


class ScopeTests(unittest.TestCase):
    def test_allowed_example_host(self):
        scope = Scope()
        validated = scope.validate_target("https://example.com")
        self.assertEqual(validated.host, "example.com")

    def test_rejects_unapproved_host(self):
        scope = Scope()
        with self.assertRaises(Exception):
            scope.validate_target("https://not-allowed.example")


if __name__ == "__main__":
    unittest.main()
