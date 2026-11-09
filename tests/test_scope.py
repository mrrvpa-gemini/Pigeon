import unittest

from core.exceptions import ValidationError
from core.scope import Scope


class ScopeTests(unittest.TestCase):
    def test_allowed_example_host(self):
        scope = Scope()
        validated = scope.validate_target("https://example.com")
        self.assertEqual(validated.host, "example.com")

    def test_rejects_unapproved_host(self):
        scope = Scope()
        with self.assertRaises(ValidationError):
            scope.validate_target("https://not-allowed.example")

    def test_explicit_allowlist_does_not_fall_back_to_defaults(self):
        scope = Scope(allowed_hosts={"approved.test"})
        with self.assertRaises(ValidationError):
            scope.validate_target("https://example.com")


if __name__ == "__main__":
    unittest.main()
