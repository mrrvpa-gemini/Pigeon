import unittest

from config import DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT


class ProxyTests(unittest.TestCase):
    def test_proxy_defaults(self):
        self.assertEqual(DEFAULT_PROXY_HOST, "127.0.0.1")
        self.assertEqual(DEFAULT_PROXY_PORT, 8080)


if __name__ == "__main__":
    unittest.main()
