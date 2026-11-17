"""Proxy configuration on actual stdlib connection objects, without sockets."""
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
import sys
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release


class HttpRoutesTest(unittest.TestCase):
    def test_proxy_port_defaults_follow_the_selected_connection_class(self):
        for scheme, proxy, connection_class, port in (
            ("http", "http://example.com", HTTPConnection, 80),
            ("http", "https://example.com", HTTPSConnection, 443),
            ("http", "example.com", HTTPConnection, 80),
            ("https", "http://example.com", HTTPSConnection, 443),
            ("https", "https://example.com", HTTPSConnection, 443),
            ("https", "example.com", HTTPSConnection, 443),
            ("https", "http://example.com:8080", HTTPSConnection, 8080),
            ("https", "http://example.com%3A8080", HTTPSConnection, 8080),
            ("https", "http://example.com:0", HTTPSConnection, 0),
        ):
            with self.subTest(scheme=scheme, proxy=proxy):
                connection, path, headers = release.destination_connection(
                    urlsplit(scheme + "://example.com/a?b=c#fragment"), proxy, timeout=0.25)
                try:
                    self.assertIsInstance(connection, connection_class)
                    self.assertEqual(port, connection.port)
                    self.assertEqual("example.com", connection.host)
                    self.assertIsNone(connection.sock)
                    self.assertEqual("/a?b=c" if scheme == "https" else scheme + "://example.com/a?b=c", path)
                finally:
                    connection.close()

    def test_a_user_without_a_password_does_not_send_proxy_authorization(self):
        for authority in ("example.com:8080", "synthetic-user@example.com:8080",
                          "synthetic-user:@example.com:8080", ":synthetic-password@example.com:8080"):
            with self.subTest(has_userinfo="@" in authority):
                connection, _, headers = release.destination_connection(
                    urlsplit("http://example.com/path"), "http://" + authority, timeout=1)
                try:
                    self.assertNotIn("Proxy-Authorization", headers)
                finally:
                    connection.close()


if __name__ == "__main__":
    unittest.main()
