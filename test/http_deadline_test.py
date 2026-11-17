"""Deadline and idle timeouts against real sockets with stalled responses."""
from contextlib import closing
from http.client import HTTPConnection
from pathlib import Path
import sys
import time
import unittest
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import release
from release_test import local_http
from http_proxy_test import local_proxy, request


class HttpDeadlineTest(unittest.TestCase):
    def test_direct_stalled_body_reports_the_destination_deadline(self):
        with local_http({"/stall": [(200, {}, [(0.6, b"")])]}) as (base, observed):
            with self.assertRaisesRegex(ValueError, "destination deadline exceeded while reading response body"):
                release.verify_http_destinations([base + "/stall"], deadline_seconds=0.2)
            self.assertEqual(["/stall"], observed)

    def test_proxied_stalled_body_reports_the_destination_deadline(self):
        with local_http({"/stall": [(200, {}, [(0.6, b"")])]}) as (base, observed), local_proxy() as (proxy, forwarded):
            result = request([base + "/stall"], proxy=proxy, deadline=0.2)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("destination deadline exceeded while reading response body", result.stdout)
            self.assertEqual(["/stall"], observed)
            self.assertEqual([("GET", base + "/stall")], forwarded)

    def test_read1_expiry_is_chained_to_the_socket_timeout(self):
        with local_http({"/stall": [(200, {}, [(0.6, b"")])]}) as (base, observed):
            url = urlsplit(base)
            with closing(HTTPConnection(url.hostname, url.port, timeout=1)) as connection:
                connection.request("GET", "/stall")
                sock = connection.sock
                with connection.getresponse() as response:
                    with self.assertRaisesRegex(TimeoutError, "destination deadline exceeded while reading response body") as caught:
                        release.read_response_body(response, sock, time.monotonic() + 0.1)
                    # A loop-boundary expiry has no cause. This receipt proves
                    # the timeout came from the actual blocking read1 call.
                    self.assertIsInstance(caught.exception.__cause__, TimeoutError)
                    self.assertEqual("timed out", str(caught.exception.__cause__))
            self.assertEqual(["/stall"], observed)

    def test_idle_timeout_before_the_deadline_stays_a_transport_timeout(self):
        with local_http({"/stall": [(200, {}, [(0.6, b"")])]}) as (base, observed):
            url = urlsplit(base)
            with closing(HTTPConnection(url.hostname, url.port, timeout=1)) as connection:
                connection.request("GET", "/stall")
                sock = connection.sock
                with connection.getresponse() as response:
                    deadline = time.monotonic() + 2
                    with self.assertRaisesRegex(TimeoutError, "^timed out$") as caught:
                        release.read_response_body(response, sock, deadline, socket_timeout=0.05)
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertLess(time.monotonic(), deadline)
            self.assertEqual(["/stall"], observed)

    def test_direct_and_proxied_header_stalls_report_the_deadline(self):
        with local_http({"/stall": [200]}, response_delay=0.6) as (base, observed), local_proxy() as (proxy, forwarded):
            with self.assertRaisesRegex(ValueError, "destination deadline exceeded while reading response headers"):
                release.verify_http_destinations([base + "/stall"], deadline_seconds=0.2)
            result = request([base + "/stall"], proxy=proxy, deadline=0.2)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("destination deadline exceeded while reading response headers", result.stdout)
            self.assertEqual(["/stall", "/stall"], observed)
            self.assertEqual([("GET", base + "/stall")], forwarded)

    def test_stalled_connect_tunnel_reports_the_deadline(self):
        with local_http({"/ok": [200]}) as (base, observed), local_proxy(connect_delay=0.6) as (proxy, forwarded):
            # The proxy stalls before acknowledging CONNECT. No TLS or HTTP
            # request reaches the origin, which waits on its real socket.
            destination = base.replace("http://", "https://") + "/ok"
            result = request([destination], proxy=proxy, deadline=0.2)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("destination deadline exceeded while connecting or sending request", result.stdout)
            self.assertEqual([], observed)
            self.assertEqual([("CONNECT", urlsplit(base).netloc)], forwarded)


if __name__ == "__main__":
    unittest.main()
