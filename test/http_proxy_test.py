"""Real HTTP forwarding and CONNECT tunnels for publication destination checks."""
from contextlib import contextmanager
import base64
import os
from pathlib import Path
import selectors
import socket
import socketserver
import ssl
import sys
import threading
import time
import unittest
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from processes import run, temporary_directory
from release_test import local_http


@contextmanager
def local_proxy(*, credentials=None, connect_delay=0):
    requests = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            method, target, protocol = self.rfile.readline().decode("ascii").strip().split(" ", 2)
            headers = []
            while line := self.rfile.readline():
                if line in (b"\r\n", b"\n"):
                    break
                headers.append(line)
            requests.append((method, target))
            if credentials is not None:
                authorization = b"Basic " + base64.b64encode(":".join(credentials).encode())
                supplied = next((line.split(b":", 1)[1].strip() for line in headers
                                 if line.lower().startswith(b"proxy-authorization:")), None)
                if supplied != authorization:
                    self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                                     b'Proxy-Authenticate: Basic realm="local-test"\r\n'
                                     b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                    self.wfile.flush()
                    return
            destination = urlsplit("//" + target if method == "CONNECT" else target)
            try:
                with socket.create_connection((destination.hostname, destination.port or 80), timeout=5) as upstream:
                    if method == "CONNECT":
                        time.sleep(connect_delay)
                        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        self.wfile.flush()
                    else:
                        path = destination.path or "/"
                        if destination.query:
                            path += "?" + destination.query
                        upstream.sendall(f"{method} {path} {protocol}\r\n".encode("ascii") + b"".join(
                            line for line in headers if not line.lower().startswith(b"proxy-authorization:")) + b"\r\n")
                    # This is a working byte-forwarding proxy. TLS negotiation,
                    # HTTP responses, retries and deadlines use real sockets.
                    with selectors.DefaultSelector() as streams:
                        streams.register(self.connection, selectors.EVENT_READ, upstream)
                        streams.register(upstream, selectors.EVENT_READ, self.connection)
                        while ready := streams.select(timeout=5):
                            for key, _ in ready:
                                data = key.fileobj.recv(65536)
                                if not data:
                                    return
                                key.data.sendall(data)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                pass

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}", requests
        finally:
            server.shutdown()
            thread.join()


def request(targets, *, proxy, bypass="", certificate=None, deadline=5):
    # A separate process gives urllib its real environment without mutating the
    # runner's environment or replacing getproxies/proxy_bypass.
    environment = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
    environment.update(http_proxy=proxy, https_proxy=proxy, no_proxy=bypass)
    if certificate is not None:
        environment["SSL_CERT_FILE"] = str(certificate)
    script = """import sys
sys.path.insert(0, sys.argv[1])
import release
try:
    release.verify_http_destinations(sys.argv[3:], deadline_seconds=float(sys.argv[2]))
except ValueError as error:
    print(error)
    sys.exit(1)
"""
    return run([sys.executable, "-B", "-c", script, ROOT / "scripts", str(deadline), *targets],
               env=environment, capture_output=True, text=True, check=False, timeout=20)


class HttpProxyTest(unittest.TestCase):
    def assert_credentials_private(self, result, credentials):
        encoded = base64.b64encode(":".join(credentials).encode()).decode()
        values = [*credentials, *(quote(value, safe="") for value in credentials), encoded]
        for output in (result.stdout, result.stderr):
            self.assertFalse(any(value in output for value in values), "proxy credentials appeared in output")

    def test_proxy_requires_both_credentials_and_never_prints_them(self):
        credentials = ("synthetic-user@proxy", "synthetic-password:/proxy")
        user, password = (quote(value, safe="") for value in credentials)
        with local_http({"/ok": [200], "/denied": [403]}) as (base, origin), local_proxy(credentials=credentials) as (proxy, forwarded):
            endpoint = proxy.removeprefix("http://")
            authenticated = f"http://{user}:{password}@{endpoint}"
            result = request([base + "/ok"], proxy=authenticated)
            self.assert_credentials_private(result, credentials)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            result = request([base + "/denied"], proxy=authenticated)
            self.assert_credentials_private(result, credentials)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("HTTP 403", result.stdout)
            for unauthenticated in (proxy, f"http://{user}@{endpoint}", f"http://{user}:@{endpoint}",
                                    f"http://:{password}@{endpoint}"):
                with self.subTest(credentials_present=unauthenticated != proxy):
                    result = request([base + "/ok"], proxy=unauthenticated)
                    self.assert_credentials_private(result, credentials)
                    self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                    self.assertIn("HTTP 407", result.stdout)
            self.assertEqual(["/ok", "/denied"], origin)
            self.assertEqual(6, len(forwarded))

    def test_http_proxy_forwards_requests_and_no_proxy_bypasses_it(self):
        with local_http({"/ok?x=1": [200]}) as (base, origin), local_proxy() as (proxy, forwarded):
            target = base + "/ok?x=1"
            result = request([target], proxy=proxy)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual([("GET", target)], forwarded)
            result = request([target], proxy=proxy, bypass="127.0.0.1")
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual([("GET", target)], forwarded)
            self.assertEqual(["/ok?x=1", "/ok?x=1"], origin)

    def test_https_proxy_uses_a_real_connect_tunnel_and_no_proxy_bypasses_it(self):
        with temporary_directory(prefix="requestseal-proxy-tls-") as directory:
            certificate = Path(directory) / "certificate.pem"
            key = Path(directory) / "key.pem"
            run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                 "-keyout", key, "-out", certificate], capture_output=True, timeout=30)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            credentials = ("synthetic-tunnel-user", "synthetic-tunnel-password")
            with local_http({"/ok": [200]}, tls_context=context) as (base, origin), local_proxy(credentials=credentials) as (proxy, forwarded):
                endpoint = proxy.removeprefix("http://")
                for scheme in ("http", "https"):
                    authenticated = scheme + "://" + ":".join(credentials) + "@" + endpoint
                    result = request([base + "/ok"], proxy=authenticated, certificate=certificate)
                    self.assert_credentials_private(result, credentials)
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual([("CONNECT", urlsplit(base).netloc)] * 2, forwarded)
                result = request([base + "/ok"], proxy=proxy, certificate=certificate, deadline=0.3)
                self.assert_credentials_private(result, credentials)
                self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                self.assertIn("407", result.stdout)
                unauthenticated_count = len(forwarded)
                result = request([base + "/ok"], proxy=proxy, bypass="127.0.0.1", certificate=certificate)
                self.assert_credentials_private(result, credentials)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual(unauthenticated_count, len(forwarded))
                self.assertEqual(["/ok", "/ok", "/ok"], origin)

    def test_proxy_preserves_retries_retry_after_and_redirect_rejection(self):
        observed = []
        responses = {"/rate": [(429, {"Retry-After": "1"}), 200], "/redirect": [302], "/ok": [200]}
        with local_http(responses, observed) as (base, origin), local_proxy() as (proxy, forwarded):
            result = request([base + "/rate"], proxy=proxy)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertGreaterEqual(observed[1] - observed[0], 0.9)
            result = request([base + "/redirect"], proxy=proxy)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("HTTP 302", result.stdout)
            self.assertEqual(["/rate", "/rate", "/redirect"], origin)
            self.assertEqual(3, len(forwarded))

    def test_proxy_does_not_extend_the_response_body_deadline(self):
        body = [(0.05, b"x")] * 30
        with local_http({"/slow": [(200, {}, body)]}) as (base, origin), local_proxy() as (proxy, forwarded):
            started = time.monotonic()
            result = request([base + "/slow"], proxy=proxy, deadline=0.35)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("deadline", result.stdout)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(["/slow"], origin)
            self.assertEqual(1, len(forwarded))


if __name__ == "__main__":
    unittest.main()
