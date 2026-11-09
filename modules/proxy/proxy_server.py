"""A local HTTP(S) proxy with metadata-only inspection."""

from __future__ import annotations

import base64
import http.client
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from config import DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT
from modules.proxy.request_view import RequestView
from modules.proxy.response_view import ResponseView


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Simple proxy handler that logs metadata only and never stores sensitive values."""

    server_version = "RvpaPentestToolkit/1.0"

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_request()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_request()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._handle_request()

    def do_CONNECT(self) -> None:  # noqa: N802
        host, port = self.path.split(":", 1)
        port = int(port)
        self.send_response(200, "Connection established")
        self.end_headers()
        self._log_request_metadata("CONNECT", self.path)
        remote = socket.create_connection((host, port), timeout=10)
        local = self.connection
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        local.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def forward(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    src.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        t1 = threading.Thread(target=forward, args=(local, remote), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote, local), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()

    def _handle_request(self) -> None:
        request_headers = dict(self.headers)
        request_view = RequestView(
            method=self.command,
            target=self.path,
            headers=request_headers,
            host=self.headers.get("Host", "unknown-host"),
        )
        self._log_request_metadata(request_view.method, request_view.target)

        if self.path.startswith("http://") or self.path.startswith("https://"):
            target_url = self.path
        else:
            target_url = f"http://{self.headers.get('Host', 'localhost')}{self.path}"

        try:
            host, port = self._split_url(target_url)
            conn = http.client.HTTPConnection(host, port=port, timeout=10)
            headers = {
                key: value for key, value in request_headers.items() if key.lower() not in {"host", "proxy-connection"}
            }
            body = None
            if self.command in {"POST", "PUT", "DELETE"}:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length > 0 else b""
            conn.request(self.command, self.path if self.path.startswith("/") else "/", body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            response_headers = dict(response.headers)
            response_view = ResponseView(response.status, response.reason, response_headers)
            self._log_response_metadata(response_view)
            self.send_response(response.status, response.reason)
            for key, value in response_headers.items():
                if key.lower() not in {"transfer-encoding", "content-encoding"}:
                    self.send_header(key, value)
            self.end_headers()
            if data:
                self.wfile.write(data)
            conn.close()
        except Exception as exc:
            self.send_response(502, "Bad Gateway")
            self.end_headers()
            self.wfile.write(f"Proxy error: {exc}".encode("utf-8"))

    def _log_request_metadata(self, method: str, target: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[{timestamp}] REQUEST {method} {target}")

    def _log_response_metadata(self, response_view: ResponseView) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[{timestamp}] RESPONSE {response_view.status_code} {response_view.reason}")

    @staticmethod
    def _split_url(target_url: str) -> tuple[str, int]:
        if target_url.startswith("http://"):
            target_url = target_url[len("http://") :]
        elif target_url.startswith("https://"):
            target_url = target_url[len("https://") :]
        host, _, rest = target_url.partition("/")
        if ":" in host:
            hostname, port = host.rsplit(":", 1)
            return hostname, int(port)
        return host, 80


class ProxyServer(HTTPServer):
    """Simple threaded HTTP proxy server."""

    def __init__(self, host: str = DEFAULT_PROXY_HOST, port: int = DEFAULT_PROXY_PORT):
        self.host = host
        self.port = port
        super().__init__((host, port), ProxyRequestHandler)

    def serve_forever(self) -> None:
        print(f"Proxy listening on http://{self.host}:{self.port}")
        print("HTTPS inspection is limited without TLS decryption; only CONNECT metadata is shown.")
        super().serve_forever()


if __name__ == "__main__":
    ProxyServer().serve_forever()
