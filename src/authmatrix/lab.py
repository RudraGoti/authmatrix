"""A local-only vulnerable/fixed demo API; all routes are read-only."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

TOKENS = {
    "alice-local-token": ("alice", "user"),
    "bob-local-token": ("bob", "user"),
    "admin-local-token": ("admin", "admin"),
}
ITEMS = {
    "1": {"id": "1", "owner": "alice", "value": "Alice's sample item"},
    "2": {"id": "2", "owner": "bob", "value": "Bob's sample item"},
}


class DemoHandler(BaseHTTPRequestHandler):
    mode = "vulnerable"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        principal = TOKENS.get(
            self.headers.get("Authorization", "").removeprefix("Bearer ")
        )
        if principal is None:
            self._json(401, {"error": "authentication required"})
            return
        username, role = principal
        path = urlsplit(self.path).path
        if path.startswith("/items/"):
            item_id = path.removeprefix("/items/")
            item = ITEMS.get(item_id)
            if item is None:
                self._json(404, {"error": "not found"})
                return
            if self.mode == "fixed" and item["owner"] != username and role != "admin":
                self._json(403, {"error": "forbidden"})
                return
            self._json(200, {"id": item["id"], "value": item["value"]})
            return
        if path == "/admin/reports":
            if self.mode == "fixed" and role != "admin":
                self._json(403, {"error": "forbidden"})
                return
            self._json(200, {"reports": ["sample-report"]})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        self._json(405, {"error": "read-only demo API"})

    def do_PUT(self) -> None:
        self._json(405, {"error": "read-only demo API"})

    def do_PATCH(self) -> None:
        self._json(405, {"error": "read-only demo API"})

    def do_DELETE(self) -> None:
        self._json(405, {"error": "read-only demo API"})


def run_server(mode: str, host: str, port: int) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "The demo API host must be a literal loopback IP address."
        ) from exc
    if not address.is_loopback:
        raise ValueError("The demo API can only bind to a loopback IP address.")
    if mode not in {"vulnerable", "fixed"}:
        raise ValueError("Demo mode must be vulnerable or fixed.")
    handler = type("ConfiguredDemoHandler", (DemoHandler,), {"mode": mode})
    server_type = type(
        "LoopbackHTTPServer",
        (ThreadingHTTPServer,),
        {"address_family": socket.AF_INET6 if address.version == 6 else socket.AF_INET},
    )
    server = server_type((host, port), handler)
    print(f"AuthMatrix {mode} lab listening at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AuthMatrix lab.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local AuthMatrix demo API.")
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        run_server(args.mode, args.host, args.port)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
