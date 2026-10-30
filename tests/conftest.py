from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from authmatrix.lab import DemoHandler

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config_path() -> Path:
    return ROOT / "examples" / "policy.yaml"


@pytest.fixture
def demo_server(request):
    class LocalOnlyServer(ThreadingHTTPServer):
        daemon_threads = True

    handler = type(
        "TestDemoHandler",
        (DemoHandler,),
        {"mode": getattr(request, "param", "vulnerable")},
    )
    server = LocalOnlyServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHMATRIX_ALICE_TOKEN", "alice-local-token")
    monkeypatch.setenv("AUTHMATRIX_BOB_TOKEN", "bob-local-token")
    monkeypatch.setenv("AUTHMATRIX_ADMIN_TOKEN", "admin-local-token")
