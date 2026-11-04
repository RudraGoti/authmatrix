import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_compose_dashboard_is_loopback_only_and_restricted() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    dashboard = compose["services"]["authmatrix"]

    assert dashboard["ports"] == ["127.0.0.1:8001:8001"]
    assert dashboard["read_only"] is True
    assert dashboard["tmpfs"] == ["/tmp"]
    assert dashboard["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in dashboard["security_opt"]
    assert dashboard["volumes"] == ["authmatrix-data:/data"]
    assert "authmatrix-data" in compose["volumes"]
    assert dashboard["healthcheck"]["retries"] == 3
    assert "api/health" in " ".join(dashboard["healthcheck"]["test"])
    alice_default = dashboard["environment"]["AUTHMATRIX_ALICE_TOKEN"]
    assert alice_default == "${AUTHMATRIX_ALICE_TOKEN:-}"
    assert dashboard["environment"]["AUTHMATRIX_BOB_TOKEN"] == (
        "${AUTHMATRIX_BOB_TOKEN:-}"
    )
    assert dashboard["environment"]["AUTHMATRIX_ADMIN_TOKEN"] == (
        "${AUTHMATRIX_ADMIN_TOKEN:-}"
    )


def test_compose_demo_lab_is_private_and_profile_gated() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    lab = compose["services"]["lab"]

    assert lab["profiles"] == ["lab"]
    assert lab["network_mode"] == "service:authmatrix"
    assert "ports" not in lab
    assert lab["environment"]["AUTHMATRIX_ALICE_TOKEN"].endswith(
        ":-alice-local-token}"
    )
    assert lab["read_only"] is True
    assert lab["tmpfs"] == ["/tmp"]
    assert lab["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in lab["security_opt"]
    assert lab["stop_signal"] == "SIGINT"
    assert lab["healthcheck"]["retries"] == 3


def test_docker_image_runs_unprivileged_and_packages_static_assets() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY src ./src" in dockerfile
    assert "useradd --system --uid 10001" in dockerfile
    assert "mkdir -p /data" in dockerfile
    assert "chown authmatrix:authmatrix /data" in dockerfile
    assert "USER authmatrix" in dockerfile
    command = next(
        line.removeprefix("CMD ").strip()
        for line in dockerfile.splitlines()
        if line.startswith("CMD ")
    )
    assert json.loads(command) == [
        "uvicorn",
        "authmatrix.web.app:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8001",
        "--workers",
        "1",
    ]


def test_docker_build_context_excludes_local_secrets_and_scan_data() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert ".env" in dockerignore
    assert ".env.*" in dockerignore
    assert "*.sqlite3" in dockerignore
