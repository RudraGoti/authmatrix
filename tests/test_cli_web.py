from pathlib import Path

from typer.testing import CliRunner

from authmatrix.cli import app

ROOT = Path(__file__).resolve().parents[1]


def test_web_command_runs_single_loopback_server(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "authmatrix.cli.uvicorn.run",
        lambda *args, **kwargs: calls.append(kwargs),
    )

    result = CliRunner().invoke(app, ["web"])

    assert result.exit_code == 0
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8001,
            "workers": 1,
        }
    ]


def test_web_command_rejects_non_loopback_bind():
    result = CliRunner().invoke(app, ["web", "--host", "0.0.0.0"])

    assert result.exit_code == 2
    assert "only bind to a loopback IP" in result.output


def test_test_command_accepts_explicit_openapi_mapping(tmp_path, monkeypatch):
    from authmatrix import cli

    monkeypatch.setattr(
        cli,
        "run_authorization_tests",
        lambda _config: {
            "schema_version": 1,
            "scan_id": "test-scan",
            "generated_at": "2026-11-04T00:00:00+00:00",
            "target": "http://127.0.0.1:8000",
            "policy": "policy.yaml",
            "identities": [],
            "limitations": [],
            "summary": {
                "requests": 0,
                "passed": 0,
                "failed": 0,
                "inconclusive": 0,
                "findings": 0,
            },
            "findings": [],
            "checks": [],
        },
    )
    output = tmp_path / "scan.json"

    result = CliRunner().invoke(
        app,
        [
            "test",
            "--config",
            str(ROOT / "examples" / "policy.yaml"),
            "--openapi",
            str(ROOT / "examples" / "openapi.yaml"),
            "--values",
            str(ROOT / "examples" / "openapi.mapping.yaml"),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Completed 0 requests" in result.output
    assert output.exists()


def test_test_command_requires_openapi_values_mapping():
    result = CliRunner().invoke(
        app,
        [
            "test",
            "--config",
            str(ROOT / "examples" / "policy.yaml"),
            "--openapi",
            str(ROOT / "examples" / "openapi.yaml"),
        ],
    )

    assert result.exit_code == 2
    assert "--openapi and --values must be provided together" in result.output
