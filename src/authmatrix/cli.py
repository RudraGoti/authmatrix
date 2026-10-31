"""AuthMatrix command-line interface."""

from __future__ import annotations

from pathlib import Path

import typer

from authmatrix import __version__
from authmatrix.config import load_config
from authmatrix.errors import AuthMatrixError
from authmatrix.lab import run_server
from authmatrix.openapi import write_operation_inventory
from authmatrix.reporting import write_report
from authmatrix.scanner import run_authorization_tests, write_scan_results

app = typer.Typer(
    name="authmatrix",
    help=(
        "Policy-driven API authorization checks for explicitly authorized "
        "local targets."
    ),
    no_args_is_help=True,
)


def _handle_error(error: AuthMatrixError) -> None:
    typer.echo(f"Error: {error}", err=True)
    raise typer.Exit(code=2) from error


@app.command("version")
def version() -> None:
    """Print the installed AuthMatrix version."""
    typer.echo(__version__)


@app.command("config-check")
def config_check(
    config: Path = typer.Option(..., "--config", "-c", exists=True, readable=True),
    check_auth_env: bool = typer.Option(
        False, "--check-auth-env", help="Also verify referenced auth variables are set."
    ),
) -> None:
    """Validate a policy and its explicitly authorized loopback scope."""
    try:
        parsed = load_config(config, check_auth_env=check_auth_env)
    except AuthMatrixError as exc:
        _handle_error(exc)
    typer.echo(
        f"Configuration valid: {len(parsed.identities)} identities, "
        f"{len(parsed.resources)} resources, {len(parsed.operations)} operations; "
        f"authorized loopback target {parsed.base_url}."
    )


@app.command("import-openapi")
def import_openapi(
    specification: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("openapi-inventory.json"), "--output", "-o"),
) -> None:
    """Extract a local OpenAPI 3.x operation inventory (does not scan the API)."""
    try:
        count = write_operation_inventory(specification, output)
    except AuthMatrixError as exc:
        _handle_error(exc)
    typer.echo(f"Imported {count} operations to {output}.")


@app.command("test")
def test_authorization(
    config: Path = typer.Option(..., "--config", "-c", exists=True, readable=True),
    output: Path = typer.Option(Path("scan-results.json"), "--output", "-o"),
) -> None:
    """Run the configured authorization matrix against an authorized local API."""
    try:
        parsed = load_config(config)
        results = run_authorization_tests(parsed)
        write_scan_results(results, str(output))
    except AuthMatrixError as exc:
        _handle_error(exc)
    typer.echo(
        f"Completed {results['summary']['requests']} requests: "
        f"{results['summary']['findings']} finding(s), "
        f"{results['summary']['failed']} failed check(s), "
        f"{results['summary'].get('inconclusive', 0)} inconclusive check(s). "
        f"Results: {output}"
    )


@app.command("report")
def report(
    results: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("authmatrix-report.html"), "--output", "-o"),
    format: str = typer.Option("html", "--format", help="Output format: html or json."),
) -> None:
    """Render sanitized JSON or HTML from saved scan results."""
    try:
        write_report(results, output, format)
    except AuthMatrixError as exc:
        _handle_error(exc)
    typer.echo(f"Wrote {format.upper()} report to {output}.")


@app.command("lab")
def lab(
    mode: str = typer.Option("vulnerable", "--mode"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
) -> None:
    """Launch the read-only local vulnerable or fixed demo API."""
    try:
        run_server(mode, host, port)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()
