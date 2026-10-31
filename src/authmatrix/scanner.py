"""Bounded HTTP authorization checks against explicitly scoped loopback targets."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

import httpx

from authmatrix.config import (
    DESTRUCTIVE_METHODS,
    Identity,
    Operation,
    ScanConfig,
    validate_scope,
)
from authmatrix.errors import ScanError, ScopeError

REMEDIATION = {
    "BOLA": (
        "Enforce object-level authorization on every request. Derive ownership from "
        "the authenticated principal and deny access to objects owned by other users."
    ),
    "BFLA": (
        "Enforce function-level authorization on the server for every privileged "
        "operation; do not rely on hidden routes or client-side role checks."
    ),
}


def _request_count(config: ScanConfig) -> int:
    count = 0
    for operation in config.operations:
        count += len(config.identities) * (
            len(config.resources[operation.resource].ids)
            if operation.resource is not None
            else 1
        )
    return count


def _auth_for(identity: Identity) -> tuple[dict[str, str], httpx.BasicAuth | None]:
    if identity.auth.kind == "bearer":
        token = os.environ.get(identity.auth.token_env or "")
        if not token:
            raise ScanError(
                "Missing authentication environment variable for identity "
                f"{identity.name}."
            )
        return {"Authorization": f"Bearer {token}"}, None

    username = os.environ.get(identity.auth.username_env or "")
    password = os.environ.get(identity.auth.password_env or "")
    if not username or not password:
        raise ScanError(
            f"Missing basic-auth environment variables for identity {identity.name}."
        )
    return {}, httpx.BasicAuth(username, password)


def _route(operation: Operation, resource_id: str | None) -> str:
    if resource_id is None:
        return operation.path

    parts = operation.path.split("/")
    replaced = []
    count = 0

    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            replaced.append(quote(resource_id, safe=""))
            count += 1
        else:
            replaced.append(part)

    if count != 1:
        raise ScanError(
            f"Operation {operation.operation_id} must have exactly one "
            "resource placeholder."
        )

    return "/".join(replaced)


def _expected(operation: Operation, identity_name: str, resource_id: str | None) -> str:
    value = operation.expected[identity_name]
    return value[resource_id] if resource_id is not None else value


def _request_url(config: ScanConfig, route: str) -> str:
    url = f"{config.base_url}{route}"
    parsed = urlsplit(url)

    validate_scope(
        f"{parsed.scheme}://{parsed.netloc}",
        config.allowed_hosts,
    )

    return url


def _parse_returned_object_id(
    body: bytes,
    response_id_path: str = "id",
) -> str | None:
    """Return a scalar JSON object ID at the configured path, or None."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    current = payload

    for segment in response_id_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None

        current = current[segment]

    if isinstance(current, bool) or not isinstance(current, (str, int)):
        return None

    return str(current)


def _read_response_body(response: httpx.Response, max_bytes: int) -> bytes:
    """Read a bounded response body without retaining oversized responses."""
    body = bytearray()

    for chunk in response.iter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise ScanError(
                "Response exceeded scope.max_response_bytes "
                f"({max_bytes})."
            )
        body.extend(chunk)

    return bytes(body)


def run_authorization_tests(config: ScanConfig) -> dict:
    """Run bounded authorization checks against explicitly scoped targets."""
    validate_scope(config.base_url, config.allowed_hosts)

    total = _request_count(config)

    if total > config.max_requests:
        raise ScanError(
            f"Scan requires {total} requests, exceeding scope.max_requests "
            f"({config.max_requests}); reduce the policy or raise the "
            "explicit local limit."
        )

    checks = []
    findings = []
    request_number = 0

    with httpx.Client(
        timeout=config.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        for operation in config.operations:
            resource_ids = (
                config.resources[operation.resource].ids
                if operation.resource is not None
                else (None,)
            )

            for identity_name, identity in config.identities.items():
                headers, basic_auth = _auth_for(identity)

                for resource_id in resource_ids:
                    request_number += 1

                    if request_number > config.max_requests:
                        raise ScanError(
                            "Request limit exceeded before sending the request."
                        )

                    expected = _expected(operation, identity_name, resource_id)
                    route = _route(operation, resource_id)
                    url = _request_url(config, route)

                    if (
                        operation.method in DESTRUCTIVE_METHODS
                        and not config.allow_destructive
                    ):
                        raise ScopeError(
                            f"Destructive operation {operation.operation_id} "
                            "is disabled."
                        )

                    try:
                        with client.stream(
                            operation.method,
                            url,
                            headers=headers,
                            auth=basic_auth,
                        ) as response:
                            if 300 <= response.status_code < 400:
                                raise ScopeError(
                                    f"Unsafe redirect from {operation.method} {route}; "
                                    "redirects are never followed."
                                )

                            status_code = response.status_code
                            content_type = response.headers.get("content-type", "")
                            body = _read_response_body(
                                response,
                                config.max_response_bytes,
                            )

                    except (ScopeError, ScanError):
                        raise
                    except httpx.RequestError as exc:
                        raise ScanError(
                            f"Request failed for {operation.method} {route} "
                            f"as identity {identity_name} ({type(exc).__name__})."
                        ) from exc

                    is_success = 200 <= status_code < 300
                    inconclusive = False
                    returned_id = None

                    if operation.category == "BOLA" and is_success:
                        returned_id = _parse_returned_object_id(
                            body,
                            operation.response_id_path,
                        )

                        if returned_id != resource_id:
                            actual = "unknown"
                            inconclusive = True
                        else:
                            actual = "allow"
                    else:
                        actual = "allow" if is_success else "deny"

                    passed = not inconclusive and expected == actual

                    check = {
                        "operation_id": operation.operation_id,
                        "category": operation.category,
                        "method": operation.method,
                        "path": route,
                        "identity": identity_name,
                        "role": identity.role,
                        "resource_id": resource_id,
                        "expected": expected,
                        "actual": actual,
                        "status_code": status_code,
                        "content_type": content_type,
                        "passed": passed,
                        "inconclusive": inconclusive,
                    }

                    checks.append(check)

                    if expected == "deny" and actual == "allow":
                        evidence = {
                            "identity": identity_name,
                            "role": identity.role,
                            "resource_id": resource_id,
                            "expected_decision": "deny",
                            "observed_decision": "allow",
                            "http_status": status_code,
                            "response_content_type": content_type,
                        }

                        if operation.category == "BOLA":
                            evidence["requested_resource_id"] = resource_id
                            evidence["returned_resource_id"] = returned_id
                            evidence["object_id_verified"] = True

                        findings.append(
                            {
                                "id": (
                                    f"{operation.operation_id}:{identity_name}:"
                                    f"{resource_id or '-'}"
                                ),
                                "category": operation.category,
                                "severity": "high",
                                "title": (
                                    "Unauthorized object access"
                                    if operation.category == "BOLA"
                                    else "Unauthorized function access"
                                ),
                                "operation_id": operation.operation_id,
                                "evidence": evidence,
                                "reproduction": {
                                    "method": operation.method,
                                    "path": route,
                                    "identity": identity_name,
                                    "resource_id": resource_id,
                                    "note": (
                                        "Replay only against the explicitly "
                                        "authorized local lab."
                                    ),
                                },
                                "remediation": REMEDIATION[operation.category],
                            }
                        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": config.base_url,
        "summary": {
            "requests": len(checks),
            "passed": sum(1 for check in checks if check["passed"]),
            "failed": sum(
                1
                for check in checks
                if not check["passed"] and not check["inconclusive"]
            ),
            "inconclusive": sum(1 for check in checks if check["inconclusive"]),
            "findings": len(findings),
        },
        "findings": findings,
        "checks": checks,
    }


def write_scan_results(results: dict, path: str) -> None:
    """Write sanitized scan results as JSON."""
    try:
        with open(path, "w", encoding="utf-8") as output:
            json.dump(results, output, indent=2, ensure_ascii=False)
            output.write("\n")
    except OSError as exc:
        raise ScanError(f"Cannot write scan results: {path}") from exc
