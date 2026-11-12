"""Bounded HTTP authorization checks against explicitly scoped loopback targets."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit
from uuid import uuid4

import httpx

from authmatrix.config import (
    DESTRUCTIVE_METHODS,
    Identity,
    Operation,
    ScanConfig,
    validate_scope,
)
from authmatrix.errors import ScanError, ScopeError
from authmatrix.openapi_scan import IDENTITY_VALUES_MARKER, RESOURCE_ID_MARKER

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
        token_env = identity.auth.token_env or ""
        token = os.environ.get(token_env)
        if not token:
            message = (
                "Missing authentication environment variable "
                f"{token_env or '<unset>'} for identity {identity.name}."
            )
            raise ScanError(
                message,
                public_detail=message,
            )
        return {"Authorization": f"Bearer {token}"}, None

    username_env = identity.auth.username_env or ""
    password_env = identity.auth.password_env or ""
    username = os.environ.get(username_env)
    password = os.environ.get(password_env)
    if not username or not password:
        missing = [
            name
            for name, value in (
                (username_env, username),
                (password_env, password),
            )
            if not value
        ]
        message = (
            "Missing basic-auth environment variable(s) "
            f"{', '.join(missing)} for identity {identity.name}."
        )
        raise ScanError(message, public_detail=message)
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


def _resolve_request_value(
    value: object,
    identity_name: str,
    resource_id: str | None,
) -> object:
    if isinstance(value, dict):
        if value == {RESOURCE_ID_MARKER: True}:
            if resource_id is None:
                raise ScanError("OpenAPI request mapping requires a resource ID.")
            return resource_id
        if IDENTITY_VALUES_MARKER in value:
            return _resolve_request_value(
                value[IDENTITY_VALUES_MARKER][identity_name],
                identity_name,
                resource_id,
            )
        return {
            key: _resolve_request_value(item, identity_name, resource_id)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _resolve_request_value(item, identity_name, resource_id)
            for item in value
        ]
    return value


def _parameter_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)) and value is not None:
        return str(value)
    raise ScanError("OpenAPI parameter values must be scalar, array, or object values.")


def _parameter_parts(
    value: object,
) -> tuple[str, list[str] | None, list[tuple[str, str]] | None]:
    if isinstance(value, list):
        return "array", [_parameter_scalar(item) for item in value], None
    if isinstance(value, dict):
        return (
            "object",
            None,
            [(str(key), _parameter_scalar(item)) for key, item in value.items()],
        )
    return "scalar", [_parameter_scalar(value)], None


def _encode_path_part(value: str) -> str:
    return quote(value, safe="-._~")


def _serialize_path_parameter(name: str, definition: dict, value: object) -> str:
    style = definition["style"]
    explode = definition["explode"]
    kind, scalars, pairs = _parameter_parts(value)
    encoded_name = _encode_path_part(name)
    if kind == "scalar":
        scalar = _encode_path_part(scalars[0])
        if style == "label":
            return f".{scalar}"
        if style == "matrix":
            return f";{encoded_name}={scalar}"
        return scalar
    if kind == "array":
        encoded = [_encode_path_part(item) for item in scalars]
        if style == "label":
            delimiter = "." if explode else ","
            return "." + delimiter.join(encoded)
        if style == "matrix":
            if explode:
                return "".join(f";{encoded_name}={item}" for item in encoded)
            return f";{encoded_name}={','.join(encoded)}"
        return ",".join(encoded)

    encoded_pairs = [
        (_encode_path_part(key), _encode_path_part(item)) for key, item in pairs
    ]
    if style == "label":
        if explode:
            return "." + ".".join(f"{key}={item}" for key, item in encoded_pairs)
        return "." + ",".join(
            part for pair in encoded_pairs for part in pair
        )
    if style == "matrix":
        if explode:
            return "".join(f";{key}={item}" for key, item in encoded_pairs)
        return f";{encoded_name}=" + ",".join(
            part for pair in encoded_pairs for part in pair
        )
    if explode:
        return ",".join(f"{key}={item}" for key, item in encoded_pairs)
    return ",".join(part for pair in encoded_pairs for part in pair)


def _serialize_query_parameter(
    name: str,
    definition: dict,
    value: object,
) -> list[tuple[str, str]]:
    style = definition["style"]
    explode = definition["explode"]
    kind, scalars, pairs = _parameter_parts(value)
    if kind == "scalar":
        return [(name, scalars[0])]
    if kind == "array":
        delimiter = {
            "form": ",",
            "spaceDelimited": " ",
            "pipeDelimited": "|",
        }.get(style)
        if delimiter is None:
            raise ScanError("OpenAPI query array uses an unsupported style.")
        if style == "form" and explode:
            return [(name, item) for item in scalars]
        return [(name, delimiter.join(scalars))]

    if style == "deepObject":
        return [(f"{name}[{key}]", item) for key, item in pairs]
    if style != "form":
        raise ScanError("OpenAPI query object uses an unsupported style.")
    if explode:
        return pairs
    return [(name, ",".join(part for pair in pairs for part in pair))]


def _serialize_header_parameter(name: str, definition: dict, value: object) -> str:
    kind, scalars, pairs = _parameter_parts(value)
    if kind == "scalar":
        serialized = scalars[0]
    elif kind == "array":
        serialized = ",".join(scalars)
    elif definition["explode"]:
        serialized = ",".join(f"{key}={item}" for key, item in pairs)
    else:
        serialized = ",".join(part for pair in pairs for part in pair)
    if any(ord(character) < 32 or ord(character) == 127 for character in serialized):
        raise ScanError(
            f"OpenAPI header parameter {name!r} contains invalid characters."
        )
    return serialized


def _build_request(
    operation: Operation,
    identity_name: str,
    resource_id: str | None,
) -> tuple[str, list[tuple[str, str]], dict[str, str], object, bool]:
    """Build a bounded request from explicit OpenAPI values and policy IDs."""
    if operation.request_parameters is None:
        return _route(operation, resource_id), [], {}, None, False

    route = operation.path
    query = []
    headers = {}
    path_values = operation.request_parameters["path"]
    placeholders = re.findall(r"\{([^{}]+)\}", route)
    if len(placeholders) != len(path_values) or set(placeholders) != set(path_values):
        raise ScanError(
            f"OpenAPI path parameters do not match {operation.operation_id}."
        )
    for name in placeholders:
        definition = path_values[name]
        value = _resolve_request_value(
            definition["value"],
            identity_name,
            resource_id,
        )
        route = route.replace(
            "{" + name + "}",
            _serialize_path_parameter(name, definition, value),
            1,
        )

    for name, definition in operation.request_parameters["query"].items():
        value = _resolve_request_value(
            definition["value"],
            identity_name,
            resource_id,
        )
        query.extend(_serialize_query_parameter(name, definition, value))

    for name, definition in operation.request_parameters["header"].items():
        value = _resolve_request_value(
            definition["value"],
            identity_name,
            resource_id,
        )
        headers[name] = _serialize_header_parameter(name, definition, value)

    has_body = operation.request_content_type is not None
    body = (
        _resolve_request_value(
            operation.request_body,
            identity_name,
            resource_id,
        )
        if has_body
        else None
    )
    if has_body:
        headers["Content-Type"] = operation.request_content_type
    return route, query, headers, body, has_body


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


def _parse_returned_object_ids(
    body: bytes,
    response_id_path: str = "id",
    max_ids: int = 100,
) -> tuple[str, ...] | None:
    """Extract bounded, unique scalar IDs from a JSON response.

    Return None when the path is invalid, missing, unusable, or exceeds
    the extraction limit. Invalid individual values are skipped.
    """
    if not isinstance(max_ids, int) or isinstance(max_ids, bool) or max_ids < 1:
        return None

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(response_id_path, str) or not response_id_path:
        return None

    tokens = []
    position = 0
    length = len(response_id_path)

    def read_key():
        nonlocal position
        start = position

        while position < length:
            char = response_id_path[position]
            if not (char.isalnum() or char == "_"):
                break
            position += 1

        if position == start:
            return None

        return response_id_path[start:position]

    first_key = read_key()
    if first_key is None:
        return None
    tokens.append(("key", first_key))

    while position < length:
        char = response_id_path[position]

        if char == ".":
            position += 1
            key = read_key()
            if key is None:
                return None
            tokens.append(("key", key))

        elif char == "[":
            position += 1

            if response_id_path[position:position + 1] == "*":
                position += 1
                if position >= length or response_id_path[position] != "]":
                    return None
                position += 1
                tokens.append(("wildcard", None))
                continue

            start = position
            while position < length and response_id_path[position].isdigit():
                position += 1

            if position == start or position >= length:
                return None
            if response_id_path[position] != "]":
                return None

            index = int(response_id_path[start:position])
            position += 1
            tokens.append(("index", index))

        else:
            return None

    current_values = [payload]

    for token_type, value in tokens:
        next_values = []

        for current in current_values:
            if token_type == "key":
                if isinstance(current, dict) and value in current:
                    next_values.append(current[value])

            elif token_type == "index":
                if isinstance(current, list) and value < len(current):
                    next_values.append(current[value])

            elif token_type == "wildcard":
                if isinstance(current, list):
                    next_values.extend(current)

            if len(next_values) > max_ids:
                return None

        current_values = next_values

        if not current_values:
            return None

    extracted = []
    seen = set()

    for value in current_values:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue

        resource_id = str(value)

        if not resource_id or not resource_id.strip() or resource_id in seen:
            continue

        seen.add(resource_id)
        extracted.append(resource_id)

        if len(extracted) > max_ids:
            return None

    return tuple(extracted) if extracted else None


def _parse_returned_object_id(
    body: bytes,
    response_id_path: str = "id",
) -> str | None:
    """Return the first scalar JSON object ID for backward compatibility."""
    returned_ids = _parse_returned_object_ids(body, response_id_path)
    return returned_ids[0] if returned_ids else None


def _read_response_body(response: httpx.Response, max_bytes: int) -> bytes:
    """Read a bounded response body without retaining oversized responses."""
    body = bytearray()

    for chunk in response.iter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise ScanError(
                "Response exceeded scope.max_response_bytes "
                f"({max_bytes}).",
                public_detail=(
                    "The target response exceeded the response-size limit "
                    "configured by the policy."
                ),
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
            "explicit local limit.",
            public_detail=(
                "The scan exceeds the request limit configured by the policy."
            ),
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
                            "Request limit exceeded before sending the request.",
                            public_detail=(
                                "The scan exceeds the request limit configured "
                                "by the policy."
                            ),
                        )

                    expected = _expected(operation, identity_name, resource_id)
                    resource_owner = (
                        config.resources[operation.resource].owner_by_id.get(
                            resource_id or ""
                        )
                        if operation.category == "BOLA" and operation.resource
                        else None
                    )
                    cross_user_access_verified = (
                        resource_owner is not None and resource_owner != identity_name
                    )
                    route, query, operation_headers, request_body, has_body = (
                        _build_request(operation, identity_name, resource_id)
                    )
                    url = _request_url(config, route)
                    display_path = (
                        operation.path
                        if operation.request_parameters is not None
                        else route
                    )

                    if (
                        operation.method in DESTRUCTIVE_METHODS
                        and not config.allow_destructive
                    ):
                        raise ScopeError(
                            f"Destructive operation {operation.operation_id} "
                            "is disabled."
                        )

                    try:
                        request_options = {
                            "headers": {**headers, **operation_headers},
                            "auth": basic_auth,
                        }
                        if query:
                            request_options["params"] = query
                        if has_body:
                            request_options["json"] = request_body
                        with client.stream(
                            operation.method,
                            url,
                            **request_options,
                        ) as response:
                            if 300 <= response.status_code < 400:
                                raise ScopeError(
                                    f"Unsafe redirect from {operation.method} "
                                    f"{display_path}; "
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
                            f"Request failed for {operation.method} {display_path} "
                            f"as identity {identity_name} ({type(exc).__name__}).",
                            public_detail=(
                                "Could not reach the authorized local target. "
                                "Confirm it is running and accessible."
                            ),
                        ) from exc

                    is_success = 200 <= status_code < 300
                    inconclusive = False
                    returned_ids = None
                    returned_id = None
                    response_evidence_verified = None

                    if operation.category == "BOLA" and is_success:
                        returned_ids = _parse_returned_object_ids(
                            body,
                            operation.response_id_path,
                        )

                        returned_id = (
                            returned_ids[0]
                            if returned_ids and len(returned_ids) == 1
                            else None
                        )

                        if (
                            returned_ids is None
                            or resource_id not in returned_ids
                            or (
                                expected == "deny"
                                and not cross_user_access_verified
                            )
                        ):
                            actual = "unknown"
                            inconclusive = True
                        else:
                            actual = "allow"
                    elif (
                        operation.category == "BFLA"
                        and expected == "deny"
                        and is_success
                    ):
                        evidence_values = (
                            _parse_returned_object_ids(
                                body,
                                operation.response_evidence_path,
                            )
                            if operation.response_evidence_path
                            else None
                        )
                        response_evidence_verified = bool(evidence_values)
                        if response_evidence_verified:
                            actual = "allow"
                        else:
                            actual = "unknown"
                            inconclusive = True
                    else:
                        actual = "allow" if is_success else "deny"

                    passed = not inconclusive and expected == actual

                    check = {
                        "operation_id": operation.operation_id,
                        "category": operation.category,
                        "method": operation.method,
                        "path": display_path,
                        "identity": identity_name,
                        "role": identity.role,
                        "resource_id": resource_id,
                        "resource_owner": resource_owner,
                        "cross_user_access_verified": (
                            cross_user_access_verified
                            if operation.category == "BOLA"
                            else None
                        ),
                        "returned_resource_ids": (
                            list(returned_ids) if returned_ids is not None else None
                        ),
                        "response_evidence_verified": response_evidence_verified,
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
                            evidence["resource_owner"] = resource_owner
                            evidence["cross_user_access_verified"] = (
                                cross_user_access_verified
                            )
                            evidence["returned_resource_ids"] = list(returned_ids)
                            if returned_id is not None:
                                evidence["returned_resource_id"] = returned_id
                            evidence["object_id_verified"] = True
                        else:
                            evidence["response_evidence_path"] = (
                                operation.response_evidence_path
                            )
                            evidence["response_evidence_verified"] = True

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
                                    "path": display_path,
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
        "scan_id": uuid4().hex,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": config.base_url,
        "policy": config.source.name,
        "identities": [
            {"name": identity.name, "role": identity.role}
            for identity in config.identities.values()
        ],
        "limitations": [
            "Only operations and resource IDs listed in the policy were tested.",
            "Response bodies and authentication credentials are not retained.",
        ],
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


def write_scan_results(
    results: dict,
    path: str | Path,
    *,
    overwrite: bool = False,
) -> None:
    """Write scan results without replacing an existing file by default."""
    destination = Path(path)
    if destination.is_symlink():
        raise ScanError("Scan result output must not be a symbolic link.")
    try:
        mode = "w" if overwrite else "x"
        with destination.open(mode, encoding="utf-8") as output:
            json.dump(results, output, indent=2, ensure_ascii=False)
            output.write("\n")
    except FileExistsError as exc:
        raise ScanError(
            "Scan result output already exists; choose a new path or use --force."
        ) from exc
    except OSError as exc:
        raise ScanError(f"Cannot write scan results: {destination}") from exc
