
"""Bounded, metadata-only web security posture assessment."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import httpx

from authmatrix.errors import ScopeError
from authmatrix.execution_scope import (
    DnspythonResolver,
    InventoryExecutionPolicy,
    Resolver,
    WebPosturePolicy,
)
from authmatrix.transport import InventoryScopedTransport
from authmatrix.web.asset_inventory import authorization_eligibility
from authmatrix.web.storage import ScanStore

_TOKEN = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SAFE_HEADER_VALUE = re.compile(r"^[\x20-\x7e\t]*$")

_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


class PostureResponseLimitError(ValueError):
    """Raised when response metadata exceeds configured limits."""


def _collect_headers(
    raw_headers: list[tuple[bytes, bytes]],
    policy: WebPosturePolicy,
) -> tuple[dict[str, list[str]], list[bytes]]:
    if len(raw_headers) > policy.max_header_count:
        raise PostureResponseLimitError("Response header count exceeded.")

    total_bytes = 0
    collected: dict[str, list[str]] = {}
    cookie_values: list[bytes] = []

    for raw_name, raw_value in raw_headers:
        total_bytes += len(raw_name) + len(raw_value) + 4
        if total_bytes > policy.max_header_bytes:
            raise PostureResponseLimitError("Response header size exceeded.")

        if not _TOKEN.fullmatch(raw_name):
            raise PostureResponseLimitError("Malformed response header name.")

        name = raw_name.decode("ascii").casefold()

        if any(
            byte < 32 and byte != 9 or byte == 127
            for byte in raw_value
        ):
            raise PostureResponseLimitError("Malformed response header value.")

        if name == "set-cookie":
            cookie_values.append(raw_value)
            if len(cookie_values) > policy.max_cookie_headers:
                raise PostureResponseLimitError("Cookie header count exceeded.")
            continue

        value = raw_value.decode("latin-1").strip()
        collected.setdefault(name, []).append(value)

    return collected, cookie_values


def _single_header(
    headers: dict[str, list[str]],
    name: str,
) -> tuple[str | None, str]:
    values = headers.get(name, [])

    if not values:
        return None, "missing"

    if len(values) != 1:
        return None, "invalid"

    value = values[0]
    if not value or not _SAFE_HEADER_VALUE.fullmatch(value):
        return None, "invalid"

    return value, "present"


def _valid_hsts(value: str) -> bool:
    directives = [part.strip() for part in value.split(";")]
    if not directives or not directives[0]:
        return False

    max_age = re.fullmatch(
        r"max-age\s*=\s*(\d+)",
        directives[0],
        re.IGNORECASE,
    )
    if max_age is None or not max_age.group(1).lstrip("0"):
        return False

    seen = {"max-age"}
    for directive in directives[1:]:
        if not directive:
            continue

        name = directive.casefold()
        if name not in {"includesubdomains", "preload"} or name in seen:
            return False

        seen.add(name)

    return True


def _parse_csp(value: str) -> tuple[bool, bool]:
    """Return (syntactically_valid, restrictive_frame_ancestors)."""
    directives: set[str] = set()
    frame_ancestors_restrictive = False

    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue

        name = tokens[0].casefold()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            return False, False

        if name in directives:
            return False, False

        directives.add(name)
        if name == "frame-ancestors":
            sources = tokens[1:]

            def valid_frame_source(source: str) -> bool:
                if source in {"'none'", "'self'"}:
                    return True

                if source == "*" or "'" in source or chr(92) in source:
                    return False

                candidate = source
                lowered = candidate.casefold()

                if lowered.startswith("https://"):
                    candidate = candidate[8:]
                elif lowered.startswith("http://"):
                    candidate = candidate[7:]
                elif "://" in candidate:
                    return False

                if candidate.startswith("*."):
                    candidate = candidate[2:]

                if "*" in candidate:
                    return False

                host = candidate
                if ":" in candidate:
                    host, port = candidate.rsplit(":", 1)
                    if not port.isdigit() or len(port) > 5:
                        return False
                    if not 1 <= int(port) <= 65535:
                        return False

                if not host or len(host) > 253:
                    return False

                labels = host.split(".")
                for label in labels:
                    if (
                        not label
                        or len(label) > 63
                        or re.fullmatch(
                            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                            label,
                        )
                        is None
                    ):
                        return False

                return True

            # Only recognizable restrictive source expressions count.
            # An empty source list blocks all framing; a wildcard does not.
            frame_ancestors_restrictive = all(
                valid_frame_source(source) for source in sources
            ) and "*" not in sources

    return bool(directives), frame_ancestors_restrictive


def _cookie_summary(
    cookie_headers: list[bytes],
) -> dict[str, int]:
    summary = {
        "cookies_seen": len(cookie_headers),
        "secure": 0,
        "httponly": 0,
        "samesite_strict": 0,
        "samesite_lax": 0,
        "samesite_none": 0,
        "samesite_missing_or_invalid": 0,
    }

    for raw_cookie in cookie_headers:
        # Cookie names and values are intentionally discarded.
        parts = raw_cookie.decode("latin-1").split(";")
        attributes: dict[str, str | None] = {}
        duplicates: set[str] = set()

        for part in parts[1:]:
            key, separator, value = part.strip().partition("=")
            key = key.casefold()

            if not key:
                continue

            if key in attributes:
                duplicates.add(key)
                continue

            attributes[key] = value.strip() if separator else None

        # Treat the entire cookie's security metadata as ambiguous if
        # any attribute is duplicated.
        if duplicates:
            summary["samesite_missing_or_invalid"] += 1
            continue

        if "secure" in attributes and attributes["secure"] is None:
            summary["secure"] += 1

        if "httponly" in attributes and attributes["httponly"] is None:
            summary["httponly"] += 1

        samesite = attributes.get("samesite")

        if samesite is None or "samesite" in duplicates:
            summary["samesite_missing_or_invalid"] += 1
        elif samesite.casefold() == "strict":
            summary["samesite_strict"] += 1
        elif samesite.casefold() == "lax":
            summary["samesite_lax"] += 1
        elif samesite.casefold() == "none":
            summary["samesite_none"] += 1
        else:
            summary["samesite_missing_or_invalid"] += 1

    return summary


def _observation(
    name: str,
    status: str,
    evidence: str = "",
) -> dict[str, str]:
    return {
        "check": name,
        "status": status,
        "evidence": evidence,
    }


def analyze_response_headers(
    raw_headers: list[tuple[bytes, bytes]],
    *,
    scheme: str,
    policy: WebPosturePolicy,
) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Analyze allowlisted headers without retaining cookie values."""
    headers, cookie_headers = _collect_headers(raw_headers, policy)
    observations: list[dict[str, str]] = []

    # Strict-Transport-Security
    hsts, state = _single_header(headers, "strict-transport-security")

    if scheme != "https":
        observations.append(
            _observation("strict_transport_security", "not_applicable")
        )
    elif state == "missing":
        observations.append(
            _observation("strict_transport_security", "missing")
        )
    elif state == "invalid" or not _valid_hsts(hsts or ""):
        observations.append(
            _observation("strict_transport_security", "invalid")
        )
    else:
        hsts_parts = [part.strip() for part in (hsts or "").split(";")]
        max_age_match = re.fullmatch(
            r"max-age\s*=\s*(\d+)",
            hsts_parts[0],
            re.IGNORECASE,
        )

        safe_hsts_evidence = "; ".join(
            [f"max-age={max_age_match.group(1)}"]
            + sorted(
                part.casefold()
                for part in hsts_parts[1:]
                if part
            )
        )

        observations.append(
            _observation(
                "strict_transport_security",
                "present",
                safe_hsts_evidence,
            )
        )

    # Content-Security-Policy
    csp, csp_state = _single_header(headers, "content-security-policy")
    frame_ancestors = False

    if csp_state == "present":
        valid_csp, frame_ancestors = _parse_csp(csp or "")
        if not valid_csp:
            csp_state = "invalid"

    if csp_state == "present":
        directive_names = [
            part.strip().split()[0].casefold()
            for part in (csp or "").split(";")
            if part.strip()
        ]

        observations.append(
            _observation(
                "content_security_policy",
                "present",
                (
                    "directives: "
                    + ", ".join(directive_names)
                    + "; directive values are not fully validated"
                ),
            )
        )
    else:
        observations.append(
            _observation("content_security_policy", csp_state)
        )

    # X-Content-Type-Options
    nosniff, state = _single_header(
        headers,
        "x-content-type-options",
    )

    if state == "present" and (nosniff or "").casefold() != "nosniff":
        state = "invalid"

    observations.append(
        _observation(
            "x_content_type_options",
            state,
            "nosniff" if state == "present" else "",
        )
    )

    # Clickjacking protection: CSP frame-ancestors takes precedence.
    frame, frame_state = _single_header(headers, "x-frame-options")

    if frame_ancestors:
        observations.append(
            _observation(
                "clickjacking_protection",
                "present",
                "CSP frame-ancestors directive present",
            )
        )
    elif frame_state == "present":
        if (frame or "").casefold() not in {"deny", "sameorigin"}:
            observations.append(
                _observation("clickjacking_protection", "invalid")
            )
        else:
            observations.append(
                _observation(
                    "clickjacking_protection",
                    "present",
                    (frame or "").casefold(),
                )
            )
    else:
        observations.append(
            _observation("clickjacking_protection", frame_state)
        )

    # Referrer-Policy
    referrer, state = _single_header(headers, "referrer-policy")
    tokens: list[str] = []

    if state == "present":
        tokens = [
            item.strip().casefold()
            for item in (referrer or "").split(",")
        ]

        if not tokens or any(
            token not in _REFERRER_POLICIES
            for token in tokens
        ):
            state = "invalid"

    observations.append(
        _observation(
            "referrer_policy",
            state,
            ", ".join(tokens) if state == "present" else "",
        )
    )

    # Permissions-Policy
    permissions, state = _single_header(
        headers,
        "permissions-policy",
    )

    permission_directives: list[str] = []
    if state == "present":
        seen_directives: set[str] = set()

        for clause in (permissions or "").split(","):
            match = re.fullmatch(
                r"\s*([a-z][a-z0-9-]*)\s*=\s*(?:\*|\(([^()]*)\))\s*",
                clause,
                flags=re.IGNORECASE,
            )
            if match is None:
                state = "invalid"
                permission_directives = []
                break

            directive = match.group(1).casefold()
            allowlist = match.group(2)

            if directive in seen_directives:
                state = "invalid"
                permission_directives = []
                break

            seen_directives.add(directive)

            if allowlist is not None:
                members = allowlist.split()
                if any(
                    re.fullmatch(
                        r'(?:self|src)|"[^"\s]+"',
                        member,
                        flags=re.IGNORECASE,
                    ) is None
                    for member in members
                ):
                    state = "invalid"
                    permission_directives = []
                    break

            permission_directives.append(directive)

    observations.append(
        _observation(
            "permissions_policy",
            state,
            (
                "directives: " + ", ".join(permission_directives)
                if state == "present"
                else ""
            ),
        )
    )

    return observations, _cookie_summary(cookie_headers)


def run_web_posture_assessment(
    store: ScanStore,
    asset_id: str,
    execution_policy: InventoryExecutionPolicy,
    posture_policy: WebPosturePolicy,
    *,
    authorization_confirmed: bool,
    resolver: Resolver | None = None,
) -> dict[str, Any]:
    """Assess root-response security metadata for one authorized inventory asset."""
    if not posture_policy.enabled:
        raise ScopeError("Web posture assessment is disabled by server policy.")

    if not execution_policy.enabled:
        raise ScopeError("Inventory-scoped execution is disabled by server policy.")

    if not authorization_confirmed:
        raise ScopeError("Explicit assessment authorization confirmation is required.")

    assets, _entries = store.authorization_snapshot()
    asset = next(
        (item for item in assets if item["asset_id"] == asset_id),
        None,
    )

    if asset is None:
        raise ScopeError("Selected inventory asset is unavailable.")

    if asset["asset_type"] not in {
        "domain",
        "subdomain",
        "hostname",
        "ipv4",
        "ipv6",
    }:
        raise ScopeError("Selected inventory asset is not an executable target.")

    if not authorization_eligibility(asset)[0]:
        raise ScopeError("Selected inventory asset is not currently authorized.")

    host = asset["canonical_value"]
    authority = f"[{host}]" if ":" in host else host
    origin = f"{execution_policy.scheme}://{authority}:{execution_policy.port}"

    transport = InventoryScopedTransport(
        store,
        resolver
        or DnspythonResolver(
            nameservers=execution_policy.dns_nameservers,
            timeout_seconds=execution_policy.dns_timeout_seconds,
            max_cname_depth=execution_policy.dns_max_cname_depth,
            max_answers=execution_policy.dns_max_answers,
        ),
        execution_policy,
        asset_id=asset_id,
        asset_type=asset["asset_type"],
        canonical_value=asset["canonical_value"],
    )

    result: dict[str, Any] = {
        "schema_version": 1,
        "assessed_at": datetime.now(UTC).isoformat(),
        "asset_id": asset_id,
        "scheme": execution_policy.scheme,
        "port": execution_policy.port,
        "method": "HEAD",
        "path": "/",
        "status_code": None,
        "outcome": "inconclusive",
        "observations": [],
        "cookie_summary": {},
    }

    try:
        with httpx.Client(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(posture_policy.timeout_seconds),
        ) as client:
            request = client.build_request("HEAD", f"{origin}/")

            # Defense in depth: this service may send only HEAD to the exact root.
            if (
                request.method != "HEAD"
                or request.url.scheme != execution_policy.scheme
                or request.url.host.casefold() != host.casefold()
                or (
                    request.url.port
                    or (80 if execution_policy.scheme == "http" else 443)
                )
                != execution_policy.port
                or request.url.path != "/"
                or request.url.query
                or request.url.fragment
                or request.url.username
                or request.url.password
            ):
                raise ScopeError(
                    "Posture request does not match the approved root origin."
                )

            response = client.send(request, stream=True)

            try:
                result["status_code"] = response.status_code

                observations, cookie_summary = analyze_response_headers(
                    response.headers.raw,
                    scheme=execution_policy.scheme,
                    policy=posture_policy,
                )

                result["observations"] = observations
                result["cookie_summary"] = cookie_summary
                result["outcome"] = "completed"
            finally:
                response.close()

    except ScopeError:
        raise
    except PostureResponseLimitError:
        result["outcome"] = "inconclusive"
        result["reason"] = "response_metadata_limit_exceeded"
    except httpx.TimeoutException:
        result["outcome"] = "inconclusive"
        result["reason"] = "request_timeout"
    except httpx.RequestError:
        result["outcome"] = "inconclusive"
        result["reason"] = "request_failed"

    return result
