import ipaddress

import pytest

from authmatrix.errors import ScopeError
from authmatrix.execution_scope import (
    InventoryExecutionPolicy,
    ResolvedAddressSet,
    WebPosturePolicy,
)
from authmatrix.web.posture import (
    PostureResponseLimitError,
    analyze_response_headers,
    run_web_posture_assessment,
)
from authmatrix.web.storage import ScanStore


def _posture_policy(**updates):
    values = {"enabled": True}
    values.update(updates)
    return WebPosturePolicy(**values)


def _headers(*items):
    return [(name.encode(), value.encode()) for name, value in items]


def test_header_analysis_recognizes_security_headers():
    headers = _headers(
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=()"),
    )

    observations, cookies = analyze_response_headers(
        headers,
        scheme="https",
        policy=_posture_policy(),
    )

    states = {item["check"]: item["status"] for item in observations}

    assert states["strict_transport_security"] == "present"
    assert states["content_security_policy"] == "present"
    assert states["x_content_type_options"] == "present"
    assert states["clickjacking_protection"] == "present"
    assert states["referrer_policy"] == "present"
    assert states["permissions_policy"] == "present"
    assert cookies["cookies_seen"] == 0


def test_http_hsts_is_not_applicable():
    observations, _ = analyze_response_headers(
        [],
        scheme="http",
        policy=_posture_policy(),
    )

    states = {item["check"]: item["status"] for item in observations}
    assert states["strict_transport_security"] == "not_applicable"


def test_duplicate_security_header_is_invalid():
    observations, _ = analyze_response_headers(
        _headers(
            ("X-Content-Type-Options", "nosniff"),
            ("X-Content-Type-Options", "invalid"),
        ),
        scheme="https",
        policy=_posture_policy(),
    )

    states = {item["check"]: item["status"] for item in observations}
    assert states["x_content_type_options"] == "invalid"


def test_cookie_values_and_names_are_not_retained():
    headers = [
        (
            b"Set-Cookie",
            b"session_secret=do-not-store; Secure; HttpOnly; SameSite=Strict",
        ),
        (
            b"Set-Cookie",
            b"preference_secret=also-do-not-store; SameSite=Lax",
        ),
    ]

    observations, cookies = analyze_response_headers(
        headers,
        scheme="https",
        policy=_posture_policy(),
    )

    assert cookies == {
        "cookies_seen": 2,
        "secure": 1,
        "httponly": 1,
        "samesite_strict": 1,
        "samesite_lax": 1,
        "samesite_none": 0,
        "samesite_missing_or_invalid": 0,
    }

    assert "session_secret" not in repr(observations)
    assert "do-not-store" not in repr(observations)
    assert "preference_secret" not in repr(cookies)


def test_cookie_header_limit_is_enforced():
    with pytest.raises(PostureResponseLimitError):
        analyze_response_headers(
            [
                (b"Set-Cookie", b"a=1"),
                (b"Set-Cookie", b"b=2"),
            ],
            scheme="https",
            policy=_posture_policy(max_cookie_headers=1),
        )


def test_total_response_header_size_is_enforced():
    with pytest.raises(PostureResponseLimitError):
        analyze_response_headers(
            [(b"X-Test", b"x" * 100)],
            scheme="https",
            policy=_posture_policy(max_header_bytes=32),
        )


def test_malformed_header_name_is_rejected():
    with pytest.raises(PostureResponseLimitError):
        analyze_response_headers(
            [(b"Bad Header", b"value")],
            scheme="https",
            policy=_posture_policy(),
        )


def test_invalid_security_header_values_are_not_marked_present():
    observations, _ = analyze_response_headers(
        _headers(
            ("Strict-Transport-Security", "max-age=invalid"),
            ("X-Content-Type-Options", "nosniff, invalid"),
            ("X-Frame-Options", "ALLOWALL"),
            ("Referrer-Policy", "made-up-policy"),
        ),
        scheme="https",
        policy=_posture_policy(),
    )

    states = {item["check"]: item["status"] for item in observations}
    assert states["strict_transport_security"] == "invalid"
    assert states["x_content_type_options"] == "invalid"
    assert states["clickjacking_protection"] == "invalid"
    assert states["referrer_policy"] == "invalid"


def _store(
    path,
    *,
    asset_type="hostname",
    value="api.example.com",
    status="authorized",
):
    store = ScanStore(path)
    store.create_asset(
        {
            "asset_id": "target",
            "name": "Target",
            "asset_type": asset_type,
            "canonical_value": value,
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": status,
            "authorization_confirmed": status == "authorized",
            "authorization_reference": "AUTH-1" if status == "authorized" else None,
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("target", "include", "2026-11-12T00:00:00+00:00")
    return store


class FakeResolver:
    def __init__(self):
        self.calls = []

    def resolve(self, hostname):
        self.calls.append(hostname)
        return ResolvedAddressSet((ipaddress.ip_address("8.8.8.8"),))


class FakeStream:
    def __init__(self, response, body=b""):
        self.response = response
        self.body = body
        self.request = bytearray()
        self.read_calls = 0
        self.closed = False

    def read(self, max_bytes, timeout=None):
        self.read_calls += 1

        if self.response:
            chunk = self.response[:max_bytes]
            self.response = self.response[max_bytes:]
            return chunk

        chunk = self.body[:max_bytes]
        self.body = self.body[max_bytes:]
        return chunk

    def write(self, buffer, timeout=None):
        self.request.extend(buffer)

    def close(self):
        self.closed = True

    def get_extra_info(self, info):
        if info == "server_addr":
            return ("8.8.8.8", 80)
        if info == "client_addr":
            return ("127.0.0.1", 12345)
        return None


class FakeBackend:
    def __init__(self, _address, _hostname, _port, response=None, body=b""):
        self.streams = []
        self.response = response or (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 999\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"Set-Cookie: secret_name=secret_value; Secure; HttpOnly; SameSite=Lax\r\n"
            b"\r\n"
        )
        self.body = body

    def connect_tcp(self, host, port, **_kwargs):
        assert host == "api.example.com"
        assert port == 80
        stream = FakeStream(self.response, self.body)
        self.streams.append(stream)
        return stream


def _install_posture_backend(monkeypatch, response, body=b""):
    from authmatrix import transport

    backends = []

    def backend_factory(*args):
        backend = FakeBackend(*args, response=response, body=body)
        backends.append(backend)
        return backend

    monkeypatch.setattr(
        transport,
        "_PinnedNetworkBackend",
        backend_factory,
    )
    return backends


def _execution_policy():
    return InventoryExecutionPolicy(
        enabled=True,
        scheme="http",
        port=80,
        allowed_ports=frozenset({80}),
        allow_http=True,
        allow_public_egress=True,
        allowed_restricted_classes=frozenset(),
    )


def test_assessment_sends_only_head_root_and_does_not_store_cookie_values(
    tmp_path, monkeypatch
):
    from authmatrix import transport

    backends = []

    def backend_factory(*args):
        backend = FakeBackend(*args)
        backends.append(backend)
        return backend

    monkeypatch.setattr(
        transport,
        "_PinnedNetworkBackend",
        backend_factory,
    )

    store = _store(tmp_path / "scans.sqlite3")
    resolver = FakeResolver()

    result = run_web_posture_assessment(
        store,
        "target",
        _execution_policy(),
        _posture_policy(),
        authorization_confirmed=True,
        resolver=resolver,
    )

    assert result["outcome"] == "completed"
    assert result["status_code"] == 200
    assert result["method"] == "HEAD"
    assert result["path"] == "/"
    assert resolver.calls == ["api.example.com"]

    request = bytes(backends[0].streams[0].request).lower()
    assert request.startswith(b"head / http/1.1\r\n")
    assert b"get /" not in request
    assert backends[0].streams[0].closed is True

    serialized = repr(result)
    assert "secret_name" not in serialized
    assert "secret_value" not in serialized


def test_assessment_does_not_follow_redirects(tmp_path, monkeypatch):
    response = (
        b"HTTP/1.1 302 Found\r\n"
        b"Content-Length: 0\r\n"
        b"Location: http://attacker.example/redirect-target\r\n"
        b"\r\n"
    )
    backends = _install_posture_backend(monkeypatch, response)
    resolver = FakeResolver()

    result = run_web_posture_assessment(
        _store(tmp_path / "scans.sqlite3"),
        "target",
        _execution_policy(),
        _posture_policy(),
        authorization_confirmed=True,
        resolver=resolver,
    )

    assert result["outcome"] == "completed"
    assert result["status_code"] == 302
    assert len(backends) == 1
    assert resolver.calls == ["api.example.com"]
    assert bytes(backends[0].streams[0].request).lower().startswith(
        b"head / http/1.1\r\n"
    )
    assert backends[0].streams[0].closed is True


def test_assessment_does_not_consume_response_body(tmp_path, monkeypatch):
    body = b"SECRET_RESPONSE_BODY"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 20\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"\r\n"
    )
    backends = _install_posture_backend(monkeypatch, response, body)

    result = run_web_posture_assessment(
        _store(tmp_path / "scans.sqlite3"),
        "target",
        _execution_policy(),
        _posture_policy(),
        authorization_confirmed=True,
        resolver=FakeResolver(),
    )

    stream = backends[0].streams[0]

    assert result["outcome"] == "completed"
    assert result["status_code"] == 200
    assert stream.body == body
    assert stream.closed is True
    assert "SECRET_RESPONSE_BODY" not in repr(result)


def test_assessment_requires_explicit_confirmation(tmp_path):
    store = _store(tmp_path / "scans.sqlite3")

    with pytest.raises(ScopeError, match="confirmation"):
        run_web_posture_assessment(
            store,
            "target",
            _execution_policy(),
            _posture_policy(),
            authorization_confirmed=False,
            resolver=FakeResolver(),
        )


def test_assessment_rejects_unconfirmed_asset_before_dns(tmp_path):
    store = _store(
        tmp_path / "scans.sqlite3",
        status="pending",
    )
    resolver = FakeResolver()

    with pytest.raises(ScopeError):
        run_web_posture_assessment(
            store,
            "target",
            _execution_policy(),
            _posture_policy(),
            authorization_confirmed=True,
            resolver=resolver,
        )

    assert resolver.calls == []


def test_assessment_requires_both_server_side_feature_flags(tmp_path):
    store = _store(tmp_path / "scans.sqlite3")

    with pytest.raises(ScopeError, match="disabled"):
        run_web_posture_assessment(
            store,
            "target",
            _execution_policy(),
            _posture_policy(enabled=False),
            authorization_confirmed=True,
            resolver=FakeResolver(),
        )


def test_hsts_zero_max_age_is_invalid():
    observations, _ = analyze_response_headers(
        _headers(("Strict-Transport-Security", "max-age=0")),
        scheme="https",
        policy=_posture_policy(),
    )
    states = {item["check"]: item["status"] for item in observations}
    assert states["strict_transport_security"] == "invalid"


def test_hsts_very_long_positive_max_age_does_not_crash():
    max_age = "9" * 5000
    observations, _ = analyze_response_headers(
        _headers(("Strict-Transport-Security", f"max-age={max_age}")),
        scheme="https",
        policy=_posture_policy(),
    )
    states = {item["check"]: item["status"] for item in observations}
    assert states["strict_transport_security"] == "present"


def test_csp_evidence_does_not_retain_raw_policy_values():
    secret = "nonce-super-secret-value"
    internal = "https://internal.example.local"
    observations, _ = analyze_response_headers(
        _headers(
            (
                "Content-Security-Policy",
                f"default-src 'self' {internal}; script-src 'nonce-{secret}'",
            )
        ),
        scheme="https",
        policy=_posture_policy(),
    )
    csp = next(
        item for item in observations
        if item["check"] == "content_security_policy"
    )
    assert csp["status"] == "present"
    assert secret not in repr(observations)
    assert internal not in repr(observations)


def test_permissions_policy_evidence_does_not_retain_origins():
    origin = "https://internal.example.local"
    observations, _ = analyze_response_headers(
        _headers(("Permissions-Policy", f"camera=(self {origin})")),
        scheme="https",
        policy=_posture_policy(),
    )
    assert origin not in repr(observations)


def test_permissions_policy_rejects_malformed_directive_names():
    injected = "camera=(self), bad<script>=()"
    observations, _ = analyze_response_headers(
        _headers(("Permissions-Policy", injected)),
        scheme="https",
        policy=_posture_policy(),
    )

    item = next(
        item for item in observations
        if item["check"] == "permissions_policy"
    )
    assert item["status"] == "invalid"
    assert item["evidence"] == ""
    assert "bad<script>" not in repr(observations)


def test_permissions_policy_rejects_duplicate_directives():
    observations, _ = analyze_response_headers(
        _headers(("Permissions-Policy", "camera=(self), camera=()")),
        scheme="https",
        policy=_posture_policy(),
    )

    item = next(
        item for item in observations
        if item["check"] == "permissions_policy"
    )
    assert item["status"] == "invalid"
    assert item["evidence"] == ""


def test_referrer_policy_evidence_is_normalized():
    observations, _ = analyze_response_headers(
        _headers(("Referrer-Policy", "Strict-Origin")),
        scheme="https",
        policy=_posture_policy(),
    )
    item = next(
        item for item in observations
        if item["check"] == "referrer_policy"
    )
    assert item["evidence"] == "strict-origin"


def test_valid_csp_frame_ancestors_overrides_invalid_xfo():
    observations, _ = analyze_response_headers(
        _headers(
            ("X-Frame-Options", "ALLOWALL"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
        ),
        scheme="https",
        policy=_posture_policy(),
    )
    states = {item["check"]: item["status"] for item in observations}
    assert states["clickjacking_protection"] == "present"


def test_permissive_csp_frame_ancestors_wildcard_is_not_protection():
    observations, _ = analyze_response_headers(
        _headers(("Content-Security-Policy", "frame-ancestors *")),
        scheme="https",
        policy=_posture_policy(),
    )
    states = {item["check"]: item["status"] for item in observations}
    assert states["content_security_policy"] == "present"
    assert states["clickjacking_protection"] == "missing"


def test_invalid_csp_frame_ancestors_source_is_not_protection():
    for source_value in ("'unsafe-inline'", "data:text/html"):
        observations, _ = analyze_response_headers(
            _headers(
                ("Content-Security-Policy", f"frame-ancestors {source_value}")
            ),
            scheme="https",
            policy=_posture_policy(),
        )
        states = {item["check"]: item["status"] for item in observations}
        assert states["clickjacking_protection"] == "missing"


def test_valid_csp_frame_ancestors_host_source_is_protection():
    observations, _ = analyze_response_headers(
        _headers(
            (
                "Content-Security-Policy",
                "frame-ancestors https://trusted.example",
            )
        ),
        scheme="https",
        policy=_posture_policy(),
    )
    states = {item["check"]: item["status"] for item in observations}
    assert states["clickjacking_protection"] == "present"


def test_cookie_duplicate_attributes_are_not_counted_as_valid():
    observations, cookies = analyze_response_headers(
        [
            (
                b"Set-Cookie",
                b"session=value; Secure; Secure; HttpOnly; SameSite=Strict",
            )
        ],
        scheme="https",
        policy=_posture_policy(),
    )
    assert cookies["secure"] == 0
    assert cookies["httponly"] == 0
    assert cookies["samesite_missing_or_invalid"] == 1
    assert "session" not in repr(observations)


def test_broad_csp_frame_ancestor_schemes_are_not_protection():
    for source_value in (
        "https:",
        "http:",
        "https: https://trusted.example",
    ):
        observations, _ = analyze_response_headers(
            _headers(
                (
                    "Content-Security-Policy",
                    f"frame-ancestors {source_value}",
                )
            ),
            scheme="https",
            policy=_posture_policy(),
        )

        states = {item["check"]: item["status"] for item in observations}
        assert states["clickjacking_protection"] == "missing", source_value


def test_malformed_csp_frame_ancestors_host_sources_are_not_protection():
    for source_value in (
        "trusted..example",
        ".trusted.example",
        "trusted.example.",
        "-trusted.example",
        "trusted-.example",
        "trusted.example:0",
        "trusted.example:65536",
        "trusted.example:999999",
        "trusted.example:abc",
        "trusted.example:443:80",
    ):
        observations, _ = analyze_response_headers(
            _headers(
                (
                    "Content-Security-Policy",
                    f"frame-ancestors {source_value}",
                )
            ),
            scheme="https",
            policy=_posture_policy(),
        )
        states = {item["check"]: item["status"] for item in observations}
        assert states["clickjacking_protection"] == "missing", source_value
