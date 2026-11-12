import ipaddress
import sqlite3
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event
from time import sleep

import httpcore
import httpx
import pytest

from authmatrix.config import load_config
from authmatrix.errors import ScanError, ScopeError
from authmatrix.execution_scope import (
    AddressClass,
    InventoryExecutionPolicy,
    ResolvedAddressSet,
)
from authmatrix.scanner import run_inventory_authorization_tests
from authmatrix.transport import (
    InventoryScopedTransport,
    _PinnedNetworkBackend,
    _PinnedNetworkStream,
)
from authmatrix.web.storage import ScanStore


class FakeResolver:
    def __init__(self, addresses, callback=None):
        self.addresses = tuple(ipaddress.ip_address(value) for value in addresses)
        self.callback = callback
        self.calls = []

    def resolve(self, hostname):
        self.calls.append(hostname)
        if self.callback:
            self.callback()
        return ResolvedAddressSet(self.addresses)


class FakeNetworkStream:
    def __init__(self, address, response):
        self.address = str(address)
        self.response = response
        self.request_data = bytearray()
        self.closed = False

    def read(self, max_bytes, timeout=None):
        chunk = self.response[:max_bytes]
        self.response = self.response[max_bytes:]
        return chunk

    def write(self, buffer, timeout=None):
        self.request_data.extend(buffer)

    def close(self):
        self.closed = True

    def get_extra_info(self, info):
        if info == "server_addr":
            return (self.address, 80)
        if info == "client_addr":
            return ("127.0.0.1", 12345)
        return None


class FakeBackend:
    def __init__(self, address, response):
        self.address = address
        self.response = response
        self.streams = []
        self.origins = []

    def connect_tcp(self, host, port, **_kwargs):
        self.origins.append((host, port))
        stream = FakeNetworkStream(self.address, self.response)
        self.streams.append(stream)
        return stream


def _policy(**updates):
    values = {
        "enabled": True,
        "scheme": "http",
        "port": 80,
        "allowed_ports": frozenset({80}),
        "allow_http": True,
        "allow_public_egress": True,
        "allowed_restricted_classes": frozenset(),
    }
    values.update(updates)
    return InventoryExecutionPolicy(**values)


def _store(tmp_path, *, asset_type="hostname", value="api.example.com"):
    store = ScanStore(tmp_path / "scans.sqlite3")
    store.create_asset(
        {
            "asset_id": "target",
            "name": "Target",
            "asset_type": asset_type,
            "canonical_value": value,
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-1",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("target", "include", "2026-11-12T00:00:00+00:00")
    return store


def _transport(
    store,
    resolver,
    *,
    asset_type="hostname",
    canonical_value="api.example.com",
    **policy_overrides,
):
    return InventoryScopedTransport(
        store,
        resolver,
        _policy(**policy_overrides),
        asset_id="target",
        asset_type=asset_type,
        canonical_value=canonical_value,
    )


def _success_response():
    return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"


def _install_fake_backend(monkeypatch, address="8.8.8.8", response=None):
    backend = FakeBackend(address, response or _success_response())
    monkeypatch.setattr(
        "authmatrix.transport._PinnedNetworkBackend",
        lambda *_args, **_kwargs: backend,
    )
    return backend


def test_authorized_public_target_is_pinned_and_preserves_http_authority(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch, "8.8.8.8")

    with httpx.Client(transport=_transport(store, resolver)) as client:
        response = client.get("http://api.example.com:80/items")

    assert response.status_code == 200
    assert resolver.calls == ["api.example.com"]
    assert backend.origins == [("api.example.com", 80)]
    assert (
        b"host: api.example.com\r\n" in bytes(backend.streams[0].request_data).lower()
    )


def test_unauthorized_or_excluded_hostname_has_zero_dns_and_socket_attempts(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    store.update_authorization(
        "target",
        {
            "authorization_status": "revoked",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-1",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "updated_at": "2026-11-12T00:00:00+00:00",
        },
    )
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert resolver.calls == []
    assert backend.origins == []

    store = _store(tmp_path / "excluded", asset_type="hostname")
    store.create_asset(
        {
            "asset_id": "parent",
            "name": "Parent",
            "asset_type": "domain",
            "canonical_value": "example.com",
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-PARENT",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("parent", "include", "2026-11-12T00:00:00+00:00")
    store.set_scope_entry("target", "exclude", "2026-11-12T00:00:00+00:00")
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert resolver.calls == []
    assert backend.origins == []


@pytest.mark.parametrize(
    "state",
    ["pending", "unconfirmed", "revoked", "inactive", "expired", "not_yet_valid"],
)
def test_ineligible_authorization_states_stop_before_dns_or_socket(
    tmp_path, monkeypatch, state
):
    store = _store(tmp_path)
    if state == "inactive":
        store.set_asset_active("target", False, "2026-11-12T00:00:00+00:00")
    elif state == "unconfirmed":
        with store._connect() as connection:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(
                "UPDATE assets SET authorization_confirmed = 0 "
                "WHERE asset_id = 'target'"
            )
    else:
        authorization = {
            "authorization_status": ("pending" if state == "pending" else "revoked"),
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-1",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
        if state == "expired":
            authorization.update(
                authorization_status="authorized",
                authorization_expires_at="2000-01-01",
            )
        elif state == "not_yet_valid":
            authorization.update(
                authorization_status="authorized",
                authorization_starts_at="2999-01-01",
            )
        store.update_authorization("target", authorization)

    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert resolver.calls == []
    assert backend.origins == []


def test_unsafe_or_mixed_dns_answers_are_rejected_before_target_socket(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8", "10.0.0.4"])
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []

    resolver = FakeResolver(["10.0.0.4"])
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.4",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "240.0.0.1",
        "192.0.2.1",
        "2001:db8::1",
    ],
)
def test_restricted_and_special_dns_answers_never_connect_by_default(
    tmp_path, monkeypatch, address
):
    store = _store(tmp_path)
    resolver = FakeResolver([address])
    backend = _install_fake_backend(monkeypatch, address)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []


def test_restricted_address_requires_policy_and_matching_ip_scope(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    store.create_asset(
        {
            "asset_id": "private",
            "name": "Private IP",
            "asset_type": "ipv4_cidr",
            "canonical_value": "10.0.0.0/24",
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-IP",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("private", "include", "2026-11-12T00:00:00+00:00")
    resolver = FakeResolver(["10.0.0.4"])
    backend = _install_fake_backend(monkeypatch, "10.0.0.4")
    with httpx.Client(
        transport=_transport(
            store,
            resolver,
            allowed_restricted_classes=frozenset({AddressClass.PRIVATE}),
        )
    ) as client:
        response = client.get("http://api.example.com/items")
    assert response.status_code == 200
    assert backend.origins == [("api.example.com", 80)]

    store.create_asset(
        {
            "asset_id": "excluded-private",
            "name": "Excluded private IP",
            "asset_type": "ipv4_cidr",
            "canonical_value": "10.0.0.4/32",
            "description": "",
            "tags": [],
            "organization": "Local workspace",
            "authorization_status": "authorized",
            "authorization_confirmed": True,
            "authorization_reference": "AUTH-EXCLUDE",
            "authorization_starts_at": None,
            "authorization_expires_at": None,
            "created_at": "2026-11-12T00:00:00+00:00",
            "updated_at": "2026-11-12T00:00:00+00:00",
        }
    )
    store.set_scope_entry("excluded-private", "exclude", "2026-11-12T00:00:00+00:00")
    resolver = FakeResolver(["10.0.0.4"])
    backend = _install_fake_backend(monkeypatch, "10.0.0.4")
    with httpx.Client(
        transport=_transport(
            store,
            resolver,
            allowed_restricted_classes=frozenset({AddressClass.PRIVATE}),
        )
    ) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []


def test_public_ipv6_answer_uses_same_pinned_gate(tmp_path, monkeypatch):
    store = _store(tmp_path)
    resolver = FakeResolver(["2001:4860:4860::8888"])
    backend = _install_fake_backend(monkeypatch, "2001:4860:4860::8888")
    with httpx.Client(transport=_transport(store, resolver)) as client:
        response = client.get("http://api.example.com/items")
    assert response.status_code == 200
    assert resolver.calls == ["api.example.com"]
    assert backend.origins == [("api.example.com", 80)]


@pytest.mark.parametrize(
    ("asset_type", "value", "url", "host_header"),
    [
        ("ipv4", "8.8.8.8", "http://8.8.8.8:80/items", b"host: 8.8.8.8\r\n"),
        (
            "ipv6",
            "2001:4860:4860::8888",
            "http://[2001:4860:4860::8888]:80/items",
            b"host: [2001:4860:4860::8888]\r\n",
        ),
    ],
)
def test_literal_ip_assets_skip_dns_and_preserve_authority(
    tmp_path,
    monkeypatch,
    asset_type,
    value,
    url,
    host_header,
):
    store = _store(tmp_path, asset_type=asset_type, value=value)
    resolver = FakeResolver([])
    backend = _install_fake_backend(monkeypatch, value)
    transport = _transport(
        store,
        resolver,
        asset_type=asset_type,
        canonical_value=value,
    )

    with httpx.Client(transport=transport) as client:
        response = client.get(url)

    assert response.status_code == 200
    assert resolver.calls == []
    assert backend.origins == [(value, 80)]
    assert host_header in bytes(backend.streams[0].request_data).lower()


def test_asset_revoked_during_dns_is_rejected_before_socket(tmp_path, monkeypatch):
    store = _store(tmp_path)

    def revoke():
        store.update_authorization(
            "target",
            {
                "authorization_status": "revoked",
                "authorization_confirmed": True,
                "authorization_reference": "AUTH-1",
                "authorization_starts_at": None,
                "authorization_expires_at": None,
                "updated_at": "2026-11-12T00:00:00+00:00",
            },
        )

    resolver = FakeResolver(["8.8.8.8"], callback=revoke)
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []


def test_target_identity_change_during_dns_is_rejected_before_socket(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)

    def change_target():
        store.update_asset(
            "target",
            {
                "name": "Target",
                "asset_type": "hostname",
                "canonical_value": "admin.example.com",
                "description": "",
                "tags": [],
                "organization": "Local workspace",
                "updated_at": "2026-11-12T00:00:00+00:00",
            },
        )

    resolver = FakeResolver(["8.8.8.8"], callback=change_target)
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError):
            client.get("http://api.example.com/items")
    assert backend.origins == []
    assert store.get_asset("target")["authorization_status"] == "pending"


def test_final_authorization_lock_timeout_prevents_socket(tmp_path, monkeypatch):
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    transport = _transport(
        store,
        resolver,
        authorization_lock_timeout=0.05,
    )
    with store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        with httpx.Client(transport=transport) as client:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                client.get("http://api.example.com/items")
    assert backend.origins == []


def test_revocation_waits_until_response_headers_after_final_authorization(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    connected = Event()
    release = Event()

    class BlockingBackend:
        def __init__(self, address, _hostname, _port):
            self.address = address

        def connect_tcp(self, host, port, **_kwargs):
            connected.set()
            assert release.wait(timeout=2)
            stream = FakeNetworkStream(self.address, _success_response())
            stream.get_extra_info = lambda info: (
                (str(self.address), port) if info == "server_addr" else None
            )
            return stream

    monkeypatch.setattr(
        "authmatrix.transport._PinnedNetworkBackend",
        BlockingBackend,
    )
    resolver = FakeResolver(["8.8.8.8"])
    transport = _transport(store, resolver)

    def send_request():
        with httpx.Client(transport=transport) as client:
            return client.get("http://api.example.com/items")

    with ThreadPoolExecutor(max_workers=2) as executor:
        request = executor.submit(send_request)
        assert connected.wait(timeout=2)
        revocation = executor.submit(
            store.update_authorization,
            "target",
            {
                "authorization_status": "revoked",
                "authorization_confirmed": True,
                "authorization_reference": "AUTH-1",
                "authorization_starts_at": None,
                "authorization_expires_at": None,
                "updated_at": "2026-11-12T00:00:00+00:00",
            },
        )
        sleep(0.05)
        assert not revocation.done()
        release.set()
        assert request.result(timeout=3).status_code == 200
        assert revocation.result(timeout=3) is True
    assert store.get_asset("target")["authorization_status"] == "revoked"


def test_host_override_is_rejected_and_each_request_uses_new_pool(
    tmp_path, monkeypatch
):
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    with httpx.Client(transport=_transport(store, resolver)) as client:
        with pytest.raises(ScopeError, match="Host authority"):
            client.get(
                "http://api.example.com/items",
                headers={"Host": "attacker.example"},
            )
        client.get("http://api.example.com/items")
        client.get("http://api.example.com/items")
    assert len(backend.origins) == 2
    assert resolver.calls == ["api.example.com", "api.example.com"]


def test_server_policy_defaults_to_https_443_and_http_requires_opt_in():
    from authmatrix.execution_scope import load_inventory_execution_policy

    policy = load_inventory_execution_policy({})
    assert policy.enabled is False
    assert policy.scheme == "https"
    assert policy.port == 443
    assert policy.allow_public_egress is False

    with pytest.raises(ValueError, match="HTTP port 80"):
        load_inventory_execution_policy(
            {
                "AUTHMATRIX_INVENTORY_SCHEME": "http",
                "AUTHMATRIX_INVENTORY_PORT": "80",
                "AUTHMATRIX_INVENTORY_ALLOWED_PORTS": "80",
            }
        )


@pytest.mark.parametrize(
    ("address", "expected_sockaddr"),
    [
        ("8.8.8.8", ("8.8.8.8", 443)),
        ("2001:4860:4860::8888", ("2001:4860:4860::8888", 443, 0, 0)),
    ],
)
def test_real_pinned_backend_uses_numeric_socket_and_checks_peer(
    monkeypatch,
    address,
    expected_sockaddr,
):
    class FakeSocket:
        def __init__(self, *_args):
            self.connected = None
            self.closed = False

        def settimeout(self, _timeout):
            pass

        def setsockopt(self, *_args):
            pass

        def connect(self, address):
            self.connected = address

        def getpeername(self):
            return self.connected

        def getsockname(self):
            return ("192.0.2.1", 1234)

        def close(self):
            self.closed = True

    sockets = []

    def socket_factory(*args):
        sock = FakeSocket(*args)
        sockets.append(sock)
        return sock

    monkeypatch.setattr("authmatrix.transport.socket.socket", socket_factory)
    monkeypatch.setattr(
        "authmatrix.transport.socket.getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("A resolver fallback was attempted."),
    )
    backend = _PinnedNetworkBackend(
        ipaddress.ip_address(address),
        "api.example.com",
        443,
    )
    backend.connect_tcp("api.example.com", 443)
    assert sockets[0].connected == expected_sockaddr

    sockets.clear()

    mismatched_sockets = []

    class MismatchedPeerSocket(FakeSocket):
        def __init__(self):
            super().__init__()
            mismatched_sockets.append(self)

        def getpeername(self):
            return ("1.1.1.1", 443)

    monkeypatch.setattr(
        "authmatrix.transport.socket.socket",
        lambda *_args: MismatchedPeerSocket(),
    )
    with pytest.raises(ScopeError, match="pinned address"):
        backend.connect_tcp("api.example.com", 443)
    assert mismatched_sockets[0].closed is True


def test_tls_uses_original_hostname_and_verified_context():
    class FakeSocket:
        def settimeout(self, _timeout):
            pass

        def do_handshake(self):
            pass

        def close(self):
            pass

    class FakeContext:
        def __init__(self):
            self.server_hostname = None

        def wrap_socket(self, sock, *, server_hostname, do_handshake_on_connect):
            assert do_handshake_on_connect is False
            self.server_hostname = server_hostname
            return FakeSocket()

    context = ssl.create_default_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    fake_context = FakeContext()
    stream = _PinnedNetworkStream(FakeSocket(), "api.example.com")
    stream.start_tls(fake_context, "api.example.com", 1)
    assert fake_context.server_hostname == "api.example.com"
    with pytest.raises(ScopeError, match="TLS server name"):
        stream.start_tls(fake_context, "attacker.example", 1)


def _single_operation_config():
    examples = Path(__file__).parents[1] / "examples"
    config = load_config(examples / "policy.yaml")
    operation = config.operations[0]
    return replace(
        config,
        base_url="http://api.example.com:80",
        operations=(operation,),
        max_requests=25,
    )


def test_inventory_scanner_rejects_redirect_without_following(monkeypatch, tmp_path):
    from authmatrix import scanner

    monkeypatch.setattr(scanner, "_auth_for", lambda _identity: ({}, None))
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(
        monkeypatch,
        response=(
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n"
            b"Location: http://attacker.example/\r\n\r\n"
        ),
    )
    transport = _transport(store, resolver)

    with pytest.raises(ScopeError, match="redirects are never followed"):
        run_inventory_authorization_tests(_single_operation_config(), transport)
    assert len(backend.origins) == 1
    assert resolver.calls == ["api.example.com"]


def test_inventory_scanner_does_not_retry_or_fall_back_to_default_transport(
    monkeypatch, tmp_path
):
    from authmatrix import scanner

    monkeypatch.setattr(scanner, "_auth_for", lambda _identity: ({}, None))
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    attempts = []

    class FailingBackend:
        def __init__(self, *_args):
            pass

        def connect_tcp(self, host, port, **_kwargs):
            attempts.append((host, port))
            raise httpcore.ConnectError("test connection failure")

    monkeypatch.setattr(
        "authmatrix.transport._PinnedNetworkBackend",
        lambda *args: FailingBackend(*args),
    )
    transport = _transport(store, resolver)
    with pytest.raises(ScanError, match="Request failed"):
        run_inventory_authorization_tests(_single_operation_config(), transport)
    assert attempts == [("api.example.com", 80)]


def test_inventory_scanner_preserves_request_and_response_limits(monkeypatch, tmp_path):
    from authmatrix import scanner

    monkeypatch.setattr(scanner, "_auth_for", lambda _identity: ({}, None))
    store = _store(tmp_path)
    resolver = FakeResolver(["8.8.8.8"])
    backend = _install_fake_backend(monkeypatch)
    transport = _transport(store, resolver)

    with pytest.raises(ScanError, match="exceeding scope.max_requests"):
        run_inventory_authorization_tests(
            replace(_single_operation_config(), max_requests=1),
            transport,
        )
    assert resolver.calls == []
    assert backend.origins == []

    with pytest.raises(ScanError, match="max_response_bytes"):
        run_inventory_authorization_tests(
            replace(_single_operation_config(), max_response_bytes=1),
            transport,
        )
    assert backend.origins == [("api.example.com", 80)]
