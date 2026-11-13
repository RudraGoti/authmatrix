"""One-request HTTP transport gated by current inventory scope and pinned DNS."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Iterable, Iterator
from typing import Any

import httpcore
import httpx

from authmatrix.errors import ScopeError
from authmatrix.execution_scope import (
    AddressPolicyError,
    InventoryExecutionPolicy,
    ResolutionError,
    ResolvedAddressSet,
    Resolver,
    validate_address_set,
)
from authmatrix.web.asset_inventory import (
    authorization_eligibility,
    evaluate_target,
)
from authmatrix.web.storage import ScanStore

_HTTPCORE_ERROR_MAP = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
    (httpcore.ProtocolError, httpx.ProtocolError),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.TimeoutException, httpx.TimeoutException),
)


def _translate_httpcore_error(
    error: Exception,
    request: httpx.Request,
) -> Exception:
    for core_type, httpx_type in _HTTPCORE_ERROR_MAP:
        if isinstance(error, core_type):
            return httpx_type(str(error), request=request)
    return error


class _PinnedNetworkStream:
    def __init__(self, sock: socket.socket, expected_hostname: str) -> None:
        self._socket = sock
        self._expected_hostname = expected_hostname

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self._socket.settimeout(timeout)
        return self._socket.recv(max_bytes)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._socket.settimeout(timeout)
        self._socket.sendall(buffer)

    def close(self) -> None:
        self._socket.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> _PinnedNetworkStream:
        if (server_hostname or "").casefold() != self._expected_hostname.casefold():
            self.close()
            raise ScopeError("TLS server name did not match the authorized hostname.")
        try:
            self._socket.settimeout(timeout)
            self._socket = ssl_context.wrap_socket(
                self._socket,
                server_hostname=server_hostname,
                do_handshake_on_connect=False,
            )
            self._socket.settimeout(timeout)
            self._socket.do_handshake()
        except (OSError, ssl.SSLError):
            self.close()
            raise
        return self

    def get_extra_info(self, info: str) -> Any:
        if info == "socket":
            return self._socket
        if info == "client_addr":
            return self._socket.getsockname()
        if info == "server_addr":
            return self._socket.getpeername()
        if info == "ssl_object" and isinstance(self._socket, ssl.SSLSocket):
            return self._socket
        return None


class _PinnedNetworkBackend:
    def __init__(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        hostname: str,
        port: int,
    ) -> None:
        self._address = address
        self._hostname = hostname
        self._port = port

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> _PinnedNetworkStream:
        if host.casefold() != self._hostname.casefold() or port != self._port:
            raise ScopeError("HTTP connection origin changed after authorization.")
        family = socket.AF_INET6 if self._address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            if local_address is not None:
                local_ip = ipaddress.ip_address(local_address)
                if local_ip.version != self._address.version:
                    raise ScopeError("Local bind address family is inconsistent.")
                local_sockaddr = (
                    (str(local_ip), 0, 0, 0)
                    if local_ip.version == 6
                    else (str(local_ip), 0)
                )
                sock.bind(local_sockaddr)
            options = socket_options or ((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),)
            for level, option, value in options:
                sock.setsockopt(level, option, value)
            sock.settimeout(timeout)
            peer_sockaddr = (
                (str(self._address), port, 0, 0)
                if self._address.version == 6
                else (str(self._address), port)
            )
            sock.connect(peer_sockaddr)
            peer = ipaddress.ip_address(sock.getpeername()[0])
            if peer != self._address:
                raise ScopeError("Connected peer did not match the pinned address.")
            return _PinnedNetworkStream(sock, self._hostname)
        except ScopeError:
            sock.close()
            raise
        except TimeoutError as exc:
            sock.close()
            raise httpcore.ConnectTimeout("Pinned connection timed out.") from exc
        except OSError as exc:
            sock.close()
            raise httpcore.ConnectError("Pinned connection failed.") from exc
        except Exception:
            sock.close()
            raise


class _ResponseStream(httpx.SyncByteStream):
    def __init__(
        self,
        stream: Iterable[bytes],
        pool: httpcore.ConnectionPool,
        request: httpx.Request,
    ) -> None:
        self._stream = stream
        self._pool = pool
        self._request = request
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._stream
        except Exception as exc:
            translated = _translate_httpcore_error(exc, self._request)
            if translated is exc:
                raise
            raise translated from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._stream, "close", None)
        try:
            if close is not None:
                close()
        finally:
            self._pool.close()


class InventoryScopedTransport(httpx.BaseTransport):
    """Reauthorize and pin each HTTP request to one validated numeric address."""

    def __init__(
        self,
        store: ScanStore,
        resolver: Resolver,
        policy: InventoryExecutionPolicy,
        *,
        asset_id: str,
        asset_type: str,
        canonical_value: str,
    ) -> None:
        if not policy.enabled:
            raise ValueError("Inventory-scoped execution is disabled by server policy.")
        self._store = store
        self._resolver = resolver
        self._policy = policy
        self._asset_id = asset_id
        self._asset_type = asset_type
        self._canonical_value = canonical_value

    def _authorize_target(
        self,
        assets: list[dict[str, Any]],
        entries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        by_id = {asset["asset_id"]: asset for asset in assets}
        asset = by_id.get(self._asset_id)
        if (
            asset is None
            or asset["asset_type"] != self._asset_type
            or asset["canonical_value"] != self._canonical_value
            or asset["asset_type"]
            not in {"domain", "subdomain", "hostname", "ipv4", "ipv6"}
        ):
            raise ScopeError("Selected asset no longer matches the authorized target.")
        if not authorization_eligibility(asset)[0]:
            raise ScopeError("Selected asset is not currently authorized and active.")
        scope_result = evaluate_target(
            assets,
            entries,
            asset["asset_type"],
            asset["canonical_value"],
        )
        if not scope_result["eligible"]:
            raise ScopeError("Selected asset is outside the effective scope.")
        return asset

    def _address_decision(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        assets: list[dict[str, Any]],
        entries: list[dict[str, Any]],
    ) -> tuple[bool, bool]:
        asset_type = "ipv4" if address.version == 4 else "ipv6"
        result = evaluate_target(assets, entries, asset_type, str(address))
        return result["eligible"], result["reason"] == "explicitly_excluded"

    def _validate_addresses(
        self,
        result: ResolvedAddressSet,
        assets: list[dict[str, Any]],
        entries: list[dict[str, Any]],
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        try:
            return validate_address_set(
                result,
                allow_public_egress=self._policy.allow_public_egress,
                allowed_restricted_classes=self._policy.allowed_restricted_classes,
                evaluate_ip_scope=lambda address: self._address_decision(
                    address, assets, entries
                ),
            )
        except AddressPolicyError as exc:
            raise ScopeError(
                "Resolved addresses are outside the authorized address scope."
            ) from exc

    def _check_request_origin(self, request: httpx.Request) -> str:
        url = request.url
        default_port = 443 if url.scheme == "https" else 80
        actual_port = url.port or default_port
        if (
            url.scheme != self._policy.scheme
            or actual_port != self._policy.port
            or url.username
            or url.password
            or url.host.casefold() != self._canonical_value.casefold()
        ):
            raise ScopeError("Request origin differs from the authorized target.")
        expected_host = f"[{url.host}]" if ":" in url.host else url.host
        if actual_port != default_port:
            expected_host = f"{expected_host}:{actual_port}"
        host_header = request.headers.get("host")
        if host_header is None or host_header.casefold() != expected_host.casefold():
            raise ScopeError("HTTP Host authority differs from the authorized target.")
        return url.host

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        hostname = self._check_request_origin(request)

        # Reject before DNS when the current asset or hostname scope is ineligible.
        assets, entries = self._store.authorization_snapshot()
        asset = self._authorize_target(assets, entries)
        if asset["asset_type"] in {"ipv4", "ipv6"}:
            resolution = ResolvedAddressSet(
                (ipaddress.ip_address(asset["canonical_value"]),)
            )
        else:
            try:
                resolution = self._resolver.resolve(hostname)
            except ResolutionError as exc:
                raise ScopeError("DNS resolution could not be validated.") from exc
        addresses = self._validate_addresses(resolution, assets, entries)
        pinned_address = addresses[0]

        pool: httpcore.ConnectionPool | None = None
        try:
            with self._store.locked_authorization_snapshot(
                timeout=self._policy.authorization_lock_timeout
            ) as (fresh_assets, fresh_entries):
                fresh_asset = self._authorize_target(fresh_assets, fresh_entries)
                if fresh_asset["asset_type"] in {"ipv4", "ipv6"}:
                    fresh_resolution = ResolvedAddressSet(
                        (ipaddress.ip_address(fresh_asset["canonical_value"]),)
                    )
                else:
                    fresh_resolution = resolution
                fresh_addresses = self._validate_addresses(
                    fresh_resolution,
                    fresh_assets,
                    fresh_entries,
                )
                if pinned_address not in fresh_addresses:
                    raise ScopeError("Pinned address is no longer in authorized scope.")

                backend = _PinnedNetworkBackend(
                    pinned_address,
                    hostname,
                    self._policy.port,
                )
                pool = httpcore.ConnectionPool(
                    ssl_context=ssl.create_default_context(),
                    max_connections=1,
                    max_keepalive_connections=0,
                    http1=True,
                    http2=False,
                    retries=0,
                    network_backend=backend,
                )
                core_request = httpcore.Request(
                    method=request.method,
                    url=httpcore.URL(
                        scheme=request.url.raw_scheme,
                        host=request.url.raw_host,
                        port=request.url.port,
                        target=request.url.raw_path,
                    ),
                    headers=request.headers.raw,
                    content=request.stream,
                    extensions=request.extensions,
                )
                response = pool.handle_request(core_request)
        except httpcore.NetworkError as exc:
            if pool is not None:
                pool.close()
            raise _translate_httpcore_error(exc, request) from exc
        except httpcore.TimeoutException as exc:
            if pool is not None:
                pool.close()
            raise _translate_httpcore_error(exc, request) from exc
        except httpcore.ProtocolError as exc:
            if pool is not None:
                pool.close()
            raise _translate_httpcore_error(exc, request) from exc
        except Exception:
            if pool is not None:
                pool.close()
            raise

        assert pool is not None
        try:
            return httpx.Response(
                status_code=response.status,
                headers=response.headers,
                stream=_ResponseStream(response.stream, pool, request),
                extensions=response.extensions,
                request=request,
            )
        except Exception:
            pool.close()
            raise

    def close(self) -> None:
        return None
