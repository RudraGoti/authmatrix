"""Address safety and bounded DNS resolution for inventory-scoped execution."""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from os import environ
from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from authmatrix.web.asset_inventory import canonicalize_asset_value

MAX_DNS_ANSWERS = 32
MAX_CNAME_DEPTH = 8
DNS_TIMEOUT_SECONDS = 3.0
MAX_DNS_NAMESERVERS = 4

# IANA protocol, shared, documentation, transition, benchmarking, and reserved
# ranges are kept explicit so behavior does not depend on one Python release.
_IPV4_SPECIAL = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
    )
)
_IPV6_SPECIAL = tuple(
    ipaddress.ip_network(value)
    for value in (
        "::/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
    )
)
_IPV6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


class AddressClass(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    SPECIAL = "special"


class ResolutionError(ValueError):
    """Raised when DNS data is incomplete, malformed, or over a configured limit."""


@dataclass(frozen=True)
class ResolvedAddressSet:
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    complete: bool = True


class Resolver(Protocol):
    def resolve(self, hostname: str) -> ResolvedAddressSet: ...


@dataclass(frozen=True)
class InventoryExecutionPolicy:
    enabled: bool
    scheme: str
    port: int
    allowed_ports: frozenset[int]
    allow_http: bool
    allow_public_egress: bool
    allowed_restricted_classes: frozenset[AddressClass]
    dns_timeout_seconds: float = DNS_TIMEOUT_SECONDS
    dns_nameservers: tuple[str, ...] | None = None
    dns_max_cname_depth: int = MAX_CNAME_DEPTH
    dns_max_answers: int = MAX_DNS_ANSWERS
    authorization_lock_timeout: float = 5.0

    def __post_init__(self) -> None:
        if self.scheme not in {"http", "https"}:
            raise ValueError("Inventory execution supports HTTP and HTTPS only.")
        if not 1 <= self.port <= 65535 or self.port not in self.allowed_ports:
            raise ValueError("Inventory execution port is not allowlisted.")
        if self.scheme == "http" and (not self.allow_http or self.port != 80):
            raise ValueError("HTTP port 80 requires explicit server-side opt-in.")
        if not self.allowed_ports:
            raise ValueError("Inventory execution requires an explicit port allowlist.")
        if not 0 < self.authorization_lock_timeout <= 5:
            raise ValueError("Authorization lock timeout must be at most 5 seconds.")


class AddressPolicyError(ValueError):
    """Raised when a resolved address set exceeds server-side scope policy."""


def classify_address(
    value: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> AddressClass:
    """Classify an address using explicit special-purpose ranges and stdlib flags."""
    address = ipaddress.ip_address(value)
    if address.is_unspecified:
        return AddressClass.UNSPECIFIED
    if address.is_multicast:
        return AddressClass.MULTICAST
    if address.is_loopback:
        return AddressClass.LOOPBACK
    if address.is_link_local:
        return AddressClass.LINK_LOCAL
    if address.version == 4:
        if any(address in network for network in _IPV4_SPECIAL):
            return AddressClass.SPECIAL
        if address.is_private or address.is_reserved or not address.is_global:
            return AddressClass.PRIVATE if address.is_private else AddressClass.SPECIAL
        return AddressClass.PUBLIC

    if address in ipaddress.ip_network("fc00::/7"):
        return AddressClass.PRIVATE
    if any(address in network for network in _IPV6_SPECIAL):
        return AddressClass.SPECIAL
    if address not in _IPV6_GLOBAL_UNICAST:
        return AddressClass.SPECIAL
    if address.is_private or address.is_reserved or not address.is_global:
        return AddressClass.SPECIAL
    return AddressClass.PUBLIC


def validate_address_set(
    result: ResolvedAddressSet,
    *,
    allow_public_egress: bool,
    allowed_restricted_classes: frozenset[AddressClass],
    evaluate_ip_scope: Callable[
        [ipaddress.IPv4Address | ipaddress.IPv6Address], tuple[bool, bool]
    ],
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Validate every DNS answer before allowing any target connection.

    The callback returns ``(included_and_authorized, explicitly_excluded)``.
    Public addresses need no separate IP inclusion, but exclusions still apply.
    """
    if not result.complete or not result.addresses:
        raise AddressPolicyError("DNS answer set is incomplete or empty.")
    if len(result.addresses) > MAX_DNS_ANSWERS:
        raise AddressPolicyError("DNS answer set exceeded its size limit.")

    try:
        normalized = tuple(ipaddress.ip_address(value) for value in result.addresses)
    except ValueError as exc:
        raise AddressPolicyError(
            "DNS answer set contains a malformed address."
        ) from exc
    validated = tuple(dict.fromkeys(normalized))
    for address in validated:
        address_class = classify_address(address)
        included, excluded = evaluate_ip_scope(address)
        if excluded:
            raise AddressPolicyError("A DNS address is explicitly excluded.")
        if address_class == AddressClass.PUBLIC:
            if not allow_public_egress:
                raise AddressPolicyError("Public egress is disabled by server policy.")
            continue
        if address_class in {AddressClass.MULTICAST, AddressClass.UNSPECIFIED}:
            raise AddressPolicyError("DNS returned a non-connectable address.")
        if address_class not in allowed_restricted_classes or not included:
            raise AddressPolicyError(
                "A restricted DNS address lacks explicit address authorization."
            )
    return validated


def load_inventory_execution_policy(environment=None) -> InventoryExecutionPolicy:
    """Load the opt-in GUI execution policy exclusively from server environment."""
    settings = environ if environment is None else environment

    def boolean(name: str, default: bool = False) -> bool:
        value = settings.get(name)
        if value is None:
            return default
        normalized = value.strip().lower()
        if normalized not in {"true", "false"}:
            raise ValueError(f"{name} must be 'true' or 'false'.")
        return normalized == "true"

    try:
        allowed_ports = frozenset(
            int(part.strip())
            for part in settings.get("AUTHMATRIX_INVENTORY_ALLOWED_PORTS", "443").split(
                ","
            )
        )
        port = int(settings.get("AUTHMATRIX_INVENTORY_PORT", "443"))
        dns_timeout = float(settings.get("AUTHMATRIX_DNS_TIMEOUT_SECONDS", "3"))
        lock_timeout = float(
            settings.get("AUTHMATRIX_AUTHORIZATION_LOCK_TIMEOUT_SECONDS", "5")
        )
    except ValueError as exc:
        raise ValueError("Inventory execution numeric settings are invalid.") from exc

    if any(not 1 <= value <= 65535 for value in allowed_ports):
        raise ValueError("Inventory execution ports must be between 1 and 65535.")
    if not 0 < dns_timeout <= 10:
        raise ValueError("DNS timeout must be between 0 and 10 seconds.")
    if not 0 < lock_timeout <= 5:
        raise ValueError("Authorization lock timeout must be at most 5 seconds.")

    allow_http = boolean("AUTHMATRIX_INVENTORY_ALLOW_HTTP")
    scheme = settings.get("AUTHMATRIX_INVENTORY_SCHEME", "https").strip().lower()
    if scheme not in {"http", "https"}:
        raise ValueError("AUTHMATRIX_INVENTORY_SCHEME must be http or https.")
    nameserver_setting = settings.get("AUTHMATRIX_DNS_NAMESERVERS")
    if nameserver_setting is None:
        nameservers = None
    else:
        nameserver_values = tuple(
            item.strip() for item in nameserver_setting.split(",") if item.strip()
        )
        if not 1 <= len(nameserver_values) <= MAX_DNS_NAMESERVERS:
            raise ValueError("Configure between 1 and 4 DNS nameservers.")
        try:
            nameservers = tuple(
                str(ipaddress.ip_address(item)) for item in nameserver_values
            )
        except ValueError as exc:
            raise ValueError("DNS nameservers must be numeric IP addresses.") from exc
    restricted_names = {
        part.strip()
        for part in settings.get(
            "AUTHMATRIX_INVENTORY_RESTRICTED_ADDRESS_CLASSES", ""
        ).split(",")
        if part.strip()
    }
    allowed_classes = {
        AddressClass.PRIVATE,
        AddressClass.LOOPBACK,
        AddressClass.LINK_LOCAL,
        AddressClass.SPECIAL,
    }
    try:
        restricted_classes = frozenset(
            AddressClass(value) for value in restricted_names
        )
    except ValueError as exc:
        raise ValueError("Restricted address class setting is invalid.") from exc
    if not restricted_classes.issubset(allowed_classes):
        raise ValueError("Multicast and unspecified addresses cannot be enabled.")

    return InventoryExecutionPolicy(
        enabled=boolean("AUTHMATRIX_INVENTORY_EXECUTION_ENABLED"),
        scheme=scheme,
        port=port,
        allowed_ports=allowed_ports,
        allow_http=allow_http,
        allow_public_egress=boolean("AUTHMATRIX_ALLOW_PUBLIC_EGRESS"),
        allowed_restricted_classes=restricted_classes,
        dns_timeout_seconds=dns_timeout,
        dns_nameservers=nameservers,
        authorization_lock_timeout=lock_timeout,
    )


class DnspythonResolver:
    """Resolve A/AAAA with bounded CNAME traversal and complete-answer checks."""

    def __init__(
        self,
        *,
        nameservers: tuple[str, ...] | None = None,
        timeout_seconds: float = DNS_TIMEOUT_SECONDS,
        max_cname_depth: int = MAX_CNAME_DEPTH,
        max_answers: int = MAX_DNS_ANSWERS,
    ) -> None:
        if not 0 < timeout_seconds <= 10:
            raise ValueError("DNS timeout must be between 0 and 10 seconds.")
        if not 1 <= max_cname_depth <= MAX_CNAME_DEPTH:
            raise ValueError("DNS CNAME depth is outside the supported bound.")
        if not 1 <= max_answers <= MAX_DNS_ANSWERS:
            raise ValueError("DNS answer limit is outside the supported bound.")

        if nameservers is None:
            configured = dns.resolver.Resolver(configure=True).nameservers
            nameservers = tuple(configured[:MAX_DNS_NAMESERVERS])
        if not nameservers or len(nameservers) > MAX_DNS_NAMESERVERS:
            raise ValueError("Configure between 1 and 4 DNS nameservers.")
        try:
            parsed_nameservers = tuple(
                str(ipaddress.ip_address(server)) for server in nameservers
            )
        except ValueError as exc:
            raise ValueError("DNS nameservers must be numeric IP addresses.") from exc

        self.nameservers = parsed_nameservers
        self.timeout_seconds = timeout_seconds
        self.max_cname_depth = max_cname_depth
        self.max_answers = max_answers

    def _query(
        self, name: str, record_type: int, deadline: float
    ) -> dns.message.Message:
        query = dns.message.make_query(name, record_type)
        last_error: Exception | None = None
        for nameserver in self.nameservers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                response = dns.query.udp(query, nameserver, timeout=remaining)
                if response.flags & dns.flags.TC:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    response = dns.query.tcp(query, nameserver, timeout=remaining)
                if response.flags & dns.flags.TC:
                    raise ResolutionError("DNS response remained truncated over TCP.")
                if response.id != query.id or not response.flags & dns.flags.QR:
                    raise ResolutionError("DNS response did not match its transaction.")
                if response.rcode() != dns.rcode.NOERROR:
                    raise ResolutionError("DNS returned a non-success response.")
                if (
                    len(response.question) != 1
                    or response.question[0].name.canonicalize()
                    != dns.name.from_text(name).canonicalize()
                    or response.question[0].rdtype != record_type
                ):
                    raise ResolutionError("DNS response did not match its query.")
                return response
            except ResolutionError:
                raise
            except (TimeoutError, dns.exception.DNSException, OSError) as exc:
                last_error = exc
        if last_error is None:
            raise ResolutionError("DNS resolution exceeded its time limit.")
        raise ResolutionError("DNS resolution failed.") from last_error

    def _resolve_type(
        self,
        hostname: str,
        record_type: int,
        deadline: float,
    ) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        current = dns.name.from_text(hostname).canonicalize()
        visited: set[dns.name.Name] = set()
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        depth = 0

        while True:
            if current in visited:
                raise ResolutionError("DNS CNAME loop detected.")
            visited.add(current)
            response = self._query(current.to_text(), record_type, deadline)
            cname_targets: dict[dns.name.Name, dns.name.Name] = {}
            records: dict[dns.name.Name, list[str]] = {}
            for rrset in response.answer:
                owner = rrset.name.canonicalize()
                if rrset.rdtype == dns.rdatatype.CNAME:
                    targets = set()
                    for record in rrset:
                        target = record.target.to_text().rstrip(".")
                        try:
                            canonical_target = canonicalize_asset_value(
                                "hostname", target
                            )
                        except ValueError as exc:
                            raise ResolutionError(
                                "DNS CNAME target is malformed."
                            ) from exc
                        targets.add(dns.name.from_text(canonical_target).canonicalize())
                    if len(targets) != 1:
                        raise ResolutionError("DNS CNAME record is malformed.")
                    target = targets.pop()
                    if owner in cname_targets and cname_targets[owner] != target:
                        raise ResolutionError(
                            "DNS owner has conflicting CNAME records."
                        )
                    cname_targets[owner] = target
                elif rrset.rdtype == record_type:
                    records.setdefault(owner, []).extend(
                        record.address for record in rrset
                    )
                elif rrset.rdtype not in {
                    dns.rdatatype.RRSIG,
                    dns.rdatatype.NSEC,
                    dns.rdatatype.NSEC3,
                    dns.rdatatype.OPT,
                }:
                    raise ResolutionError(
                        "DNS response contained an unexpected record."
                    )

            if any(
                owner not in {current, *cname_targets.values()} for owner in records
            ):
                raise ResolutionError(
                    "DNS response contained unrelated address records."
                )
            if current in cname_targets:
                if current in records:
                    raise ResolutionError(
                        "DNS owner has conflicting CNAME and address data."
                    )
                depth += 1
                if depth > self.max_cname_depth:
                    raise ResolutionError("DNS CNAME chain exceeded its depth limit.")
                current = cname_targets[current]
                continue

            for record in records.get(current, []):
                try:
                    address = ipaddress.ip_address(record)
                except ValueError as exc:
                    raise ResolutionError(
                        "DNS returned a malformed IP address."
                    ) from exc
                expected_version = 4 if record_type == dns.rdatatype.A else 6
                if address.version != expected_version:
                    raise ResolutionError(
                        "DNS address family did not match its record."
                    )
                addresses.append(address)
            return addresses

    def resolve(self, hostname: str) -> ResolvedAddressSet:
        canonical = canonicalize_asset_value("hostname", hostname)
        deadline = time.monotonic() + self.timeout_seconds
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for record_type in (dns.rdatatype.A, dns.rdatatype.AAAA):
            addresses.extend(self._resolve_type(canonical, record_type, deadline))
            if len(addresses) > self.max_answers:
                raise ResolutionError("DNS answer set exceeded its size limit.")
        unique = tuple(dict.fromkeys(addresses))
        if not unique:
            raise ResolutionError("DNS returned no A or AAAA addresses.")
        return ResolvedAddressSet(unique)
