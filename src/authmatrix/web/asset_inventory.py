"""Canonical asset validation and authorization-aware scope evaluation."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, date, datetime
from typing import Any

ASSET_TYPES = frozenset(
    {
        "domain",
        "subdomain",
        "hostname",
        "ipv4",
        "ipv6",
        "ipv4_cidr",
        "ipv6_cidr",
    }
)
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_VALUE_LENGTH = 253


class AssetValidationError(ValueError):
    """Raised when an asset value is malformed or ambiguous."""


def canonicalize_asset_value(asset_type: str, value: str) -> str:
    """Validate an explicit host/address/network without performing I/O."""
    if asset_type not in ASSET_TYPES:
        raise AssetValidationError("Unsupported asset type.")
    if not value or len(value) > _MAX_VALUE_LENGTH or value != value.strip():
        raise AssetValidationError("Asset value is empty, oversized, or padded.")
    if "%" in value or any(
        ord(character) <= 32 or ord(character) == 127 for character in value
    ):
        raise AssetValidationError("Asset value contains invalid characters.")

    if asset_type in {"domain", "subdomain", "hostname"}:
        if any(character in value for character in "/\\@?#%:"):
            raise AssetValidationError("Enter a hostname, not a URL or address.")
        name = value[:-1] if value.endswith(".") else value
        if not name or len(name) > _MAX_VALUE_LENGTH:
            raise AssetValidationError("Hostname length is invalid.")
        try:
            ascii_name = name.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise AssetValidationError("Hostname is not valid IDNA.") from exc
        labels = ascii_name.split(".")
        if (
            len(labels) < 2
            or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
            or len(ascii_name) > _MAX_VALUE_LENGTH
        ):
            raise AssetValidationError("Enter a valid fully qualified hostname.")
        return ascii_name

    if "/" in value:
        if asset_type not in {"ipv4_cidr", "ipv6_cidr"}:
            raise AssetValidationError("CIDR notation requires a network asset type.")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise AssetValidationError("Enter a valid canonical CIDR network.") from exc
        expected_version = 4 if asset_type == "ipv4_cidr" else 6
        if network.version != expected_version:
            raise AssetValidationError("Network version does not match asset type.")
        if network.version == 6 and network.network_address.ipv4_mapped is not None:
            raise AssetValidationError("IPv4-mapped IPv6 networks are ambiguous.")
        return str(network)

    if asset_type in {"ipv4_cidr", "ipv6_cidr"}:
        raise AssetValidationError("A CIDR network prefix is required.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise AssetValidationError("Enter a valid IP address.") from exc
    expected_version = 4 if asset_type == "ipv4" else 6
    if address.version != expected_version:
        raise AssetValidationError("Address version does not match asset type.")
    if address.version == 6 and address.ipv4_mapped is not None:
        raise AssetValidationError("IPv4-mapped IPv6 addresses are ambiguous.")
    return str(address)


def authorization_state(asset: dict[str, Any], today: date | None = None) -> str:
    """Return the persisted state with time-based expiry applied."""
    state = asset["authorization_status"]
    if state == "authorized":
        if (
            not asset.get("authorization_confirmed")
            or not asset.get("authorization_reference")
        ):
            return "unverified"
        today = today or datetime.now(UTC).date()
        if asset.get("authorization_expires_at") and date.fromisoformat(
            asset["authorization_expires_at"]
        ) < today:
            return "expired"
    return state


def authorization_eligibility(
    asset: dict[str, Any],
    today: date | None = None,
) -> tuple[bool, str]:
    state = authorization_state(asset, today)
    if not asset["active"]:
        return False, "inactive"
    if state != "authorized":
        return False, state
    today = today or datetime.now(UTC).date()
    start = asset.get("authorization_starts_at")
    if start and date.fromisoformat(start) > today:
        return False, "not_started"
    return True, "authorized"


def _asset_matches_target(asset: dict[str, Any], target: dict[str, str]) -> bool:
    value = asset["canonical_value"]
    target_value = target["canonical_value"]
    asset_type = asset["asset_type"]
    target_type = target["asset_type"]
    if asset_type in {"domain", "subdomain", "hostname"}:
        if target_type not in {"domain", "subdomain", "hostname"}:
            return False
        return target_value == value or target_value.endswith(f".{value}")

    if asset_type in {"ipv4", "ipv6"}:
        return target_type == asset_type and target_value == value

    if asset_type in {"ipv4_cidr", "ipv6_cidr"}:
        if target_type in {"ipv4_cidr", "ipv6_cidr"}:
            try:
                scope_network = ipaddress.ip_network(value)
                target_network = ipaddress.ip_network(target_value)
                if scope_network.version != target_network.version:
                    return False
                return target_network.subnet_of(scope_network)
            except ValueError:
                return False
        if target_type not in {"ipv4", "ipv6"}:
            return False
        try:
            return ipaddress.ip_address(target_value) in ipaddress.ip_network(value)
        except ValueError:
            return False
    return False


def _exclusion_overlaps_target(
    asset: dict[str, Any],
    target: dict[str, str],
) -> bool:
    if _asset_matches_target(asset, target):
        return True
    asset_type = asset["asset_type"]
    target_type = target["asset_type"]
    if asset_type in {"domain", "subdomain", "hostname"} and target_type in {
        "domain",
        "subdomain",
        "hostname",
    }:
        asset_value = asset["canonical_value"]
        target_value = target["canonical_value"]
        return asset_value.endswith(f".{target_value}")
    if asset_type in {"ipv4_cidr", "ipv6_cidr"} and target_type in {
        "ipv4_cidr",
        "ipv6_cidr",
    }:
        try:
            exclusion = ipaddress.ip_network(asset["canonical_value"])
            proposed = ipaddress.ip_network(target["canonical_value"])
            return (
                exclusion.version == proposed.version
                and exclusion.overlaps(proposed)
            )
        except ValueError:
            return False
    if asset_type in {"ipv4", "ipv6"} and target_type in {
        "ipv4_cidr",
        "ipv6_cidr",
    }:
        try:
            address = ipaddress.ip_address(asset["canonical_value"])
            proposed = ipaddress.ip_network(target["canonical_value"])
            return address.version == proposed.version and address in proposed
        except ValueError:
            return False
    return False


def evaluate_target(
    assets: list[dict[str, Any]],
    scope_entries: list[dict[str, Any]],
    target_type: str,
    target_value: str,
) -> dict[str, Any]:
    """Check a proposed literal asset against includes, exclusions and consent."""
    canonical = canonicalize_asset_value(target_type, target_value)
    target = {"asset_type": target_type, "canonical_value": canonical}
    by_id = {asset["asset_id"]: asset for asset in assets}
    exclusions = [
        entry
        for entry in scope_entries
        if entry["direction"] == "exclude" and entry["asset_id"] in by_id
    ]
    excluded_by = [
        by_id[entry["asset_id"]]
        for entry in exclusions
        if _exclusion_overlaps_target(by_id[entry["asset_id"]], target)
    ]
    if excluded_by:
        return {
            "target_type": target_type,
            "target": canonical,
            "eligible": False,
            "reason": "explicitly_excluded",
            "matched_assets": [],
            "excluded_by": [
                {
                    "asset_id": asset["asset_id"],
                    "name": asset["name"],
                    "value": asset["canonical_value"],
                }
                for asset in excluded_by
            ],
        }

    matching = [
        (by_id[entry["asset_id"]], entry)
        for entry in scope_entries
        if entry["direction"] == "include" and entry["asset_id"] in by_id
        and _asset_matches_target(by_id[entry["asset_id"]], target)
    ]
    eligible = [
        asset for asset, _entry in matching
        if authorization_eligibility(asset)[0]
    ]
    return {
        "target_type": target_type,
        "target": canonical,
        "eligible": bool(eligible),
        "reason": "included_and_authorized" if eligible else (
            "not_included" if not matching else "authorization_ineligible"
        ),
        "matched_assets": [
            {
                "asset_id": asset["asset_id"],
                "name": asset["name"],
                "value": asset["canonical_value"],
                "authorization_status": authorization_state(asset),
                "eligibility_reason": authorization_eligibility(asset)[1],
            }
            for asset, _entry in matching
        ],
        "excluded_by": [],
    }


def effective_scope(
    assets: list[dict[str, Any]],
    scope_entries: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Describe all configured entries and their current authorization state."""
    by_id = {asset["asset_id"]: asset for asset in assets}
    result: dict[str, list[dict[str, Any]]] = {"included": [], "excluded": []}
    for entry in scope_entries:
        asset = by_id.get(entry["asset_id"])
        if asset is None:
            continue
        eligible, reason = authorization_eligibility(asset)
        result["included" if entry["direction"] == "include" else "excluded"].append(
            {
                "asset_id": asset["asset_id"],
                "name": asset["name"],
                "asset_type": asset["asset_type"],
                "value": asset["canonical_value"],
                "authorization_status": authorization_state(asset),
                "eligible": eligible if entry["direction"] == "include" else False,
                "eligibility_reason": reason,
                "active": bool(asset["active"]),
            }
        )
    return result
