from pathlib import Path

import pytest

from authmatrix.errors import ConfigurationError, OpenAPIError
from authmatrix.openapi import parse_openapi
from authmatrix.web.services import (
    configured_openapi_max_bytes,
    list_openapi_mapping_files,
    load_openapi_inventory,
    resolve_openapi_mapping_path,
    resolve_openapi_path,
    resolve_policy_path,
)


def test_resolves_policy_inside_configured_directory(tmp_path: Path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.yaml"
    policy_file.write_text("scope: {}", encoding="utf-8")

    result = resolve_policy_path("policy.yaml", policy_dir)

    assert result == policy_file.resolve()


@pytest.mark.parametrize(
    "policy_path",
    [
        "../outside.yaml",
        "/tmp/outside.yaml",
        "missing.yaml",
        "notes.txt",
        "",
    ],
)
def test_rejects_invalid_policy_paths(tmp_path: Path, policy_path: str):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()

    with pytest.raises(ConfigurationError):
        resolve_policy_path(policy_path, policy_dir)


def test_rejects_symlink_escape(tmp_path: Path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()

    outside_file = tmp_path / "outside.yaml"
    outside_file.write_text("scope: {}", encoding="utf-8")

    link = policy_dir / "outside.yaml"
    link.symlink_to(outside_file)

    with pytest.raises(ConfigurationError):
        resolve_policy_path("outside.yaml", policy_dir)


def test_openapi_spec_size_is_checked_before_bounded_read(
    tmp_path: Path,
    monkeypatch,
):
    import authmatrix.openapi as openapi_module

    spec = tmp_path / "large.yaml"
    spec.write_text("x" * 2049, encoding="utf-8")
    monkeypatch.setattr(
        openapi_module.yaml,
        "safe_load",
        lambda value: pytest.fail("Oversized document must not be parsed."),
    )

    with pytest.raises(OpenAPIError, match="exceeds the 2048-byte size limit"):
        parse_openapi(spec, max_bytes=2048)


def test_openapi_size_limit_rejects_oversized_inventory_and_lists(tmp_path: Path):
    from authmatrix.web.services import list_openapi_files

    spec = tmp_path / "large.yaml"
    spec.write_text("openapi: 3.0.3\n" + (" " * 2048), encoding="utf-8")

    assert list_openapi_files(tmp_path, max_bytes=32) == []
    with pytest.raises(OpenAPIError, match="size limit"):
        load_openapi_inventory("large.yaml", tmp_path, max_bytes=32)


def test_openapi_malformed_document_is_rejected(tmp_path: Path):
    spec = tmp_path / "broken.yaml"
    spec.write_text("openapi: [", encoding="utf-8")

    with pytest.raises(OpenAPIError, match="not valid JSON or YAML"):
        load_openapi_inventory("broken.yaml", tmp_path)


@pytest.mark.parametrize(
    "spec_path",
    ["../outside.yaml", "/tmp/outside.yaml", "nested/spec.yaml", "", "a\x00.yaml"],
)
def test_openapi_path_escape_and_invalid_names_are_rejected(
    tmp_path: Path,
    spec_path: str,
):
    with pytest.raises(OpenAPIError, match="local document filename"):
        resolve_openapi_path(spec_path, tmp_path)


def test_openapi_symlink_escape_is_rejected(tmp_path: Path):
    openapi_dir = tmp_path / "openapi"
    openapi_dir.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("openapi: 3.0.3", encoding="utf-8")
    symlink = openapi_dir / "spec.yaml"
    try:
        symlink.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not supported.")

    with pytest.raises(OpenAPIError, match="unavailable"):
        resolve_openapi_path("spec.yaml", openapi_dir)


def test_openapi_mapping_paths_are_local_yaml_filenames(tmp_path: Path):
    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    mapping = mapping_dir / "scan.mapping.yaml"
    mapping.write_text("operations: {}\n", encoding="utf-8")

    assert resolve_openapi_mapping_path(mapping.name, mapping_dir) == mapping.resolve()
    for path in ("../outside.yaml", "/tmp/outside.yaml", "nested/map.yaml", ""):
        with pytest.raises(ConfigurationError):
            resolve_openapi_mapping_path(path, mapping_dir)


def test_openapi_mapping_listing_omits_symlink_escapes(tmp_path: Path):
    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    outside = tmp_path / "outside.mapping.yaml"
    outside.write_text("operations: {}\n", encoding="utf-8")
    try:
        (mapping_dir / outside.name).symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not supported.")

    assert list_openapi_mapping_files(mapping_dir) == []


@pytest.mark.parametrize("value", [0, -1, 16 * 1024 * 1024 + 1, True])
def test_openapi_size_setting_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        configured_openapi_max_bytes(value)


def test_openapi_size_setting_rejects_invalid_environment(monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_OPENAPI_MAX_BYTES", "not-a-number")

    with pytest.raises(ValueError, match="must be an integer"):
        configured_openapi_max_bytes()


def test_openapi_size_setting_reads_environment(monkeypatch):
    monkeypatch.setenv("AUTHMATRIX_OPENAPI_MAX_BYTES", "4096")

    assert configured_openapi_max_bytes() == 4096
