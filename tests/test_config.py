from __future__ import annotations

from pathlib import Path

import pytest

from authmatrix.config import MAX_POLICY_BYTES, load_config, validate_scope
from authmatrix.errors import ConfigurationError, ScopeError


def test_loads_policy_at_size_limit(config_path: Path, tmp_path: Path) -> None:
    content = config_path.read_bytes()
    assert len(content) <= MAX_POLICY_BYTES
    path = tmp_path / "policy.yaml"
    path.write_bytes(content + b"\n" * (MAX_POLICY_BYTES - len(content)))

    config = load_config(path)

    assert len(config.operations) == 2
    assert config.source == path.resolve()


def test_rejects_oversized_policy(config_path: Path, tmp_path: Path) -> None:
    content = config_path.read_bytes()
    path = tmp_path / "policy.yaml"
    path.write_bytes(content + b"\n" * (MAX_POLICY_BYTES + 1 - len(content)))

    with pytest.raises(ConfigurationError, match="1 MiB size limit"):
        load_config(path)


def test_rejects_policy_that_grows_after_size_check(
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    from types import SimpleNamespace

    import authmatrix.config as config_module

    content = config_path.read_bytes()
    path = tmp_path / "policy.yaml"
    path.write_bytes(content + b"\n" * (MAX_POLICY_BYTES + 1 - len(content)))
    actual_fstat = os.fstat
    monkeypatch.setattr(
        config_module.os,
        "fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=actual_fstat(descriptor).st_mode,
            st_size=0,
        ),
    )

    with pytest.raises(ConfigurationError, match="1 MiB size limit"):
        load_config(path)


def test_rejects_symlink_policy(config_path: Path, tmp_path: Path) -> None:
    import os

    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("O_NOFOLLOW is not supported on this platform.")

    target = tmp_path / "target.yaml"
    target.write_bytes(config_path.read_bytes())
    link = tmp_path / "policy.yaml"
    link.symlink_to(target)

    with pytest.raises(ConfigurationError, match="Cannot access"):
        load_config(link)


def test_rejects_fifo_policy_without_blocking(tmp_path: Path) -> None:
    import os
    import stat

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is not supported on this platform.")

    path = tmp_path / "policy.yaml"
    os.mkfifo(path)

    with pytest.raises(ConfigurationError, match="regular file"):
        load_config(path)
    assert stat.S_ISFIFO(path.stat().st_mode)


def test_rejects_policy_with_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_bytes(b"\xff")

    with pytest.raises(ConfigurationError, match="valid UTF-8"):
        load_config(path)


def test_rejects_malformed_policy_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: [", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_config(path)


def test_example_policy_loads(config_path: Path) -> None:
    config = load_config(config_path)
    assert len(config.identities) == 3
    assert len(config.resources["items"].ids) == 2
    assert len(config.operations) == 2
    assert {
        name: identity.auth.token_env
        for name, identity in config.identities.items()
    } == {
        "alice": "AUTHMATRIX_ALICE_TOKEN",
        "bob": "AUTHMATRIX_BOB_TOKEN",
        "admin": "AUTHMATRIX_ADMIN_TOKEN",
    }


@pytest.mark.parametrize(
    "url,hosts",
    [
        ("https://example.com", ("example.com",)),
        ("http://127.0.0.1/path", ("127.0.0.1",)),
        ("http://127.0.0.1/?q=x", ("127.0.0.1",)),
        ("http://user:pass@127.0.0.1", ("127.0.0.1",)),
        ("http://127.0.0.1", ("localhost",)),
    ],
)
def test_rejects_out_of_scope_target(url: str, hosts: tuple[str, ...]) -> None:
    with pytest.raises(ScopeError):
        validate_scope(url, hosts)


def test_requires_explicit_authorization(config_path: Path, tmp_path: Path) -> None:
    contents = config_path.read_text(encoding="utf-8").replace(
        "authorized: true", "authorized: false"
    )
    path = tmp_path / "policy.yaml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ScopeError, match="explicitly authorize"):
        load_config(path)


def test_requires_decisions_for_every_identity(
    config_path: Path, tmp_path: Path
) -> None:
    contents = config_path.read_text(encoding="utf-8").replace("      bob: deny\n", "")
    path = tmp_path / "policy.yaml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="cover every identity"):
        load_config(path)


def test_rejects_destructive_method_by_default(
    config_path: Path, tmp_path: Path
) -> None:
    contents = config_path.read_text(encoding="utf-8").replace(
        "method: GET\n    path: /admin/reports",
        "method: DELETE\n    path: /admin/reports",
    )
    path = tmp_path / "policy.yaml"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ScopeError, match="destructive"):
        load_config(path)


def test_auth_environment_check_does_not_expose_values(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AUTHMATRIX_ALICE_TOKEN", raising=False)
    monkeypatch.delenv("AUTHMATRIX_BOB_TOKEN", raising=False)
    monkeypatch.delenv("AUTHMATRIX_ADMIN_TOKEN", raising=False)

    with pytest.raises(ConfigurationError, match="AUTHMATRIX_ALICE_TOKEN"):
        load_config(config_path, check_auth_env=True)


def test_auth_environment_check_accepts_configured_variables(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AUTHMATRIX_ALICE_TOKEN", "test-alice-token")
    monkeypatch.setenv("AUTHMATRIX_BOB_TOKEN", "test-bob-token")
    monkeypatch.setenv("AUTHMATRIX_ADMIN_TOKEN", "test-admin-token")

    config = load_config(config_path, check_auth_env=True)

    assert len(config.identities) == 3


def test_rejects_empty_bola_path_placeholder(
    config_path: Path, tmp_path: Path
) -> None:
    contents = config_path.read_text(encoding="utf-8").replace(
        "/items/{item_id}", "/items/{}"
    )
    path = tmp_path / "policy.yaml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="placeholder"):
        load_config(path)


def test_bola_response_id_path_defaults_to_top_level_id(
    config_path: Path,
) -> None:
    config = load_config(config_path)

    operation = next(op for op in config.operations if op.category == "BOLA")

    assert operation.response_id_path == "id"


def test_accepts_nested_bola_response_id_path(
    config_path: Path, tmp_path: Path
) -> None:
    import yaml

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["operations"][0]["response_id_path"] = "data.order.id"

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    config = load_config(path)
    operation = next(op for op in config.operations if op.category == "BOLA")

    assert operation.response_id_path == "data.order.id"


@pytest.mark.parametrize(
    "invalid_path",
    [
        "",
        ".id",
        "data.",
        "data..id",
        "data.orders[-1].id",
        "data.orders[].id",
        "data.orders[abc].id",
        "data.orders[0]id",
        "data.orders[*",
        "data.orders[**].id",
        "data.orders[*]id",
        "data.orders[*].",
    ],
)
def test_rejects_invalid_bola_response_id_path(
    config_path: Path, tmp_path: Path, invalid_path: str
) -> None:
    import yaml

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["operations"][0]["response_id_path"] = invalid_path

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="response_id_path"):
        load_config(path)


@pytest.mark.parametrize(
    "valid_path",
    [
        "id",
        "data.order.id",
        "data.orders[0].id",
        "data.orders[12].id",
        "data.orders[0].items[2].id",
        "data.orders[*].id",
        "data.data.orders[*].items[*].id",
    ],
)
def test_accepts_array_index_bola_response_id_paths(
    config_path: Path, tmp_path: Path, valid_path: str
) -> None:
    import yaml

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["operations"][0]["response_id_path"] = valid_path

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    config = load_config(path)
    operation = next(op for op in config.operations if op.category == "BOLA")

    assert operation.response_id_path == valid_path


def test_rejects_response_id_path_on_bfla_operation(
    config_path: Path, tmp_path: Path
) -> None:
    import yaml

    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["operations"][1]["response_id_path"] = "data.id"

    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="response_id_path"):
        load_config(path)
