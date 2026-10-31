from __future__ import annotations

from pathlib import Path

import pytest

from authmatrix.config import load_config, validate_scope
from authmatrix.errors import ConfigurationError, ScopeError


def test_example_policy_loads(config_path: Path) -> None:
    config = load_config(config_path)
    assert len(config.identities) == 3
    assert len(config.resources["items"].ids) == 2
    assert len(config.operations) == 2


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
