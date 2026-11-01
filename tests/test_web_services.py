from pathlib import Path

import pytest

from authmatrix.errors import ConfigurationError
from authmatrix.web.services import resolve_policy_path


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
