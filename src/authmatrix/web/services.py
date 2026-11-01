"""Service functions connecting the web API to the AuthMatrix engine."""

from pathlib import Path

from authmatrix.config import load_config
from authmatrix.errors import ConfigurationError
from authmatrix.scanner import run_authorization_tests


def resolve_policy_path(policy_path: str, policy_dir: Path) -> Path:
    """Resolve a policy file while preventing traversal and symlink escapes."""
    root = policy_dir.expanduser().resolve()

    if not policy_path or "\x00" in policy_path:
        raise ConfigurationError("Invalid policy path.")

    supplied = Path(policy_path)

    if supplied.is_absolute():
        raise ConfigurationError("Policy path must be relative.")

    if supplied.suffix.lower() not in {".yaml", ".yml"}:
        raise ConfigurationError("Only YAML policy files are supported.")

    try:
        resolved = (root / supplied).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError) as exc:
        raise ConfigurationError("Policy file is unavailable.") from exc

    if not resolved.is_file():
        raise ConfigurationError("Policy path must reference a file.")

    return resolved


def run_policy_scan(policy_path: str, policy_dir: Path) -> dict:
    """Load an approved policy and run the existing authorization scanner."""
    resolved_path = resolve_policy_path(policy_path, policy_dir)
    config = load_config(resolved_path)
    return run_authorization_tests(config)
