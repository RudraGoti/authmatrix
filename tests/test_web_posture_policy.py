import pytest

from authmatrix.execution_scope import (
    WebPosturePolicy,
    load_web_posture_policy,
)


def test_web_posture_is_disabled_by_default():
    policy = load_web_posture_policy({})

    assert policy.enabled is False
    assert policy.timeout_seconds == 5.0
    assert policy.max_header_bytes == 16384


def test_web_posture_accepts_explicit_server_configuration():
    policy = load_web_posture_policy(
        {
            "AUTHMATRIX_WEB_POSTURE_ENABLED": "true",
            "AUTHMATRIX_WEB_POSTURE_TIMEOUT_SECONDS": "4",
            "AUTHMATRIX_WEB_POSTURE_MAX_HEADER_BYTES": "8192",
            "AUTHMATRIX_WEB_POSTURE_MAX_HEADER_COUNT": "32",
            "AUTHMATRIX_WEB_POSTURE_MAX_COOKIE_HEADERS": "16",
        }
    )

    assert policy.enabled is True
    assert policy.timeout_seconds == 4.0
    assert policy.max_header_bytes == 8192
    assert policy.max_header_count == 32
    assert policy.max_cookie_headers == 16


@pytest.mark.parametrize(
    "environment",
    [
        {"AUTHMATRIX_WEB_POSTURE_ENABLED": "yes"},
        {"AUTHMATRIX_WEB_POSTURE_TIMEOUT_SECONDS": "0"},
        {"AUTHMATRIX_WEB_POSTURE_TIMEOUT_SECONDS": "11"},
        {"AUTHMATRIX_WEB_POSTURE_MAX_HEADER_BYTES": "32769"},
        {"AUTHMATRIX_WEB_POSTURE_MAX_HEADER_COUNT": "129"},
        {"AUTHMATRIX_WEB_POSTURE_MAX_COOKIE_HEADERS": "65"},
    ],
)
def test_web_posture_rejects_invalid_configuration(environment):
    with pytest.raises(ValueError):
        load_web_posture_policy(environment)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 11},
        {"max_header_bytes": 0},
        {"max_header_count": 129},
        {"max_cookie_headers": 65},
        {"max_header_count": True},
    ],
)
def test_web_posture_policy_rejects_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        WebPosturePolicy(enabled=True, **kwargs)