import pytest
from pydantic import ValidationError

from authmatrix.web.schemas import ScanRequest


def test_accepts_valid_policy_path():
    request = ScanRequest(policy_path="policy.yaml")

    assert request.policy_path == "policy.yaml"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"policy_path": ""},
        {"policy_path": "policy.yaml", "base_url": "http://example.com"},
        {"policy_path": 123},
        {"policy_path": True},
        {"policy_path": None},
    ],
)
def test_rejects_invalid_request_payloads(payload):
    with pytest.raises(ValidationError):
        ScanRequest.model_validate(payload)


def test_rejects_policy_path_longer_than_limit():
    with pytest.raises(ValidationError):
        ScanRequest(policy_path="a" * 256)
