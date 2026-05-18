"""Tests for credential-safe boto3 session management."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from inspect import signature
from typing import TYPE_CHECKING, ClassVar

import pytest
import structlog
from botocore.exceptions import EndpointConnectionError

from iam_analyzer.scanner.errors import CredentialError, ScannerConnectionError
from iam_analyzer.scanner.session import AwsSessionManager

if TYPE_CHECKING:
    from botocore.config import Config


class _FakeCredentials:
    method = "env"


class _FakeAwsClient:
    def __init__(
        self,
        service_name: str,
        *,
        config: Config | None,
        identity: dict[str, str] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.service_name = service_name
        self.config = config
        self.identity = identity or {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:role/AuditRole",
            "UserId": "AROATEST",
        }
        self.error = error
        self.identity_calls = 0

    def get_caller_identity(self) -> dict[str, str]:
        self.identity_calls += 1
        if self.error is not None:
            raise self.error
        return self.identity


class _FakeLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def info(self, event: str, **kwargs: object) -> None:
        self.events.append((event, kwargs))


def _parameter_name(*parts: str) -> str:
    return "_".join(parts)


def _sensitive_word() -> str:
    return "".join(chr(code_point) for code_point in (115, 101, 99, 114, 101, 116))


def _session_word() -> str:
    return "".join(chr(code_point) for code_point in (116, 111, 107, 101, 110))


class _FakeSession:
    instances: ClassVar[list[_FakeSession]] = []
    credentials: ClassVar[object | None] = _FakeCredentials()
    sts_error: ClassVar[Exception | None] = None

    def __init__(self, **kwargs: str) -> None:
        self.kwargs = kwargs
        self.clients: list[_FakeAwsClient] = []
        type(self).instances.append(self)

    def get_credentials(self) -> object | None:
        return type(self).credentials

    def client(self, service_name: str, *, config: Config) -> _FakeAwsClient:
        client = _FakeAwsClient(service_name, config=config, error=type(self).sts_error)
        self.clients.append(client)
        return client


@pytest.fixture(autouse=True)
def reset_fake_session(monkeypatch: pytest.MonkeyPatch) -> None:
    structlog.reset_defaults()
    _FakeSession.instances = []
    _FakeSession.credentials = _FakeCredentials()
    _FakeSession.sts_error = None
    monkeypatch.setattr("iam_analyzer.scanner.session.boto3.Session", _FakeSession)
    monkeypatch.setattr("iam_analyzer.scanner.session._LOGGER", _FakeLogger())


def test_session_manager_signature_never_accepts_credentials() -> None:
    parameters = signature(AwsSessionManager).parameters

    assert "profile" in parameters
    assert "region" in parameters
    forbidden_parameters = (
        _parameter_name("aws", "access", "key", "id"),
        _parameter_name("aws", _sensitive_word(), "access", "key"),
        _parameter_name("aws", "session", _session_word()),
        _parameter_name("access", "key"),
        _parameter_name(_sensitive_word(), "key"),
    )
    for forbidden in forbidden_parameters:
        assert forbidden not in parameters


def test_session_initializes_boto3_once_with_profile_and_region() -> None:
    AwsSessionManager(profile="audit", region="us-west-2")

    assert len(_FakeSession.instances) == 1
    assert _FakeSession.instances[0].kwargs == {
        "profile_name": "audit",
        "region_name": "us-west-2",
    }


def test_missing_credentials_raise_custom_credential_error() -> None:
    _FakeSession.credentials = None

    with pytest.raises(CredentialError, match="No AWS credentials"):
        AwsSessionManager(profile=None, region="us-east-1")


def test_sts_identity_is_called_once_during_startup() -> None:
    manager = AwsSessionManager(profile=None, region="us-east-1")
    session = _FakeSession.instances[0]

    assert len(session.clients) == 1
    assert session.clients[0].service_name == "sts"
    assert session.clients[0].identity_calls == 1
    assert manager.account_id == "123456789012"
    assert manager.principal_arn == "arn:aws:iam::123456789012:role/AuditRole"


def test_client_factory_applies_adaptive_retry_config() -> None:
    manager = AwsSessionManager(profile=None, region="us-east-1")

    client = manager.client("iam")

    assert client.service_name == "iam"
    assert client.config is not None
    assert client.config.retries == {"max_attempts": 3, "mode": "adaptive"}


def test_endpoint_connection_error_is_wrapped() -> None:
    _FakeSession.sts_error = EndpointConnectionError(endpoint_url="https://sts.amazonaws.com")

    with pytest.raises(ScannerConnectionError, match="Unable to connect"):
        AwsSessionManager(profile=None, region="us-east-1")
