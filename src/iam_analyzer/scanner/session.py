"""Credential-safe boto3 session management."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import Any

import boto3
import structlog
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from iam_analyzer.scanner.errors import CredentialError, ScannerConnectionError

_LOGGER = structlog.get_logger(__name__)
_RETRY_CONFIG = {"max_attempts": 3, "mode": "adaptive"}


class AwsSessionManager:
    """Own exactly one boto3 session for a scanner run."""

    def __init__(self, *, profile: str | None = None, region: str = "us-east-1") -> None:
        """Resolve credentials through boto3's standard chain and validate caller identity."""
        self.profile = profile
        self.region = region
        self._config = Config(retries=_RETRY_CONFIG)
        self._session = self._create_session()
        self._validate_credentials_present()
        identity = self._load_caller_identity()
        self.account_id = identity["Account"]
        self.principal_arn = identity["Arn"]
        _LOGGER.info(
            "aws_identity_resolved",
            account_id=self.account_id,
            principal_arn=self.principal_arn,
            region=self.region,
        )

    def client(self, service_name: str) -> Any:  # noqa: ANN401
        """Create a boto3 client with the scanner retry configuration."""
        return self._session.client(service_name, config=self._config)

    def _create_session(self) -> Any:  # noqa: ANN401
        session_kwargs = {"region_name": self.region}
        if self.profile is not None:
            session_kwargs["profile_name"] = self.profile

        try:
            return boto3.Session(**session_kwargs)
        except ProfileNotFound as error:
            msg = f"AWS profile could not be found: {self.profile}"
            raise CredentialError(msg) from error

    def _validate_credentials_present(self) -> None:
        try:
            credentials = self._session.get_credentials()
        except (NoCredentialsError, PartialCredentialsError) as error:
            msg = "No AWS credentials could be resolved from the boto3 credential chain"
            raise CredentialError(msg) from error

        if credentials is None:
            msg = "No AWS credentials could be resolved from the boto3 credential chain"
            raise CredentialError(msg)

    def _load_caller_identity(self) -> dict[str, str]:
        try:
            response = self._session.client("sts", config=self._config).get_caller_identity()
        except (NoCredentialsError, PartialCredentialsError) as error:
            msg = "AWS credentials could not be used to validate caller identity"
            raise CredentialError(msg) from error
        except EndpointConnectionError as error:
            msg = "Unable to connect to AWS STS endpoint to validate caller identity"
            raise ScannerConnectionError(msg) from error
        except ClientError as error:
            msg = "AWS STS caller identity validation failed"
            raise CredentialError(msg) from error

        return {
            "Account": str(response["Account"]),
            "Arn": str(response["Arn"]),
            "UserId": str(response["UserId"]),
        }
