"""Tests for shared boto3 pagination helpers."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

from iam_analyzer.scanner.pagination import PaginatorUtil


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.received_kwargs: dict[str, Any] | None = None

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:  # noqa: ANN401
        self.received_kwargs = kwargs
        return self.pages


class _FakeClient:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.paginator = _FakePaginator(pages)
        self.operation_name: str | None = None

    def get_paginator(self, operation_name: str) -> _FakePaginator:
        self.operation_name = operation_name
        return self.paginator


class _FailingClient:
    def get_paginator(self, operation_name: str) -> object:
        raise ClientError(
            {
                "Error": {"Code": "AccessDenied", "Message": operation_name},
                "ResponseMetadata": {"HTTPStatusCode": 403},
            },
            operation_name,
        )


def test_paginate_returns_empty_list_for_empty_pages() -> None:
    client = _FakeClient([{}, {"Users": []}])

    result = PaginatorUtil().paginate(client, "list_users", "Users")

    assert result == []
    assert client.operation_name == "list_users"


def test_paginate_preserves_items_across_multiple_pages() -> None:
    client = _FakeClient(
        [
            {"Users": [{"UserName": "alice"}]},
            {"Users": [{"UserName": "bob"}]},
        ],
    )

    result = PaginatorUtil().paginate(
        client,
        "list_users",
        "Users",
        PathPrefix="/engineering/",
    )

    assert result == [{"UserName": "alice"}, {"UserName": "bob"}]
    assert client.paginator.received_kwargs == {"PathPrefix": "/engineering/"}


def test_paginate_lets_client_errors_reach_check_layer() -> None:
    with pytest.raises(ClientError):
        PaginatorUtil().paginate(_FailingClient(), "list_users", "Users")
