"""Shared boto3 paginator utilities."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


class _Paginator(Protocol):
    def paginate(self, **kwargs: Any) -> Iterable[Mapping[str, Any]]:  # noqa: ANN401
        """Return paginated boto3 response pages."""


class _ClientWithPaginator(Protocol):
    def get_paginator(self, operation_name: str) -> _Paginator:
        """Return a boto3 paginator for the requested operation."""


class PaginatorUtil:
    """Small wrapper that centralizes boto3 paginator loops."""

    def paginate(
        self,
        client: _ClientWithPaginator,
        operation_name: str,
        result_key: str,
        **kwargs: Any,  # noqa: ANN401
    ) -> list[Any]:
        """Concatenate list values from every paginator page."""
        paginator = client.get_paginator(operation_name)
        results: list[Any] = []
        for page in paginator.paginate(**kwargs):
            page_results = page.get(result_key, [])
            if isinstance(page_results, list):
                results.extend(page_results)
        return results
