"""Baseline tests for the initial package scaffold."""

from typing import NoReturn

import pytest
import typer
from typer import Typer
from typer.testing import CliRunner

from iam_analyzer import __version__
from iam_analyzer.cli.app import app, main

runner = CliRunner()


def test_package_version_matches_initial_release() -> None:
    """The package exposes the initial public version."""
    assert __version__ == "0.1.0"


def test_cli_app_stub_is_importable() -> None:
    """The console script entry point resolves to a Typer application."""
    assert isinstance(app, Typer)
    assert app.info.help is not None
    assert "CIS AWS Foundations Benchmark v5.0.0" in app.info.help


class StubContext:
    """Small context double for covering the baseline Typer callback."""

    invoked_subcommand: str | None = None

    def get_help(self) -> str:
        """Return deterministic help text."""
        return "help"

    def exit(self, code: int = 0) -> NoReturn:
        """Mirror Click context exit behavior."""
        raise typer.Exit(code=code)


def test_cli_stub_prints_help() -> None:
    """The baseline console script exposes help while scan is not implemented."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_cli_callback_exits_cleanly_without_subcommand() -> None:
    """The baseline callback exits cleanly when no subcommand is invoked."""
    with pytest.raises(typer.Exit) as exc_info:
        main(StubContext())  # type: ignore[arg-type]

    assert exc_info.value.exit_code == 0
