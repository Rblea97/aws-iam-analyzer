"""Typer application entry point for iam-analyzer."""

import typer

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="AWS IAM and CloudTrail posture analyzer for CIS AWS Foundations Benchmark v5.0.0.",
)
