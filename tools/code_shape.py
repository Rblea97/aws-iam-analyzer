"""Enforce lightweight production code-shape guardrails."""

# ruff: noqa: INP001

from __future__ import annotations

import argparse
import ast
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

MAX_FUNCTION_COMPLEXITY = 8
MAX_FUNCTION_LOGICAL_LINES = 40
MAX_MODULE_PHYSICAL_LINES = 300
MAX_NESTING_DEPTH = 3
SUCCESS = 0
FAILURE = 1
RULE_COMPLEXITY = "cyclomatic complexity"
RULE_LOGICAL_LINES = "logical lines"
RULE_NESTING_DEPTH = "nesting depth"
RULE_PHYSICAL_LINES = "physical lines"

BRANCH_NODE_NAMES = {
    "Assert",
    "AsyncFor",
    "For",
    "If",
    "IfExp",
    "While",
}
COMPREHENSION_NODE_NAMES = {
    "DictComp",
    "GeneratorExp",
    "ListComp",
    "SetComp",
}
CONTROL_NODE_TYPES = (
    ast.AsyncFor,
    ast.For,
    ast.If,
    ast.Match,
    ast.Try,
    ast.TryStar,
    ast.While,
)


@dataclass(frozen=True, slots=True)
class Waiver:
    """Documented exception for legacy production code shape."""

    reason: str


@dataclass(frozen=True, slots=True)
class Metrics:
    """Measured shape for one function."""

    complexity: int
    logical_lines: int
    nesting_depth: int


@dataclass(frozen=True, slots=True)
class RuleCheck:
    """One measured value to compare against a code-shape limit."""

    rule: str
    actual: int
    limit: int


@dataclass(frozen=True, slots=True)
class Violation:
    """One code-shape violation."""

    path: str
    location: str
    rule: str
    actual: int
    limit: int

    def format(self) -> str:
        """Return a readable one-line violation."""
        return f"{self.path}:{self.location}: {self.rule} is {self.actual}; limit is {self.limit}"


MODULE_WAIVERS: dict[str, Waiver] = {}
FUNCTION_WAIVERS: dict[tuple[str, str, str], Waiver] = {
    (
        "src/iam_analyzer/checks/cloudtrail/selectors.py",
        "management_event_coverage",
        RULE_COMPLEXITY,
    ): Waiver(reason="CloudTrail selector evaluator handles basic and advanced selector forms."),
    (
        "src/iam_analyzer/checks/common.py",
        "json_safe",
        RULE_COMPLEXITY,
    ): Waiver(reason="Recursive JSON normalization handles multiple scalar/container types."),
    (
        "src/iam_analyzer/cli/app.py",
        "scan",
        RULE_LOGICAL_LINES,
    ): Waiver(
        reason="CLI orchestration is slightly over limit pending command-service extraction.",
    ),
    (
        "src/iam_analyzer/models/finding.py",
        "_is_json_safe",
        RULE_COMPLEXITY,
    ): Waiver(reason="Recursive JSON validation handles multiple scalar/container types."),
    (
        "src/iam_analyzer/scanner/orchestrator.py",
        "run_scan",
        RULE_LOGICAL_LINES,
    ): Waiver(reason="Scanner orchestration is slightly over limit pending result builder split."),
}


def _read_source(path: Path) -> str:
    with tokenize.open(path) as file:
        return file.read()


def _repo_relative(path: Path) -> str:
    resolved_path = path.resolve()
    try:
        return resolved_path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved_path.as_posix()


def _iter_python_files(paths: Sequence[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_file() and path.suffix == ".py" and "__pycache__" not in path.parts:
            yield path
            continue

        if path.is_dir():
            for candidate in sorted(path.rglob("*.py")):
                if "__pycache__" not in candidate.parts:
                    yield candidate


def _logical_line_count(source_lines: Sequence[str], node: ast.AST) -> int:
    end_lineno = getattr(node, "end_lineno", None)
    lineno = getattr(node, "lineno", None)
    if lineno is None or end_lineno is None:
        return 0

    span = source_lines[lineno - 1 : end_lineno]
    return sum(1 for line in span if _is_logical_line(line))


def _is_logical_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def _complexity(node: ast.AST) -> int:
    visitor = _ComplexityVisitor()
    visitor.visit(node)
    return visitor.score


class _ComplexityVisitor(ast.NodeVisitor):
    """Approximate McCabe-style cyclomatic complexity with stdlib AST nodes."""

    def __init__(self) -> None:
        """Initialize complexity with the baseline path through the function."""
        self.score = 1

    def generic_visit(self, node: ast.AST) -> None:
        """Visit a node and increment complexity for branch-like constructs."""
        name = type(node).__name__
        if name in BRANCH_NODE_NAMES:
            self.score += 1
        elif isinstance(node, ast.BoolOp):
            self.score += max(0, len(node.values) - 1)
        elif isinstance(node, ast.ExceptHandler):
            self.score += 1
        elif isinstance(node, ast.Match):
            self.score += len(node.cases)
        elif name in COMPREHENSION_NODE_NAMES:
            self.score += _comprehension_complexity(node)

        super().generic_visit(node)


def _comprehension_complexity(node: ast.AST) -> int:
    generators = getattr(node, "generators", ())
    return sum(1 + len(generator.ifs) for generator in generators)


def _nesting_depth(node: ast.AST) -> int:
    visitor = _NestingDepthVisitor()
    visitor.visit(node)
    return visitor.maximum


class _NestingDepthVisitor(ast.NodeVisitor):
    """Measure nested control-structure depth inside a function."""

    def __init__(self) -> None:
        """Initialize nesting counters."""
        self.current = 0
        self.maximum = 0

    def generic_visit(self, node: ast.AST) -> None:
        """Visit a node while tracking nested control structures."""
        if isinstance(node, CONTROL_NODE_TYPES):
            self.current += 1
            self.maximum = max(self.maximum, self.current)
            super().generic_visit(node)
            self.current -= 1
            return

        super().generic_visit(node)


def _collect_function_metrics(
    tree: ast.AST,
    source_lines: Sequence[str],
) -> list[tuple[str, int, Metrics]]:
    collector = _FunctionCollector(source_lines)
    collector.visit(tree)
    return collector.functions


class _FunctionCollector(ast.NodeVisitor):
    """Collect qualified function names and their metrics."""

    def __init__(self, source_lines: Sequence[str]) -> None:
        """Store source lines and initialize traversal state."""
        self._source_lines = source_lines
        self._scope: list[str] = []
        self.functions: list[tuple[str, int, Metrics]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class scope while visiting methods."""
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Collect metrics for a synchronous function."""
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Collect metrics for an async function."""
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified_name = ".".join([*self._scope, node.name])
        metrics = Metrics(
            complexity=_complexity(node),
            logical_lines=_logical_line_count(self._source_lines, node),
            nesting_depth=_nesting_depth(node),
        )
        self.functions.append((qualified_name, node.lineno, metrics))
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()


def _module_violation(path: str, line_count: int, *, use_waivers: bool) -> Violation | None:
    if line_count <= MAX_MODULE_PHYSICAL_LINES:
        return None

    if use_waivers and path in MODULE_WAIVERS:
        return None

    return Violation(
        path=path,
        location="module",
        rule=RULE_PHYSICAL_LINES,
        actual=line_count,
        limit=MAX_MODULE_PHYSICAL_LINES,
    )


def _function_violations(
    path: str,
    name: str,
    line: int,
    metrics: Metrics,
    *,
    use_waivers: bool,
) -> list[Violation]:
    return [
        violation
        for violation in (
            _function_violation(
                path,
                name,
                line,
                RuleCheck(
                    rule=RULE_LOGICAL_LINES,
                    actual=metrics.logical_lines,
                    limit=MAX_FUNCTION_LOGICAL_LINES,
                ),
                use_waivers=use_waivers,
            ),
            _function_violation(
                path,
                name,
                line,
                RuleCheck(
                    rule=RULE_COMPLEXITY,
                    actual=metrics.complexity,
                    limit=MAX_FUNCTION_COMPLEXITY,
                ),
                use_waivers=use_waivers,
            ),
            _function_violation(
                path,
                name,
                line,
                RuleCheck(
                    rule=RULE_NESTING_DEPTH,
                    actual=metrics.nesting_depth,
                    limit=MAX_NESTING_DEPTH,
                ),
                use_waivers=use_waivers,
            ),
        )
        if violation is not None
    ]


def _function_violation(
    path: str,
    name: str,
    line: int,
    check: RuleCheck,
    *,
    use_waivers: bool,
) -> Violation | None:
    if check.actual <= check.limit:
        return None

    if use_waivers and (path, name, check.rule) in FUNCTION_WAIVERS:
        return None

    return Violation(
        path=path,
        location=f"{name}:{line}",
        rule=check.rule,
        actual=check.actual,
        limit=check.limit,
    )


def _check_file(path: Path, *, use_waivers: bool) -> tuple[int, list[Violation]]:
    source = _read_source(path)
    relative_path = _repo_relative(path)
    source_lines = source.splitlines()
    violations = []

    module_violation = _module_violation(
        relative_path,
        len(source_lines),
        use_waivers=use_waivers,
    )
    if module_violation is not None:
        violations.append(module_violation)

    tree = ast.parse(source, filename=str(path))
    functions = _collect_function_metrics(tree, source_lines)
    for name, line, metrics in functions:
        violations.extend(
            _function_violations(
                relative_path,
                name,
                line,
                metrics,
                use_waivers=use_waivers,
            ),
        )

    return len(functions), violations


def _check_paths(
    paths: Sequence[Path],
    *,
    use_waivers: bool = True,
) -> tuple[int, int, list[Violation]]:
    checked_files = 0
    checked_functions = 0
    violations: list[Violation] = []

    for path in _iter_python_files(paths):
        checked_files += 1
        function_count, file_violations = _check_file(path, use_waivers=use_waivers)
        checked_functions += function_count
        violations.extend(file_violations)

    return checked_files, checked_functions, violations


def _stale_waiver_messages(raw_violations: Sequence[Violation]) -> list[str]:
    module_violation_paths = {
        violation.path for violation in raw_violations if violation.location == "module"
    }
    function_violation_keys = {
        (violation.path, violation.location.rsplit(":", maxsplit=1)[0], violation.rule)
        for violation in raw_violations
        if violation.location != "module"
    }

    stale_modules = [
        f"module waiver for {path}"
        for path in sorted(MODULE_WAIVERS)
        if path not in module_violation_paths
    ]
    stale_functions = [
        f"function waiver for {path}:{name} ({rule})"
        for path, name, rule in sorted(FUNCTION_WAIVERS)
        if (path, name, rule) not in function_violation_keys
    ]
    return [*stale_modules, *stale_functions]


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check production Python files for bounded size and complexity.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to check.")
    return parser.parse_args(argv)


def _main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)
    checked_files, checked_functions, violations = _check_paths(args.paths)
    _, _, raw_violations = _check_paths(args.paths, use_waivers=False)
    stale_waivers = _stale_waiver_messages(raw_violations)

    if violations or stale_waivers:
        lines: list[str] = []
        if violations:
            lines.append("Code shape violations:")
            lines.extend(f"- {violation.format()}" for violation in violations)
        if stale_waivers:
            lines.append("Stale code-shape waivers:")
            lines.extend(f"- {message}" for message in stale_waivers)
        sys.stderr.write("\n".join(lines) + "\n")
        return FAILURE

    sys.stdout.write(
        "PASS code shape: "
        f"{checked_files} file(s), {checked_functions} function(s) checked; "
        f"{len(MODULE_WAIVERS) + len(FUNCTION_WAIVERS)} waiver(s) documented.\n",
    )
    return SUCCESS


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
