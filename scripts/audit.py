#!/usr/bin/env python3
"""Read-only GitHub Actions trust-boundary lint with source line evidence.

Heuristic checks, not a security audit. No network, dynamic execution, or secret reads.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required: python -m pip install 'PyYAML>=6,<7'") from exc

MAX_BYTES = 512_000
MAX_FILES = 200
LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
EXPR_UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:pull_request\.(?:title|body|head\.(?:ref|label))|"
    r"issue\.(?:title|body)|comment\.body|review\.body|discussion\.(?:title|body)|"
    r"commits\[[^]]+\]\.message)|github\.(?:head_ref|ref_name))\b", re.I
)
PR_HEAD = re.compile(r"(?:github\.event\.pull_request\.head\.|refs/pull/|github\.head_ref|github\.event\.pull_request\.number)", re.I)
GITHUB_SECRET = re.compile(r"\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}")
PIN_SHA = re.compile(r"^[0-9a-f]{40}$", re.I)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    severity: str
    rule: str
    summary: str
    guidance: str


def parse_yaml(source: str) -> tuple[Any, dict[tuple[Any, ...], int]]:
    """BaseLoader preserves GitHub's `on` key (YAML 1.1 treats it as bool)."""
    root = yaml.compose(source, Loader=yaml.BaseLoader)
    if root is None:
        raise ValueError("Empty workflow YAML")
    lines: dict[tuple[Any, ...], int] = {}

    def visit(node: yaml.Node, path: tuple[Any, ...]) -> Any:
        if isinstance(node, yaml.ScalarNode):
            lines[path] = node.start_mark.line + 1
            return node.value
        if isinstance(node, yaml.SequenceNode):
            lines[path] = node.start_mark.line + 1
            return [visit(child, path + (index,)) for index, child in enumerate(node.value)]
        if isinstance(node, yaml.MappingNode):
            lines[path] = node.start_mark.line + 1
            result: dict[str, Any] = {}
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode):
                    raise ValueError("Non-scalar mapping key")
                key = key_node.value
                if key in result:
                    raise ValueError("Duplicate YAML key: " + key)
                lines[path + (key,)] = key_node.start_mark.line + 1
                result[key] = visit(value_node, path + (key,))
            return result
        raise ValueError("Unsupported YAML node")

    return visit(root, ()), lines


def events(trigger: Any) -> set[str]:
    if isinstance(trigger, dict):
        return set(trigger)
    if isinstance(trigger, list):
        return {str(value) for value in trigger}
    if isinstance(trigger, str):
        return {trigger}
    return set()


def permission_writes(permission: Any) -> bool:
    if permission == "write-all":
        return True
    if isinstance(permission, dict):
        return any(str(value).strip().lower() == "write" for value in permission.values())
    return False


def analyze(source: str, path: str) -> list[Finding]:
    data, lines = parse_yaml(source)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        raise ValueError("Expected a GitHub Actions workflow with a jobs mapping")
    findings: list[Finding] = []

    def add(at: tuple[Any, ...], level: str, rule: str, summary: str, guidance: str) -> None:
        findings.append(Finding(path, lines.get(at, 1), level, rule, summary, guidance))

    active_events = events(data.get("on"))
    permission = data.get("permissions")
    if permission is None:
        add(("jobs",), "medium", "GHA001", "No explicit workflow-level token permissions", "Set workflow permissions: contents: read (or permissions: {}) and grant narrower job scopes as required; repository defaults may already be restrictive.")
    if permission == "write-all":
        add(("permissions",), "high", "GHA002", "Workflow grants all token permissions write access", "Use explicit least-privilege permissions scoped to individual jobs.")

    for job_name, job in data["jobs"].items():
        if not isinstance(job, dict):
            continue
        job_path = ("jobs", job_name)
        effective = job.get("permissions", permission)
        if job.get("permissions") == "write-all":
            add(job_path + ("permissions",), "high", "GHA002", "Job grants all token permissions write access", "Limit write permissions to the one API scope the job needs.")
        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        untrusted_checkout = -1
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            sp = job_path + ("steps", index)
            uses = step.get("uses")
            if isinstance(uses, str) and not uses.startswith("./") and "@" in uses:
                action, ref = uses.rsplit("@", 1)
                if not PIN_SHA.fullmatch(ref):
                    add(sp + ("uses",), "low", "GHA003", f"Action '{action}' is not pinned to a 40-character commit SHA", "For higher supply-chain assurance, pin third-party actions to immutable full commit SHAs and record the version in a comment.")
            checkout = isinstance(uses, str) and uses.startswith("actions/checkout@")
            params = step.get("with")
            params = params if isinstance(params, dict) else {}
            if checkout and "pull_request_target" in active_events:
                ref = str(params.get("ref", "")) + " " + str(params.get("repository", ""))
                if PR_HEAD.search(ref):
                    untrusted_checkout = index
            script = step.get("run")
            if isinstance(script, str):
                if EXPR_UNTRUSTED.search(script):
                    add(sp + ("run",), "high", "GHA004", "Untrusted event text interpolated directly into a shell script", "Pass event values via env: and quote shell variables. Review all expansion and escaping in the target shell.")
                if GITHUB_SECRET.search(script):
                    add(sp + ("run",), "medium", "GHA005", "Secret expression interpolated directly into run script", "Pass secrets through scoped environment variables and avoid printing them; verify whether execution or logs can reveal values.")
                if "pull_request_target" in active_events and untrusted_checkout >= 0 and index > untrusted_checkout:
                    add(sp + ("run",), "critical", "GHA006", "Shell executes after checking out PR-controlled content under pull_request_target", "Do not execute fork/PR code in a privileged pull_request_target job. Use pull_request with read-only token or isolate the trusted follow-up.")
            if checkout and permission_writes(effective) and str(params.get("persist-credentials", "true")).lower() != "false":
                add(sp + ("uses",), "low", "GHA007", "Writable token may persist in checkout credentials", "Set persist-credentials: false when steps do not need Git pushes; assess the job's actual trust boundary.")
    return sorted(findings, key=lambda f: (f.path, f.line, -LEVELS[f.severity], f.rule))


def read_workflows(path: Path) -> list[Path]:
    if path.is_symlink():
        raise ValueError("Symlink input is not supported")
    if path.is_file():
        if path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError("Input must be a YAML workflow")
        return [path]
    if not path.is_dir():
        raise ValueError("Input does not exist")
    folder = path / ".github" / "workflows"
    if not folder.is_dir():
        raise ValueError("Repository does not have .github/workflows")
    paths = sorted(list(folder.glob("*.yml")) + list(folder.glob("*.yaml")))
    if len(paths) > MAX_FILES:
        raise ValueError("Too many workflow files")
    return paths


def scan(path: Path) -> list[Finding]:
    files = read_workflows(path)
    root = path if path.is_dir() else path.parent
    findings: list[Finding] = []
    for file in files:
        if file.is_symlink() or file.stat().st_size > MAX_BYTES:
            raise ValueError(f"Unsafe or oversized workflow file: {file.name}")
        data = file.read_text(encoding="utf-8")
        try:
            findings.extend(analyze(data, str(file.relative_to(root))))
        except (yaml.YAMLError, ValueError) as exc:
            raise ValueError(f"{file.name}: {exc}") from exc
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".", help="repository root or single .yml/.yaml file")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--fail-on", choices=["none", "medium", "high", "critical"], default="high")
    args = parser.parse_args(argv)
    try:
        findings = scan(Path(args.path))
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps({"findings": [asdict(f) for f in findings], "count": len(findings), "disclaimer": "Static heuristics; manual review required."}, indent=2))
    else:
        print("# GitHub Actions trust-boundary findings\n")
        if not findings:
            print("No supported patterns found. This is not proof the workflow is secure.")
        for item in findings:
            print(f"- **{item.severity.upper()} {item.rule}** `{item.path}:{item.line}` — {item.summary}. {item.guidance}")
        print(f"\nFindings: {len(findings)}. Static heuristics, not a security certification.")
    return 2 if args.fail_on != "none" and any(LEVELS[f.severity] >= LEVELS[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
