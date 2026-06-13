from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from . import git_utils
from .risk import (
    SEVERITY_ORDER,
    Risk,
    analyze_command,
    analyze_paths,
    detect_test_command,
    highest_severity,
    reviewer_focus,
)
from .secrets import SecretFinding, find_secret_indicators, summarize_findings
from .time_utils import utc_now


def generate_report(
    events: list[dict[str, Any]],
    repo_root: Path,
    session_id: str,
    include_current_git: bool = True,
) -> str:
    commands = [event for event in events if event.get("type") == "command"]
    snapshots = [event for event in events if event.get("type") == "snapshot"]
    imported_logs = [event for event in events if event.get("type") == "imported_log"]
    changed_files = _collect_changed_files(events)

    if include_current_git:
        for item in git_utils.porcelain_status(repo_root):
            changed_files.setdefault(item.path, item.status)

    risks: list[Risk] = []
    for command_event in commands:
        command = str(command_event.get("command", ""))
        risks.extend(analyze_command(command))
    risks.extend(analyze_paths(changed_files.keys()))

    secret_findings: list[SecretFinding] = []
    for command_event in commands:
        stdout_tail = str(command_event.get("stdout_tail", ""))
        stderr_tail = str(command_event.get("stderr_tail", ""))
        command = str(command_event.get("command", ""))
        secret_findings.extend(_stored_secret_findings(command_event))
        secret_findings.extend(find_secret_indicators(command, "command"))
        secret_findings.extend(find_secret_indicators(stdout_tail, f"stdout: {command[:70]}"))
        secret_findings.extend(find_secret_indicators(stderr_tail, f"stderr: {command[:70]}"))
    for imported in imported_logs:
        secret_findings.extend(_stored_secret_findings(imported))
        content_tail = str(imported.get("content_tail", ""))
        secret_findings.extend(find_secret_indicators(content_tail, f"imported log: {imported.get('source', 'custom')}"))

    diff_text = git_utils.diff_for_secret_scan(repo_root)
    if diff_text:
        secret_findings.extend(find_secret_indicators(diff_text, "git diff"))

    tests = [
        event
        for event in commands
        if detect_test_command(str(event.get("command", "")))
    ]

    lines: list[str] = []
    lines.append("# AI Agent Activity Report")
    lines.append("")
    lines.append(f"- Session: `{session_id}`")
    lines.append(f"- Generated: `{utc_now()}`")
    lines.append(f"- Repository: `{repo_root}`")
    lines.append(f"- Commands recorded: `{len(commands)}`")
    lines.append(f"- Files changed: `{len(changed_files)}`")
    lines.append(f"- Overall risk: `{highest_severity(risks).upper() if risks else 'LOW'}`")
    lines.append("")

    lines.append("## Commands Executed")
    lines.append("")
    if commands:
        for event in commands:
            exit_code = event.get("exit_code")
            duration_ms = event.get("duration_ms")
            command = event.get("command", "")
            timestamp = event.get("timestamp", "")
            marker = "PASS" if exit_code == 0 else "FAIL"
            lines.append(f"- `{marker}` `{command}`")
            lines.append(f"  - exit code: `{exit_code}`, duration: `{duration_ms}ms`, at: `{timestamp}`")
    else:
        lines.append("- No wrapped commands were recorded.")
    lines.append("")

    lines.append("## Files Changed")
    lines.append("")
    if changed_files:
        for path, status in sorted(changed_files.items()):
            lines.append(f"- `{status}` `{path}`")
    else:
        lines.append("- No git changes detected.")
    lines.append("")

    diff_stat = _latest_diff_stat(snapshots) or git_utils.diff_stat(repo_root)
    if diff_stat:
        lines.append("## Diff Stat")
        lines.append("")
        lines.append("```text")
        lines.append(diff_stat)
        lines.append("```")
        lines.append("")

    lines.append("## Imported Logs")
    lines.append("")
    if imported_logs:
        for event in imported_logs:
            source = event.get("source", "custom")
            path = event.get("relative_path") or event.get("path", "")
            line_count = event.get("line_count", 0)
            byte_count = event.get("byte_count", 0)
            lines.append(f"- `{source}` `{path}` ({line_count} lines, {byte_count} bytes)")
    else:
        lines.append("- No existing agent logs were imported.")
    lines.append("")

    lines.append("## Risk Signals")
    lines.append("")
    if risks:
        for risk in sorted(
            risks,
            key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.category, item.subject),
            reverse=True,
        ):
            lines.append(f"- `{risk.severity.upper()}` {risk.category}: `{risk.subject}`")
            lines.append(f"  - {risk.reason}")
    else:
        lines.append("- No high-signal risk rules matched.")
    lines.append("")

    lines.append("## Tests Observed")
    lines.append("")
    if tests:
        for event in tests:
            outcome = "passed" if event.get("exit_code") == 0 else "failed"
            lines.append(f"- `{event.get('command', '')}` {outcome} with exit code `{event.get('exit_code')}`")
    else:
        lines.append("- No test command was recorded. Consider running the relevant test suite before review.")
    lines.append("")

    lines.append("## Secret Exposure Check")
    lines.append("")
    secret_lines = summarize_findings(secret_findings)
    if secret_lines:
        lines.append("- Potential secret-like values were detected. Values are not printed here.")
        for item in secret_lines:
            lines.append(f"- {item}")
    else:
        lines.append("- No secret-like values matched the built-in detectors.")
    lines.append("")

    lines.append("## Suggested Reviewer Focus")
    lines.append("")
    for item in reviewer_focus(risks):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Rollback Notes")
    lines.append("")
    if changed_files:
        lines.append("- Review the git diff before reverting or committing.")
        lines.append("- Prefer a normal revert commit for shared branches.")
        lines.append("- If this is local-only exploration, create a patch before discarding changes.")
    else:
        lines.append("- No changed files were detected at report time.")
    lines.append("")

    category_counts = Counter(risk.category for risk in risks)
    if category_counts:
        lines.append("## Risk Summary")
        lines.append("")
        for category, count in category_counts.most_common():
            lines.append(f"- {category}: `{count}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def generate_pr_summary(events: list[dict[str, Any]], repo_root: Path, session_id: str) -> str:
    full_report = generate_report(events, repo_root, session_id)
    sections = _split_sections(full_report)
    wanted = [
        "# AI Agent Activity Report",
        "## Files Changed",
        "## Risk Signals",
        "## Tests Observed",
        "## Suggested Reviewer Focus",
    ]
    output: list[str] = []
    for heading in wanted:
        if heading in sections:
            output.append(sections[heading].strip())
            output.append("")
    return "\n".join(output).rstrip() + "\n"


def _collect_changed_files(events: list[dict[str, Any]]) -> dict[str, str]:
    changed: dict[str, str] = {}
    for event in events:
        if event.get("type") != "snapshot":
            continue
        data = event.get("data", {})
        if not isinstance(data, dict):
            continue
        files = data.get("changed_files", [])
        if not isinstance(files, list):
            continue
        for item in files:
            if isinstance(item, dict) and item.get("path"):
                changed[str(item["path"])] = str(item.get("status", "changed"))
    return changed


def _latest_diff_stat(snapshots: list[dict[str, Any]]) -> str:
    for event in reversed(snapshots):
        data = event.get("data", {})
        if isinstance(data, dict) and data.get("diff_stat"):
            return str(data["diff_stat"])
    return ""


def _stored_secret_findings(event: dict[str, Any]) -> list[SecretFinding]:
    findings = event.get("secret_findings", [])
    if not isinstance(findings, list):
        return []
    output: list[SecretFinding] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        source = str(item.get("source", "unknown"))
        kind = str(item.get("kind", "secret-like value"))
        try:
            count = int(item.get("count", 1))
        except (TypeError, ValueError):
            count = 1
        output.append(SecretFinding(source=source, kind=kind, count=count))
    return output


def _split_sections(markdown: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current = "# AI Agent Activity Report"
    sections[current] = []
    for line in markdown.splitlines():
        if line.startswith("# "):
            current = line
            sections.setdefault(current, []).append(line)
        elif line.startswith("## "):
            current = line
            sections.setdefault(current, []).append(line)
        else:
            sections.setdefault(current, []).append(line)
    return {key: "\n".join(value) for key, value in sections.items()}
