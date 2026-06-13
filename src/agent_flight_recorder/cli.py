from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

from . import __version__, git_utils
from .report import generate_pr_summary, generate_report
from .secrets import find_secret_indicators, redact
from .store import EventStore


OUTPUT_LIMIT = 12_000


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 2
    return int(args.handler(args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-recorder",
        description="Local-first flight recorder for AI coding agent work.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Repository/workspace path.")
    parser.add_argument("--state-dir", default=".afr", help="State directory relative to the repo root.")

    subparsers = parser.add_subparsers(dest="command_name")

    start = subparsers.add_parser("start", help="Create a session, optionally wrapping a command.")
    start.add_argument("--session", help="Human-readable session name.")
    start.add_argument("command", nargs=argparse.REMAINDER, help="Command to wrap after --.")
    start.set_defaults(handler=handle_start)

    run = subparsers.add_parser("run", help="Run a command and record its output, duration, and exit code.")
    run.add_argument("--session", help="Session id. Defaults to the active session.")
    run.add_argument("command", nargs=argparse.REMAINDER, help="Command to run after --.")
    run.set_defaults(handler=handle_run)

    snapshot = subparsers.add_parser("snapshot", help="Record the current git status and diff stat.")
    snapshot.add_argument("--session", help="Session id. Defaults to the active session.")
    snapshot.add_argument("--label", default="manual", help="Snapshot label.")
    snapshot.set_defaults(handler=handle_snapshot)

    report = subparsers.add_parser("report", help="Generate a Markdown activity report.")
    report.add_argument("--session", help="Session id. Defaults to the active session.")
    report.add_argument("--out", type=Path, help="Write Markdown to this file instead of stdout.")
    report.set_defaults(handler=handle_report)

    pr_summary = subparsers.add_parser("pr-summary", help="Generate a compact PR review summary.")
    pr_summary.add_argument("--session", help="Session id. Defaults to the active session.")
    pr_summary.add_argument("--out", type=Path, help="Write Markdown to this file instead of stdout.")
    pr_summary.set_defaults(handler=handle_pr_summary)

    logs = subparsers.add_parser("logs", help="List sessions or show events for one session.")
    logs.add_argument("--session", help="Session id. Defaults to listing sessions.")
    logs.add_argument("--limit", type=int, default=20, help="Maximum events to print.")
    logs.set_defaults(handler=handle_logs)

    import_log = subparsers.add_parser("import-log", help="Import and redact an existing agent log file.")
    import_log.add_argument("path", type=Path, help="Log file to import.")
    import_log.add_argument("--session", help="Session id. Defaults to the active session.")
    import_log.add_argument("--source", default="custom", help="Source label, such as claude-code or aider.")
    import_log.set_defaults(handler=handle_import_log)

    status = subparsers.add_parser("status", help="Show active session and current git state.")
    status.set_defaults(handler=handle_status)

    return parser


def handle_start(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    command = _clean_remainder(args.command)
    session = store.create_session(args.session, metadata={"repo": str(repo_root), "wrapped_command": command})
    print(f"Started session {session.id}")
    _record_snapshot(store, session.id, repo_root, "before")
    if not command:
        print("No command supplied. Use `agent-recorder run -- <command>` to append activity.")
        return 0
    exit_code = _run_and_record(store, session.id, repo_root, command)
    _record_snapshot(store, session.id, repo_root, "after")
    store.append(session.id, {"type": "session_finished", "exit_code": exit_code})
    return exit_code


def handle_run(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    command = _clean_remainder(args.command)
    if not command:
        print("No command supplied. Example: agent-recorder run -- npm test", file=sys.stderr)
        return 2
    session = store.get_session(args.session, create=True)
    assert session is not None
    _record_snapshot(store, session.id, repo_root, "before-command")
    exit_code = _run_and_record(store, session.id, repo_root, command)
    _record_snapshot(store, session.id, repo_root, "after-command")
    return exit_code


def handle_snapshot(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    session = store.get_session(args.session, create=True)
    assert session is not None
    _record_snapshot(store, session.id, repo_root, args.label)
    print(f"Snapshot recorded for session {session.id}")
    return 0


def handle_report(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    session = store.get_session(args.session, create=False)
    if session is None:
        print("No session found. Start one with `agent-recorder start`.", file=sys.stderr)
        return 1
    report = generate_report(store.read_events(session.id), repo_root, session.id)
    _write_or_print(report, args.out)
    return 0


def handle_pr_summary(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    session = store.get_session(args.session, create=False)
    if session is None:
        print("No session found. Start one with `agent-recorder start`.", file=sys.stderr)
        return 1
    summary = generate_pr_summary(store.read_events(session.id), repo_root, session.id)
    _write_or_print(summary, args.out)
    return 0


def handle_logs(args: argparse.Namespace) -> int:
    _repo_root, store = _context(args)
    if args.session:
        events = store.read_events(args.session)
        for event in events[-args.limit :]:
            event_type = event.get("type", "event")
            timestamp = event.get("timestamp", "")
            if event_type == "command":
                print(f"{timestamp} command exit={event.get('exit_code')} {event.get('command')}")
            elif event_type == "snapshot":
                label = event.get("label", "")
                changed = len(event.get("data", {}).get("changed_files", []))
                print(f"{timestamp} snapshot {label} changed_files={changed}")
            else:
                print(f"{timestamp} {event_type}")
        return 0

    sessions = store.list_sessions()
    if not sessions:
        print("No sessions recorded.")
        return 0
    active = store.read_active()
    for session in sessions[: args.limit]:
        marker = "*" if session.id == active else " "
        print(f"{marker} {session.id}  {session.path}")
    return 0


def handle_import_log(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    session = store.get_session(args.session, create=True)
    assert session is not None
    path = args.path
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        return 1

    raw = path.read_text(encoding="utf-8", errors="replace")
    safe = redact(raw)
    findings = _secret_finding_dicts(raw, f"imported log: {args.source}")
    store.append(
        session.id,
        {
            "type": "imported_log",
            "source": args.source,
            "path": str(path),
            "relative_path": git_utils.relative_to(path, repo_root),
            "line_count": len(raw.splitlines()),
            "byte_count": len(raw.encode("utf-8", errors="replace")),
            "content_tail": _tail(safe, OUTPUT_LIMIT),
            "secret_findings": findings,
        },
    )
    print(f"Imported {path} into session {session.id}")
    return 0


def handle_status(args: argparse.Namespace) -> int:
    repo_root, store = _context(args)
    active = store.read_active() or "(none)"
    snap = git_utils.snapshot(repo_root)
    print(f"Repository: {repo_root}")
    print(f"Active session: {active}")
    print(f"Git repo: {snap['is_git_repo']}")
    print(f"Changed files: {len(snap['changed_files'])}")
    return 0


def _context(args: argparse.Namespace) -> tuple[Path, EventStore]:
    repo_root = git_utils.discover_repo_root(args.repo)
    return repo_root, EventStore(repo_root, args.state_dir)


def _record_snapshot(store: EventStore, session_id: str, repo_root: Path, label: str) -> None:
    store.append(
        session_id,
        {
            "type": "snapshot",
            "label": label,
            "data": git_utils.snapshot(repo_root),
        },
    )


def _run_and_record(store: EventStore, session_id: str, repo_root: Path, command: list[str]) -> int:
    start = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=str(repo_root),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    duration_ms = int((time.perf_counter() - start) * 1000)
    normalized_command = git_utils.normalize_command(command)
    safe_stdout = redact(completed.stdout)
    safe_stderr = redact(completed.stderr)
    safe_command = redact(normalized_command)
    safe_argv = [redact(part) for part in command]
    stdout_tail = _tail(safe_stdout, OUTPUT_LIMIT)
    stderr_tail = _tail(safe_stderr, OUTPUT_LIMIT)
    store.append(
        session_id,
        {
            "type": "command",
            "cwd": str(repo_root),
            "command": safe_command,
            "argv": safe_argv,
            "exit_code": completed.returncode,
            "duration_ms": duration_ms,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "secret_findings": [
                *_secret_finding_dicts(normalized_command, "command"),
                *_secret_finding_dicts(completed.stdout, "stdout"),
                *_secret_finding_dicts(completed.stderr, "stderr"),
            ],
        },
    )
    if safe_stdout:
        print(safe_stdout, end="")
    if safe_stderr:
        print(safe_stderr, end="", file=sys.stderr)
    return completed.returncode


def _clean_remainder(command: list[str]) -> list[str]:
    if command and command[0] == "--":
        return command[1:]
    return command


def _tail(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[-limit:]


def _write_or_print(content: str, out: Path | None) -> None:
    if out is None:
        print(content, end="")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(f"Wrote {out}")


def _secret_finding_dicts(text: str, source: str) -> list[dict[str, object]]:
    return [
        {"source": finding.source, "kind": finding.kind, "count": finding.count}
        for finding in find_secret_indicators(text, source)
    ]
