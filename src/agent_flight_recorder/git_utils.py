from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True)
class ChangedFile:
    path: str
    status: str


def run_git(args: list[str], cwd: Path) -> GitResult:
    process = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return GitResult(
        ok=process.returncode == 0,
        stdout=process.stdout,
        stderr=process.stderr,
        returncode=process.returncode,
    )


def discover_repo_root(cwd: Path) -> Path:
    result = run_git(["rev-parse", "--show-toplevel"], cwd)
    if result.ok and result.stdout.strip():
        return Path(result.stdout.strip()).resolve()
    return cwd.resolve()


def is_git_repo(cwd: Path) -> bool:
    return run_git(["rev-parse", "--is-inside-work-tree"], cwd).ok


def porcelain_status(cwd: Path) -> list[ChangedFile]:
    result = run_git(["status", "--porcelain=v1", "-z"], cwd)
    if not result.ok or not result.stdout:
        return []

    entries = result.stdout.split("\0")
    changed: list[ChangedFile] = []
    index = 0
    while index < len(entries):
        raw = entries[index]
        index += 1
        if not raw:
            continue
        status = raw[:2]
        path = raw[3:]
        if status.startswith("R") or status.startswith("C"):
            if index < len(entries):
                new_path = entries[index]
                index += 1
                path = f"{path} -> {new_path}"
        changed.append(ChangedFile(path=path, status=status.strip() or "modified"))
    return changed


def diff_stat(cwd: Path) -> str:
    result = run_git(["diff", "--stat"], cwd)
    return result.stdout.strip() if result.ok else ""


def diff_name_only(cwd: Path) -> list[str]:
    result = run_git(["diff", "--name-only"], cwd)
    if not result.ok:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def staged_diff_name_only(cwd: Path) -> list[str]:
    result = run_git(["diff", "--cached", "--name-only"], cwd)
    if not result.ok:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def diff_for_secret_scan(cwd: Path, max_chars: int = 250_000) -> str:
    result = run_git(["diff", "--cached", "--unified=0"], cwd)
    chunks = result.stdout if result.ok else ""
    result = run_git(["diff", "--unified=0"], cwd)
    if result.ok:
        chunks += "\n" + result.stdout
    return chunks[:max_chars]


def snapshot(cwd: Path) -> dict[str, object]:
    changed = porcelain_status(cwd)
    return {
        "is_git_repo": is_git_repo(cwd),
        "changed_files": [{"path": item.path, "status": item.status} for item in changed],
        "diff_stat": diff_stat(cwd),
    }


def normalize_command(command: list[str]) -> str:
    return " ".join(_quote_if_needed(part) for part in command)


def _quote_if_needed(value: str) -> str:
    if not value:
        return '""'
    if any(char.isspace() for char in value):
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'
    return value


def relative_to(path: Path, root: Path) -> str:
    try:
        return os.fspath(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return os.fspath(path.resolve())

