from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .time_utils import utc_now


DEFAULT_STATE_DIR = ".afr"
SESSION_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class Session:
    id: str
    path: Path


class EventStore:
    def __init__(self, repo_root: Path, state_dir: str = DEFAULT_STATE_DIR) -> None:
        self.repo_root = repo_root.resolve()
        self.root = self.repo_root / state_dir
        self.sessions_dir = self.root / "sessions"
        self.active_file = self.root / "active-session"

    def ensure(self) -> None:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, name: str | None = None, metadata: dict[str, Any] | None = None) -> Session:
        self.ensure()
        timestamp = utc_now().replace(":", "").replace("-", "")
        if name:
            slug = SESSION_RE.sub("-", name.strip()).strip("-") or "session"
            session_id = f"{timestamp}-{slug}"
        else:
            session_id = timestamp
        session = Session(id=session_id, path=self.sessions_dir / f"{session_id}.jsonl")
        self.write_active(session.id)
        self.append(
            session.id,
            {
                "type": "session_started",
                "session_id": session.id,
                "metadata": metadata or {},
            },
        )
        return session

    def get_session(self, session_id: str | None = None, create: bool = False) -> Session | None:
        self.ensure()
        resolved = session_id or self.read_active()
        if not resolved and create:
            return self.create_session()
        if not resolved:
            return None
        path = self.sessions_dir / f"{resolved}.jsonl"
        if path.exists():
            return Session(id=resolved, path=path)
        if create:
            return self.create_session(resolved)
        return None

    def write_active(self, session_id: str) -> None:
        self.ensure()
        self.active_file.write_text(session_id, encoding="utf-8")

    def read_active(self) -> str | None:
        if not self.active_file.exists():
            return None
        value = self.active_file.read_text(encoding="utf-8").strip()
        return value or None

    def append(self, session_id: str, event: dict[str, Any]) -> None:
        self.ensure()
        record = {
            "version": 1,
            "timestamp": utc_now(),
            **event,
        }
        path = self.sessions_dir / f"{session_id}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")

    def read_events(self, session_id: str) -> list[dict[str, Any]]:
        path = self.sessions_dir / f"{session_id}.jsonl"
        if not path.exists():
            return []
        events: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
        return events

    def list_sessions(self) -> list[Session]:
        self.ensure()
        sessions = [
            Session(id=path.stem, path=path)
            for path in self.sessions_dir.glob("*.jsonl")
            if path.is_file()
        ]
        return sorted(sessions, key=lambda session: session.path.stat().st_mtime, reverse=True)

