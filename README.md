# Agent Flight Recorder

A local-first flight recorder for AI coding agent sessions.

It records wrapped commands, snapshots git changes, flags risky activity, redacts likely secrets from stored output, and generates a Markdown report that helps humans review what an agent changed.

## Why

AI coding agents can touch shell, git, files, tests, dependencies, CI, infrastructure, and application code. Teams need a simple local audit trail that answers:

- What commands ran?
- What files changed?
- Did tests run?
- Did the session touch risky areas such as auth, migrations, CI, dependencies, or secrets?
- Where should a reviewer focus first?

This MVP is intentionally developer-first and stdlib-only.

## Install

```powershell
python -m pip install -e .
```

After installing, both commands are available:

```powershell
agent-recorder --help
afr --help
```

You can also run it directly from source:

```powershell
$env:PYTHONPATH="src"
python -m agent_flight_recorder --help
```

## Quick Start

Start a named session:

```powershell
agent-recorder start --session auth-fix
```

Record a command under the active session:

```powershell
agent-recorder run -- python -m unittest discover -s tests
```

Snapshot the current git state:

```powershell
agent-recorder snapshot --label after-tests
```

Import an existing agent log if you have one:

```powershell
agent-recorder import-log .\claude-code.log --source claude-code
```

Generate a report:

```powershell
agent-recorder report --out agent-report.md
```

Generate a shorter PR summary:

```powershell
agent-recorder pr-summary --out pr-summary.md
```

## Wrap an Agent or Tool

You can start a session and wrap a single long-running process:

```powershell
agent-recorder start --session codex-run -- codex
```

Or:

```powershell
agent-recorder start --session aider-run -- aider
```

The recorder stores JSONL events under `.afr/sessions/` and keeps the latest active session in `.afr/active-session`.

## What It Records

- Session lifecycle events
- Wrapped command argv, normalized command text, exit code, duration, cwd
- Redacted stdout/stderr tails
- Git status snapshots
- Git diff stats

The CLI does not install hooks, intercept unrelated shell commands, or send data to a service.

## Risk Signals

Built-in rules flag common review hotspots:

- Destructive shell commands
- Curl or wget piped to shell/interpreter
- Git history rewrites and pushes
- Production infrastructure commands
- Secret material files
- Authentication and authorization files
- Database migrations
- CI/CD and infrastructure files
- Dependency and lockfile changes
- Public API surface changes

The rules are intentionally transparent and conservative. A match means "review this carefully", not "this is definitely bad".

## Secret Redaction

Stored command output is redacted with built-in detectors for common patterns:

- OpenAI API keys
- GitHub tokens
- Slack tokens
- AWS access keys
- JWTs
- Private key blocks
- Sensitive assignments such as `DATABASE_PASSWORD=...`

Reports include secret-like finding counts and sources, but not the values.

## Commands

```text
agent-recorder start [--session NAME] [-- COMMAND...]
agent-recorder run [--session SESSION_ID] -- COMMAND...
agent-recorder snapshot [--label LABEL]
agent-recorder report [--out report.md]
agent-recorder pr-summary [--out pr-summary.md]
agent-recorder logs [--session SESSION_ID]
agent-recorder import-log PATH [--source claude-code]
agent-recorder status
```

## Development

Run tests:

```powershell
$env:PYTHONPATH="src"
python -m unittest discover -s tests
```

## License

Agent Flight Recorder is open source software licensed under the MIT License. See [LICENSE](LICENSE).

## Roadmap

- Policy YAML for team-specific risk rules
- Importers for existing agent logs
- GitHub Action mode for PR checks
- SQLite backend for richer querying
- MCP tool-call capture and trust metadata
- Approval workflow for risky actions
