from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterable


@dataclass(frozen=True)
class Risk:
    severity: str
    category: str
    subject: str
    reason: str


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


COMMAND_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "high",
        "destructive command",
        "Deletes recursively or forcefully; verify target scope and rollback path.",
        re.compile(r"(?i)\b(rm\s+-rf|remove-item\b.*\b-recurse\b|del\s+/s|rmdir\s+/s)\b"),
    ),
    (
        "high",
        "shell pipe installer",
        "Downloads code and pipes it into a shell/interpreter.",
        re.compile(r"(?i)\b(curl|wget|invoke-webrequest|iwr)\b.*\|\s*(bash|sh|python|pwsh|powershell|iex)\b"),
    ),
    (
        "high",
        "git history rewrite",
        "Changes repository history or discards local work.",
        re.compile(r"(?i)\bgit\s+(reset\s+--hard|clean\s+-fd|rebase|push\s+.*--force)\b"),
    ),
    (
        "high",
        "production infrastructure",
        "Touches live infrastructure or deployment state.",
        re.compile(r"(?i)\b(kubectl\s+(apply|delete|replace)|terraform\s+apply|helm\s+(upgrade|install)|aws\s+.*\bdelete)\b"),
    ),
    (
        "medium",
        "git publish",
        "Publishes code outside the local machine.",
        re.compile(r"(?i)\bgit\s+push\b"),
    ),
    (
        "medium",
        "container execution",
        "Runs containers with elevated or host-level access.",
        re.compile(r"(?i)\bdocker\s+run\b.*(--privileged|-v\s+/\s*:|--network\s+host)"),
    ),
    (
        "medium",
        "permission change",
        "Broad permission changes can hide or introduce security issues.",
        re.compile(r"(?i)\b(chmod\s+-R\s+777|icacls\b.*\b/grant\b)"),
    ),
)


PATH_RULES: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "high",
        "secret material",
        "Likely credentials or key material changed.",
        (".env", ".pem", ".key", "secret", "credential", "credentials", "keystore"),
    ),
    (
        "high",
        "authentication",
        "Authentication or authorization behavior changed.",
        ("auth", "authorization", "permission", "rbac", "jwt", "oauth", "session", "login"),
    ),
    (
        "high",
        "database migration",
        "Database schema or migration changed; verify forward and rollback behavior.",
        ("migration", "migrations", "db/migrate", "liquibase", "flyway", "alembic"),
    ),
    (
        "medium",
        "ci/cd",
        "Build, release, or deployment automation changed.",
        (".github/workflows", ".gitlab-ci", "jenkinsfile", "azure-pipelines", "circleci", "buildkite"),
    ),
    (
        "medium",
        "infrastructure",
        "Infrastructure as code or container runtime changed.",
        ("dockerfile", "docker-compose", "kubernetes", "k8s", "helm", "terraform", "cloudformation"),
    ),
    (
        "medium",
        "dependencies",
        "Dependencies or lockfiles changed; review supply-chain impact.",
        (
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "requirements.txt",
            "poetry.lock",
            "pipfile.lock",
            "pom.xml",
            "build.gradle",
            "gradle.lockfile",
            "cargo.lock",
            "go.mod",
            "go.sum",
        ),
    ),
    (
        "medium",
        "public api",
        "Public API surface may have changed.",
        ("openapi", "swagger", "graphql", "proto", "controller", "route", "routes", "api/"),
    ),
)


TEST_PATTERNS = (
    re.compile(r"(?i)\b(pytest|unittest|npm\s+(run\s+)?test|pnpm\s+test|yarn\s+test)\b"),
    re.compile(r"(?i)\b(mvn|gradle|go|cargo|dotnet)\b.*\btest\b"),
)


def analyze_command(command: str) -> list[Risk]:
    risks: list[Risk] = []
    for severity, category, reason, regex in COMMAND_RULES:
        if regex.search(command):
            risks.append(Risk(severity=severity, category=category, subject=command, reason=reason))
    return risks


def analyze_paths(paths: Iterable[str]) -> list[Risk]:
    risks: list[Risk] = []
    seen: set[tuple[str, str, str]] = set()
    for path in paths:
        normalized = _normalize_path(path)
        for severity, category, reason, markers in PATH_RULES:
            if any(marker in normalized for marker in markers):
                key = (category, path, reason)
                if key not in seen:
                    risks.append(Risk(severity=severity, category=category, subject=path, reason=reason))
                    seen.add(key)
    return risks


def detect_test_command(command: str) -> bool:
    return any(pattern.search(command) for pattern in TEST_PATTERNS)


def highest_severity(risks: Iterable[Risk]) -> str:
    highest = "low"
    for risk in risks:
        if SEVERITY_ORDER.get(risk.severity, 0) > SEVERITY_ORDER[highest]:
            highest = risk.severity
    return highest


def reviewer_focus(risks: Iterable[Risk]) -> list[str]:
    focus: list[str] = []
    categories = {risk.category for risk in risks}
    if "authentication" in categories:
        focus.append("Verify authorization and authentication edge cases.")
    if "database migration" in categories:
        focus.append("Check migration safety, data compatibility, and rollback plan.")
    if "dependencies" in categories:
        focus.append("Review dependency changes for licensing, CVEs, and transitive risk.")
    if "ci/cd" in categories or "infrastructure" in categories:
        focus.append("Inspect deployment and runtime configuration carefully.")
    if "secret material" in categories:
        focus.append("Confirm no real credentials were committed or exposed.")
    if "destructive command" in categories or "git history rewrite" in categories:
        focus.append("Confirm local work and git history were not unintentionally discarded.")
    if not focus:
        focus.append("Review the touched files against the intended task scope.")
    return focus


def _normalize_path(path: str) -> str:
    path = path.replace("\\", "/").lower()
    # PurePosixPath removes redundant separators without touching unresolved paths.
    return str(PurePosixPath(path))

