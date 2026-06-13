from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


MASK = "[REDACTED]"


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "OpenAI API key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    ),
    SecretPattern(
        "GitHub token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"),
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b"),
    ),
    SecretPattern(
        "AWS access key id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        "AWS secret access key assignment",
        re.compile(
            r"(?i)\b(AWS_SECRET_ACCESS_KEY\s*[:=]\s*)([A-Za-z0-9/+=]{32,})"
        ),
    ),
    SecretPattern(
        "Private key block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    SecretPattern(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    SecretPattern(
        "Sensitive assignment",
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[:=]\s*)([^\s\"']+)"
        ),
    ),
)


@dataclass(frozen=True)
class SecretFinding:
    source: str
    kind: str
    count: int


def redact(text: str, mask: str = MASK) -> str:
    """Mask likely secrets in text while preserving useful surrounding context."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        if pattern.regex.groups >= 2:
            redacted = pattern.regex.sub(lambda match: f"{match.group(1)}{mask}", redacted)
        else:
            redacted = pattern.regex.sub(mask, redacted)
    return redacted


def find_secret_indicators(text: str, source: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for pattern in SECRET_PATTERNS:
        count = len(pattern.regex.findall(text))
        if count:
            findings.append(SecretFinding(source=source, kind=pattern.name, count=count))
    return findings


def summarize_findings(findings: Iterable[SecretFinding]) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        noun = "match" if finding.count == 1 else "matches"
        lines.append(f"{finding.source}: {finding.kind} ({finding.count} {noun})")
    return lines

