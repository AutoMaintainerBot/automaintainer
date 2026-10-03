"""
Secret Pattern Scanner.
Deterministic regex-based scan over diff content for credential-like material.
A match triggers SAFETY_STOP — the session is never allowed to publish.

Does NOT call inference — must be fast and fully offline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class SecretScanResult:
    has_secrets: bool = False
    findings: List[str] = field(default_factory=list)   # Human-readable descriptions


_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("GitHub personal access token",        re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Actions token",                re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("GitHub refresh token",                re.compile(r"ghr_[A-Za-z0-9]{36}")),
    ("GitHub fine-grained token",           re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("Groq API key",                        re.compile(r"gsk_[A-Za-z0-9]{32,}")),
    ("OpenAI-style API key",                re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("AWS access key ID",                   re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS secret access key",               re.compile(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}")),
    ("Google API key",                      re.compile(r"AIza[0-9A-Za-z-_]{35}")),
    ("Google OAuth client secret",          re.compile(r"(?i)(client_secret|GOCSPX-)[A-Za-z0-9_-]{20,}")),
    ("Slack bot/webhook token",             re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Stripe secret key",                   re.compile(r"sk_live_[0-9A-Za-z]{24}")),
    ("Stripe restricted key",               re.compile(r"rk_live_[0-9A-Za-z]{24}")),
    ("Sendgrid API key",                    re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("Twilio account SID",                  re.compile(r"AC[0-9a-fA-F]{32}")),
    ("Twilio auth token",                   re.compile(r"(?i)twilio.*[0-9a-fA-F]{32}")),
    ("RSA/ECDSA private key header",        re.compile(r"-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED)\s+PRIVATE KEY-----")),
    ("Bearer token assignment",             re.compile(r"(?i)(Authorization|Bearer)\s*[=:]\s*[A-Za-z0-9._-]{20,}")),
    ("Password variable assignment",        re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*[^\s]{8,}")),
    ("Secret variable assignment",          re.compile(r"(?i)(secret|api_secret|client_secret)\s*[=:]\s*[^\s]{8,}")),
    (".env credential pattern",             re.compile(r"(?i)^(DATABASE_URL|DB_PASSWORD|SECRET_KEY|API_KEY)\s*=\s*.+", re.MULTILINE)),
    ("Connection string with credentials",  re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@")),
]


class SecretPatternScanner:
    """
    Scans raw text (diff content, file patches) for credential patterns.

    Usage:
        scanner = SecretPatternScanner()
        result = scanner.scan(diff_text)
        if result.has_secrets:
            raise SafetyStopError(...)
    """

    def scan(self, text: str) -> SecretScanResult:
        """
        Scan arbitrary text for credential patterns.
        Returns SecretScanResult with has_secrets=True and list of findings.
        """
        findings: List[str] = []

        for description, pattern in _PATTERNS:
            matches = pattern.findall(text)
            if matches:
                # Report count but never echo actual secret values
                findings.append(
                    f"[{description}] — {len(matches)} match(es) found"
                )

        return SecretScanResult(
            has_secrets=bool(findings),
            findings=findings,
        )

    def scan_diff_files(self, diff_files: List[str]) -> SecretScanResult:
        """
        Scan a list of file content strings (e.g., new file contents from a patch).
        Aggregates findings across all files.
        """
        all_findings: List[str] = []
        for content in diff_files:
            result = self.scan(content)
            all_findings.extend(result.findings)
        return SecretScanResult(
            has_secrets=bool(all_findings),
            findings=all_findings,
        )
