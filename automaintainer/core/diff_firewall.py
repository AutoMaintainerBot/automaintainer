from __future__ import annotations
import re
from typing import List, Tuple, Optional
from automaintainer.core.models import PlannedDiff, FileDiff

class DiffFirewallViolation(Exception):
    """Raised when candidate diff breaches firewall policies."""
    pass

class DiffFirewall:
    """
    Dedicated first-class security barrier inspects candidate diffs BEFORE validation or publication.
    Enforces:
    - Maximum changed files
    - Maximum line modifications (additions/deletions)
    - Path allowlists & strict denylists (.github/workflows/**, infra/**, secrets/**)
    - Binary and symlink denial
    - Unexpected file creations
    """
    DEFAULT_FORBIDDEN_PATTERNS = [
        r"^\.github/workflows/.*",      # Actions workflows execute code with repo tokens
        r"^infra/.*",                  # Infrastructure / terraform / deployment
        r"^deploy/.*",
        r".*secrets?.*",               # Secret files or configs
        r".*\.pem$",                   # Private keys
        r".*\.key$",
        r"^\.env.*",                   # Environment files
        r"^CODEOWNERS$",
    ]

    def __init__(
        self,
        max_files: int = 10,
        max_lines_added: int = 500,
        max_lines_deleted: int = 200,
        allow_binary: bool = False,
        allow_symlinks: bool = False,
        allow_new_files: bool = True,
        forbidden_patterns: List[str] = None,
        allowed_paths: List[str] = None
    ):
        self.max_files = max_files
        self.max_lines_added = max_lines_added
        self.max_lines_deleted = max_lines_deleted
        self.allow_binary = allow_binary
        self.allow_symlinks = allow_symlinks
        self.allow_new_files = allow_new_files
        self.forbidden_patterns = [
            re.compile(p, re.IGNORECASE) for p in (forbidden_patterns or self.DEFAULT_FORBIDDEN_PATTERNS)
        ]
        self.allowed_paths = [re.compile(p) for p in (allowed_paths or [])]

    def inspect(self, diff: PlannedDiff) -> Tuple[bool, List[str]]:
        violations: List[str] = []

        file_count = len(diff.files)
        if file_count > self.max_files:
            violations.append(f"Diff touched {file_count} files, exceeding max limit of {self.max_files}")

        total_added = sum(f.lines_added for f in diff.files)
        total_deleted = sum(f.lines_deleted for f in diff.files)

        if total_added > self.max_lines_added:
            violations.append(f"Diff added {total_added} lines, exceeding max limit of {self.max_lines_added}")
        if total_deleted > self.max_lines_deleted:
            violations.append(f"Diff deleted {total_deleted} lines, exceeding max limit of {self.max_lines_deleted}")

        for f in diff.files:
            # Check binary
            if f.is_binary and not self.allow_binary:
                violations.append(f"Binary file change detected in '{f.path}' (prohibited)")

            # Check symlink
            if f.is_symlink and not self.allow_symlinks:
                violations.append(f"Symlink creation/modification detected in '{f.path}' (prohibited)")

            # Check new file creation
            if f.is_new_file and not self.allow_new_files:
                violations.append(f"Unexpected file creation detected for '{f.path}' (prohibited)")

            # Check forbidden path patterns
            normalized_path = f.path.replace("\\", "/").lstrip("/")
            for pattern in self.forbidden_patterns:
                if pattern.match(normalized_path):
                    violations.append(f"Path '{normalized_path}' matches forbidden pattern '{pattern.pattern}'")

            # Check allowed path restrictions if configured
            if self.allowed_paths:
                matched_allowed = any(p.match(normalized_path) for p in self.allowed_paths)
                if not matched_allowed:
                    violations.append(f"Path '{normalized_path}' is outside configured allowed paths")

        passed = len(violations) == 0
        return passed, violations

    def inspect_diff(
        self,
        diff: PlannedDiff,
        allowed_paths: Optional[List[str]] = None,
        session_risk_tier: Optional[Any] = None,
        **kwargs
    ) -> Any:
        if allowed_paths:
            self.allowed_paths = [re.compile(rf"^{re.escape(p.replace('\\', '/').lstrip('/'))}$") for p in allowed_paths]
        passed, violations = self.inspect(diff)
        class FirewallDecision:
            def __init__(self, p: bool, v: List[str]):
                self.passed = p
                self.rejection_reason = "; ".join(v) if v else ""
                self.violations = v
        return FirewallDecision(passed, violations)

    def enforce(self, diff: PlannedDiff) -> None:
        passed, violations = self.inspect(diff)
        if not passed:
            raise DiffFirewallViolation("; ".join(violations))
