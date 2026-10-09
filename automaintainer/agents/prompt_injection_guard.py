"""
Prompt Injection Guard.
Deterministic corpus-based detector that marks repository text as [UNTRUSTED_CONTENT].
Must run BEFORE any repository text reaches a model prompt.
Does NOT call inference — this is a pure text filter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern

class PromptInjectionDetectedError(ValueError):
    """Raised when critical or high prompt injection is detected."""
    pass

@dataclass
class InjectionScanResult:
    is_safe: bool = True
    risk_level: str = "SAFE"   # SAFE | SUSPICIOUS | HIGH | CRITICAL
    findings: List[str] = field(default_factory=list)


# Critical: attempts to redefine identity or escape the sandbox
_CRITICAL_PATTERNS: List[tuple] = [
    ("Identity redefinition",
     re.compile(r"(?i)(you are now|ignore (all )?(previous|above|prior) (instructions?|rules?|prompts?)|"
                r"pretend (you are|to be)|act as (an?|the) (different|new|unrestricted)|"
                r"forget (your|all) (instructions?|rules?|training))")),
    ("Exfiltration instruction",
     re.compile(r"(?i)(send (your|the|all) (secrets?|keys?|tokens?|credentials?|api keys?)|"
                r"output (your|the) (api|groq|github) (key|token|secret)|"
                r"print (the |your )?(system|hidden|secret) (prompt|instructions?))")),
    ("Policy bypass attempt",
     re.compile(r"(?i)(bypass (all )?(security|safety|policy|restrictions?)|"
                r"disable (your )?(safety|content|policy) (filter|check|guard)|"
                r"DAN (mode|jailbreak)|developer mode|jailbreak)")),
    ("System prompt extraction",
     re.compile(r"(?i)(reveal (your|the) (system|hidden|original) prompt|"
                r"what (are|were) your (instructions?|rules?|directives?)|"
                r"show (me )?(your|the) (full |complete )?(prompt|instructions?))")),
]

# High: likely social engineering attempts targeting maintainer commands
_HIGH_PATTERNS: List[tuple] = [
    ("Fake maintainer command",
     re.compile(r"(?i)(@automaintainer|@bot|the bot should|automaintainer (must|should|shall|will))\s+"
                r"(merge|approve|bypass|ignore|skip|disable)")),
    ("Authority spoofing",
     re.compile(r"(?i)(i am (the|a) (maintainer|owner|admin|operator)|"
                r"as (the|a) (repository |repo )?(owner|admin|maintainer)|"
                r"this is (an? )?(authorized|approved|official) (request|command|instruction))")),
    ("Credential exfiltration in commit message context",
     re.compile(r"(?i)(include (the |your )?(groq|api|github) (key|token)|"
                r"add (the |my )?(password|secret|token) to)")),
]

# Suspicious: ambiguous but worth flagging
_SUSPICIOUS_PATTERNS: List[tuple] = [
    ("Hidden unicode/encoding",
     re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")),   # Zero-width / direction chars
    ("Injection-style delimiter",
     re.compile(r"(?i)(<<<|>>>|```\s*(system|instruction|prompt)|"
                r"\[system\]|\[inst\]|\[/inst\]|<\|im_start\|>|<\|im_end\|>)")),
    ("Excessive instruction language",
     re.compile(r"(?i)(always|never|must|shall|will not|forbidden|mandatory)\s.{0,80}"
                r"(instructions?|rules?|commands?|prompts?)")),
]

_SENTINEL = "[UNTRUSTED_CONTENT — DATA ONLY]"


class PromptInjectionGuard:
    """
    Scans repository-sourced text for injection attempts.

    Usage:
        guard = PromptInjectionGuard()
        result = guard.scan(readme_text)
        safe_text = guard.sanitize(readme_text)  # Wrap with DATA sentinel
    """

    def scan(self, text: str) -> InjectionScanResult:
        """
        Multi-tier scan: CRITICAL > HIGH > SUSPICIOUS.
        Returns the highest risk level found.
        """
        findings: List[str] = []

        for description, pattern in _CRITICAL_PATTERNS:
            if pattern.search(text):
                findings.append(f"[CRITICAL] {description}")

        for description, pattern in _HIGH_PATTERNS:
            if pattern.search(text):
                findings.append(f"[HIGH] {description}")

        for description, pattern in _SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                findings.append(f"[SUSPICIOUS] {description}")

        if any(f.startswith("[CRITICAL]") for f in findings):
            risk_level = "CRITICAL"
        elif any(f.startswith("[HIGH]") for f in findings):
            risk_level = "HIGH"
        elif findings:
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SAFE"

        return InjectionScanResult(
            is_safe=(risk_level == "SAFE"),
            risk_level=risk_level,
            findings=findings,
        )

    def sanitize(self, text: str, label: str = "") -> str:
        """
        Wraps untrusted repository text in a DATA sentinel so models cannot
        act on it as instructions. Call this on ALL repository-sourced content
        before it enters a prompt.
        """
        header = f"{_SENTINEL} {label}" if label else _SENTINEL
        return f"{header}\n{text}\n{_SENTINEL}"

    def scan_and_raise(self, text: str, source_label: str = "repository content") -> None:
        """Raises PromptInjectionDetectedError if CRITICAL or HIGH injection risk is found."""
        result = self.scan(text)
        if result.risk_level in ("CRITICAL", "HIGH"):
            raise PromptInjectionDetectedError(
                f"Prompt injection risk ({result.risk_level}) detected in {source_label}: "
                + "; ".join(result.findings)
            )
