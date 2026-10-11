"""
Audit Service.
Every privileged decision produces an immutable audit record.
Secrets are NEVER written to the audit log — a redaction pass strips common patterns.
"""
import re
import uuid
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from automaintainer.data.tables import AuditLogRecord

# Patterns that indicate credential-like material that must be redacted
_SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key|token|secret|password|passwd|credential|private[_-]?key)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),        # GitHub personal access token
    re.compile(r"ghs_[A-Za-z0-9]{36}"),        # GitHub Actions token
    re.compile(r"ghr_[A-Za-z0-9]{36}"),        # GitHub refresh token
    re.compile(r"gsk_[A-Za-z0-9]{32,}"),       # Groq API key pattern
    re.compile(r"sk-[A-Za-z0-9]{32,}"),        # OpenAI-style API key
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),  # PEM header
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),  # Base64 blobs > 40 chars (heuristic)
]

_REDACTED = "[REDACTED]"


def _redact_value(value: Any) -> Any:
    """Recursively redact secret-like strings in dicts, lists, and strings."""
    if isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            value = pattern.sub(_REDACTED, value)
        return value
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


class AuditService:
    """
    Typed wrapper for creating AuditLogRecord rows.

    Usage:
        audit = AuditService(db_session)
        await audit.record(
            session_id="sess_...",
            actor_type="system",
            actor_id="session_orchestrator",
            action="transition_state",
            target="sessions/sess_...",
            details={"from": "WORKING", "to": "VALIDATING"},
        )
    """

    def __init__(self, db: AsyncSession):
        self._db = db

    async def record(
        self,
        *,
        session_id: str,
        actor_type: str,           # system | human | agent | worker | github
        actor_id: str,
        action: str,
        target: str,
        details: Optional[Dict[str, Any]] = None,
        decision_id: Optional[str] = None,
        policy_version: str = "1.0",
    ) -> AuditLogRecord:
        """
        Creates and persists an audit record.
        Redacts any credential-like material from `details` before storage.
        """
        safe_details = _redact_value(details or {})

        record = AuditLogRecord(
            id=f"aud_{uuid.uuid4().hex}",
            session_id=session_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            target=target,
            decision_id=decision_id,
            policy_version=policy_version,
            details_json=safe_details,
        )
        self._db.add(record)
        await self._db.flush()
        return record
