from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON, UniqueConstraint, Index, ForeignKey
)
from sqlalchemy.orm import declarative_base

Base = declarative_base()

def utc_now():
    """Timezone-aware UTC timestamp generator."""
    return datetime.now(timezone.utc)

class UserRecord(Base):
    __tablename__ = "users"
    id = Column(String(64), primary_key=True)
    github_id = Column(Integer, unique=True, nullable=False, index=True)
    account_type = Column(String(32), default="user") # user | org
    status = Column(String(32), default="active")
    created_at = Column(DateTime(timezone=True), default=utc_now)

class InstallationRecord(Base):
    __tablename__ = "installations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    github_installation_id = Column(Integer, unique=True, nullable=False, index=True)
    account_id = Column(Integer, nullable=False, index=True)
    target_type = Column(String(32), default="organization")
    permissions_json = Column(JSON, default=dict)
    status = Column(String(32), default="active")
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class RepositoryRecord(Base):
    __tablename__ = "repositories"
    id = Column(Integer, primary_key=True, autoincrement=True)
    github_repo_id = Column(Integer, unique=True, nullable=False, index=True)
    installation_id = Column(Integer, ForeignKey("installations.id", ondelete="CASCADE"), nullable=True, index=True)
    owner = Column(String(128), nullable=False)
    name = Column(String(128), nullable=False)
    visibility = Column(String(32), default="public")
    default_branch = Column(String(64), default="main")
    archived = Column(Boolean, default=False, nullable=False)
    fingerprint_json = Column(JSON, default=dict)
    health_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class RepoPolicyRecord(Base):
    __tablename__ = "repo_policies"
    id = Column(String(64), primary_key=True)
    repo_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    autonomy = Column(String(32), default="supervised")
    allowed_classes_json = Column(JSON, default=list)
    excluded_paths_json = Column(JSON, default=list)
    budgets_json = Column(JSON, default=dict)
    schedules_json = Column(JSON, default=dict)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class SessionRecord(Base):
    """
    Session table with Optimistic Concurrency version control.
    Transitions MUST enforce: WHERE id = :id AND version = :version
    """
    __tablename__ = "sessions"
    __table_args__ = (
        UniqueConstraint("repository_id", "branch_name", name="uq_repo_session_branch"),
    )
    id = Column(String(64), primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    mode = Column(String(32), default="installed")  # installed | public
    state = Column(String(32), nullable=False, default="DISCOVERED", index=True)
    version = Column(Integer, default=1, nullable=False)  # Optimistic concurrency lock
    risk_tier = Column(String(16), default="R2")
    opportunity_score = Column(Float, default=0.0)
    workspace_id = Column(String(64), nullable=True)
    branch_name = Column(String(128), nullable=True)
    pr_number = Column(Integer, nullable=True)
    budget_json = Column(JSON, default=dict)
    metadata_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)

class TaskRecord(Base):
    """Explicit entity tracking concrete maintenance tasks per session."""
    __tablename__ = "tasks"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    task_type = Column(String(64), nullable=False)
    scope = Column(String(256), nullable=True)
    evidence_json = Column(JSON, default=list)
    confidence = Column(Float, default=0.0)
    risk_tier = Column(String(16), default="R2")
    status = Column(String(32), default="pending", index=True) # pending | approved | executing | succeeded | failed
    created_at = Column(DateTime(timezone=True), default=utc_now)

class PlanRecord(Base):
    """Versioned maintenance plan produced by the Planner agent."""
    __tablename__ = "plans"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, default=1, nullable=False)
    plan_hash = Column(String(64), nullable=False)
    plan_json = Column(JSON, default=dict)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class WorkspaceRecord(Base):
    """Tracking ephemeral sandbox environments."""
    __tablename__ = "workspaces"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    runtime_id = Column(String(128), nullable=False)
    image = Column(String(128), default="python:3.12-slim")
    resource_limits_json = Column(JSON, default=dict)
    status = Column(String(32), default="active") # active | destroyed | leaked
    created_at = Column(DateTime(timezone=True), default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)

class PullRequestRecord(Base):
    """Dedicated Pull Request entity."""
    __tablename__ = "pull_requests"
    __table_args__ = (
        UniqueConstraint("owner", "repo", "number", name="uq_repo_pr_number"),
    )
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    number = Column(Integer, nullable=False)
    owner = Column(String(128), nullable=False)
    repo = Column(String(128), nullable=False)
    head_ref = Column(String(128), nullable=False)
    base_ref = Column(String(128), default="main")
    base_sha = Column(String(64), nullable=True)
    head_sha = Column(String(64), nullable=True)
    url = Column(String(512), nullable=False)
    status = Column(String(32), default="open", index=True) # open | closed | merged
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class ArtifactRecord(Base):
    """Tracking stored diffs, reports, and logs in object storage."""
    __tablename__ = "artifacts"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(64), nullable=False) # diff | test_log | sbom | report
    object_key = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False)
    retention_until = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class PolicyDecisionRecord(Base):
    """Immutable policy evaluation records."""
    __tablename__ = "policy_decisions"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    policy_version = Column(String(32), default="1.0")
    allowed = Column(Boolean, nullable=False)
    reasons_json = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class PolicyVersionRecord(Base):
    """Rule immutability store."""
    __tablename__ = "policy_versions"
    id = Column(String(64), primary_key=True)
    version = Column(String(32), unique=True, nullable=False)
    rules_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class CommentRecord(Base):
    """Historical conversation log with classification."""
    __tablename__ = "comments"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    author = Column(String(128), nullable=False)
    comment_type = Column(String(32), default="maintainer") # maintainer | bot | contributor
    payload_ref = Column(Text, nullable=True)
    classification = Column(String(64), default="informational") # safe_request | scope_expansion | injection
    created_at = Column(DateTime(timezone=True), default=utc_now)

class EventRecord(Base):
    """Append-only event log with delivery-level idempotency key."""
    __tablename__ = "events"
    id = Column(String(64), primary_key=True)
    delivery_id = Column(String(128), unique=True, nullable=False, index=True)  # X-GitHub-Delivery
    session_id = Column(String(64), nullable=True, index=True)
    event_type = Column(String(64), nullable=False)
    source = Column(String(32), default="github")
    payload_ref = Column(Text, nullable=True)
    payload_hash = Column(String(64), nullable=True)
    received_at = Column(DateTime(timezone=True), default=utc_now)

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    actor_type = Column(String(32), nullable=False)  # system | human | agent | worker
    actor_id = Column(String(128), nullable=False)
    action = Column(String(64), nullable=False)
    target = Column(String(256), nullable=False)
    decision_id = Column(String(64), nullable=True)
    policy_version = Column(String(32), default="1.0")
    details_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class CostEventRecord(Base):
    __tablename__ = "cost_events"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    model = Column(String(128), nullable=False)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    runtime_seconds = Column(Float, default=0.0)
    estimated_cost_usd = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class RateLimitBucketRecord(Base):
    __tablename__ = "rate_limit_buckets"
    id = Column(String(64), primary_key=True)
    scope_key = Column(String(128), unique=True, nullable=False, index=True)
    tokens_remaining = Column(Integer, default=0)
    reset_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class IncidentRecord(Base):
    __tablename__ = "incidents"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=True, index=True)
    severity = Column(String(16), nullable=False) # SEV-0 | SEV-1 | SEV-2 | SEV-3
    status = Column(String(32), default="open") # open | investigating | contained | resolved
    root_cause = Column(Text, nullable=True)
    details_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class JobRecord(Base):
    __tablename__ = "jobs"
    id = Column(String(64), primary_key=True)
    task_id = Column(String(64), nullable=True, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    worker_id = Column(String(128), nullable=True)
    queue_name = Column(String(64), default="default", index=True)
    status = Column(String(32), default="pending", index=True) # pending | leased | running | succeeded | failed
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class OpportunityRecord(Base):
    """Detected maintenance opportunity with evidence and scoring."""
    __tablename__ = "opportunities"
    id = Column(String(64), primary_key=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    task_type = Column(String(64), nullable=False)
    summary = Column(Text, nullable=True)
    evidence_json = Column(JSON, default=list)
    target_paths_json = Column(JSON, default=list)
    score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    risk_tier = Column(String(16), default="R2")
    validation_recipe_json = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    status = Column(String(32), default="detected", index=True)
    detected_at = Column(DateTime(timezone=True), default=utc_now)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class ValidationRunRecord(Base):
    """Per-gate validation result within a session."""
    __tablename__ = "validation_runs"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    gate_name = Column(String(64), nullable=False)
    passed = Column(Boolean, nullable=False, default=False)
    command = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    artifact_ref = Column(Text, nullable=True)
    details_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now)

class InferenceCallRecord(Base):
    __tablename__ = "inference_calls"
    id = Column(String(64), primary_key=True)
    session_id = Column(String(64), nullable=False, index=True)
    provider = Column(String(32), default="groq")
    project_id = Column(String(64), nullable=True)
    key_id = Column(String(64), nullable=True)
    model_id = Column(String(128), nullable=False)
    logical_role = Column(String(64), nullable=True)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    latency_ms = Column(Float, default=0.0)
    status = Column(String(32), default="success")
    created_at = Column(DateTime(timezone=True), default=utc_now)

class OutboxRecord(Base):
    """Transactional outbox to guarantee reliable asynchronous event/job dispatch."""
    __tablename__ = "outbox_messages"
    __table_args__ = (
        Index("ix_outbox_status_created", "status", "created_at"),
    )
    id = Column(String(64), primary_key=True)
    idempotency_key = Column(String(128), nullable=True, unique=True, index=True)
    queue_name = Column(String(64), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    task_type = Column(String(64), nullable=True)
    payload_json = Column(JSON, default=dict)
    status = Column(String(32), default="pending", index=True) # pending | claimed | dispatched | dead_letter
    retry_count = Column(Integer, default=0)
    claim_worker_id = Column(String(64), nullable=True)
    claim_expires_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    dispatched_at = Column(DateTime(timezone=True), nullable=True)

