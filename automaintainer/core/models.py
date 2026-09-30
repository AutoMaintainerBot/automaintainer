from __future__ import annotations
from enum import Enum
from typing import Optional, List, Dict, Any, Set
from pydantic import BaseModel, Field
from datetime import datetime

class SessionState(str, Enum):
    DISCOVERED = "DISCOVERED"
    ELIGIBLE = "ELIGIBLE"
    ANALYZING = "ANALYZING"
    PLANNING = "PLANNING"
    AWAITING_POLICY = "AWAITING_POLICY"
    WORKING = "WORKING"
    VALIDATING = "VALIDATING"
    PR_OPEN = "PR_OPEN"
    MAINTAINER_REVIEW = "MAINTAINER_REVIEW"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    REVALIDATING = "REVALIDATING"
    PAUSED = "PAUSED"
    # Terminal immutable states
    MERGED = "MERGED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    SAFETY_STOP = "SAFETY_STOP"

# Immutable terminal states: once a session reaches any terminal state, no further transitions are permitted.
TERMINAL_STATES = {
    SessionState.MERGED,
    SessionState.REJECTED,
    SessionState.EXPIRED,
    SessionState.COMPLETED,
    SessionState.CANCELLED,
    SessionState.SAFETY_STOP,
}

# Backward compatibility alias
FINAL_TERMINAL_STATES = TERMINAL_STATES

class RepositoryIdentity(BaseModel):
    installation_id: Optional[int] = None
    repository_id: int
    owner: str
    name: str
    default_branch: str = "main"

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


class RiskTier(str, Enum):
    R0 = "R0"  # Read-only analysis
    R1 = "R1"  # Docs/links/metadata
    R2 = "R2"  # Dependencies/minor CI update
    R3 = "R3"  # Major dependency/API change (requires maintainer approval)
    R4 = "R4"  # Security/credentials (forbidden autonomous)
    R5 = "R5"  # Ambiguous/hostile (skip)

class TaskType(str, Enum):
    DEPENDENCY_UPDATE = "dependency_update"
    GITHUB_ACTION_UPDATE = "github_action_update"
    DOCS_LINK_FIX = "docs_link_fix"
    PACKAGE_METADATA = "package_metadata"
    TEST_REPAIR = "test_repair"

class MutationOp(str, Enum):
    CREATE_BRANCH = "create_branch"
    CREATE_COMMIT = "create_commit"
    OPEN_PR = "open_pr"
    UPDATE_PR = "update_pr"
    ADD_COMMENT = "add_comment"
    CLOSE_PR = "close_pr"

class FileDiff(BaseModel):
    path: str
    lines_added: int = 0
    lines_deleted: int = 0
    is_binary: bool = False
    is_symlink: bool = False
    is_new_file: bool = False
    content: Optional[str] = None

class PlannedDiff(BaseModel):
    files: List[FileDiff] = Field(default_factory=list)
    total_lines_added: int = 0
    total_lines_deleted: int = 0
    total_files: int = 0

class MutationIntent(BaseModel):
    session_id: str
    actor: str
    operation: MutationOp
    repository: str
    branch: str
    repository_id: Optional[int] = None
    installation_id: Optional[int] = None
    target_paths: List[str] = Field(default_factory=list)
    diff: Optional[PlannedDiff] = None
    pr_title: Optional[str] = None
    pr_body: Optional[str] = None
    comment_body: Optional[str] = None
    risk: RiskTier = RiskTier.R2
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ResourceBoundCapability(BaseModel):
    """
    Capability Token granting an operation on a strictly bounded resource.
    Enforces that an agent or worker mutation is locked to the exact
    tenant, installation, repository, session, deterministic branch,
    and expected base commit SHA.
    """
    session_id: str
    repository_full_name: str
    upstream_repository_full_name: Optional[str] = None
    branch: str
    repository_id: Optional[int] = None
    expected_base_sha: Optional[str] = None
    allowed_operations: Set[MutationOp] = Field(default_factory=set)
    allowed_paths: List[str] = Field(default_factory=list)
    installation_id: Optional[int] = None
    lease_epoch: Optional[str] = None
    expires_at: Optional[float] = None
