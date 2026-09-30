import json
import hashlib
from typing import List, Dict, Any
from pydantic import BaseModel, Field

class ReproducibilityManifest(BaseModel):
    """
    Immutable execution record guaranteeing full forensic reconstructability.
    Stored alongside audit events and signed by the orchestrator.
    """
    session_id: str
    repo_sha: str
    base_image_digest: str = Field(description="SHA-256 pinned container base image digest")
    model_id: str
    toolchain_versions: Dict[str, str] = Field(default_factory=dict)
    policy_version: str = "1.0"
    patch_hash: str
    validation_commands: List[str] = Field(default_factory=list)
    validation_results: List[str] = Field(default_factory=list)
    network_policy_version: str = "1.0"

    def compute_manifest_hash(self) -> str:
        """Produces SHA-256 hash of the canonical manifest JSON."""
        canonical_json = self.model_dump_json()
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
