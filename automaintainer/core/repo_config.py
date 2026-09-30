import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
import yaml

class InvalidRepoConfigError(ValueError):
    """Raised when repository configuration in .github/automaintainer.yml is malformed or invalid."""
    pass

class RepoConfigLimits(BaseModel):
    max_files: int = Field(default=10, ge=1)
    max_changed_lines: int = Field(default=500, ge=10)
    max_runtime_minutes: int = Field(default=60, ge=5)
    max_retries: int = Field(default=3, ge=0)

class RepoConfigCollaboration(BaseModel):
    maintainers: List[str] = Field(default_factory=list)
    respond_to_comments: bool = True

class RepoConfigPublic(BaseModel):
    enabled: bool = False

class RepoConfig(BaseModel):
    """
    Structured parser for .github/automaintainer.yml
    """
    version: int = Field(default=1)
    autonomy: str = Field(default="supervised")
    allowed_tasks: List[str] = Field(default_factory=lambda: ["dependency_update", "github_action_update", "docs_link_fix", "package_metadata"])
    denied_paths: List[str] = Field(default_factory=lambda: ["deploy/**", "infra/**", ".github/workflows/**", "secrets/**"])
    limits: RepoConfigLimits = Field(default_factory=RepoConfigLimits)
    collaboration: RepoConfigCollaboration = Field(default_factory=RepoConfigCollaboration)
    public: RepoConfigPublic = Field(default_factory=RepoConfigPublic)

    @field_validator("autonomy")
    @classmethod
    def validate_autonomy(cls, v: str) -> str:
        allowed = {"observe", "suggest", "pr", "supervised", "autonomous"}
        if v.lower() not in allowed:
            raise ValueError(f"Invalid autonomy mode '{v}'. Must be one of {allowed}")
        return v.lower()

class RepoConfigEngine:
    """
    Enforces the policy precedence hierarchy:
    Platform Hard Ceilings -> Org Policy -> Repo Policy (.github/automaintainer.yml) -> Session Policy.
    CRITICAL INVARIANT: A pull request cannot modify .github/automaintainer.yml to weaken its own policy checks.
    """

    PLATFORM_CEILING_MAX_FILES = 25
    PLATFORM_CEILING_MAX_LINES = 1500
    PLATFORM_MANDATORY_DENIED_PATHS = [
        r"^\.github/workflows/.*",
        r"^infra/.*",
        r"^deploy/.*",
        r".*secrets?.*",
        r".*\.pem$",
        r".*\.key$",
        r"^\.env.*",
        r"^CODEOWNERS$"
    ]

    @classmethod
    def parse_yaml(cls, yaml_content: str) -> RepoConfig:
        if not yaml_content or not yaml_content.strip():
            return RepoConfig()
        try:
            data = yaml.safe_load(yaml_content)
            if not isinstance(data, dict):
                raise InvalidRepoConfigError("Configuration root must be a YAML mapping.")
            cfg_dict = data.get("automaintainer", data)
            if not isinstance(cfg_dict, dict):
                raise InvalidRepoConfigError("'automaintainer' section must be a mapping.")
            return RepoConfig.model_validate(cfg_dict)
        except Exception as e:
            if isinstance(e, InvalidRepoConfigError):
                raise e
            raise InvalidRepoConfigError(f"Failed to parse repository configuration: {e}") from e

    @classmethod
    def merge_with_platform_ceilings(cls, repo_config: RepoConfig) -> Dict[str, Any]:
        effective_max_files = min(repo_config.limits.max_files, cls.PLATFORM_CEILING_MAX_FILES)
        effective_max_lines = min(repo_config.limits.max_changed_lines, cls.PLATFORM_CEILING_MAX_LINES)

        combined_denied = set(repo_config.denied_paths)
        for p in cls.PLATFORM_MANDATORY_DENIED_PATHS:
            combined_denied.add(p)

        return {
            "autonomy": repo_config.autonomy,
            "allowed_tasks": repo_config.allowed_tasks,
            "max_files": effective_max_files,
            "max_changed_lines": effective_max_lines,
            "max_runtime_minutes": repo_config.limits.max_runtime_minutes,
            "denied_paths": list(combined_denied),
            "respond_to_comments": repo_config.collaboration.respond_to_comments,
            "maintainers": [m.lower() for m in repo_config.collaboration.maintainers],
            "public_enabled": repo_config.public.enabled
        }
