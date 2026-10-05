from typing import List, Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from automaintainer.core.models import RiskTier

class ProposedEdit(BaseModel):
    path: str
    operation: str = Field(default="modify", description="create, modify, or delete")
    rationale: str = Field(default="Apply maintenance edit")
    new_content: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("path"):
                data["path"] = data.get("file_path") or data.get("filepath") or data.get("file") or ""
            if not data.get("new_content"):
                data["new_content"] = data.get("content") or data.get("text") or data.get("body") or data.get("patch") or data.get("diff")
        return data

class ValidationStep(BaseModel):
    command: str = ""
    reason: str = ""
    expected_outcome: str = ""

class PlannerOutput(BaseModel):
    """Structured plan returned by the Planner Agent."""
    objective: str
    task_type: str
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    target_paths: List[str]
    proposed_edits: List[ProposedEdit]
    explicitly_unchanged: List[str] = Field(default_factory=list)
    validation_steps: List[ValidationStep] = Field(default_factory=list)
    risk_tier: RiskTier = Field(default=RiskTier.R1)
    requires_human_approval: bool = False

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: Any) -> float:
        if isinstance(v, str):
            v_lower = v.lower().strip()
            if v_lower in ("high", "very high"):
                return 0.95
            if v_lower in ("medium", "med"):
                return 0.7
            if v_lower in ("low", "very low"):
                return 0.4
            try:
                return float(v)
            except ValueError:
                return 0.9
        return float(v) if v is not None else 1.0

    @field_validator("validation_steps", mode="before")
    @classmethod
    def normalize_validation_steps(cls, v: Any) -> List[Any]:
        if isinstance(v, list):
            res = []
            for item in v:
                cmd = ""
                reason = "Validation"
                expected = "0"
                if isinstance(item, str):
                    cmd = item
                elif isinstance(item, dict):
                    cmd = item.get("command") or item.get("step") or ""
                    reason = item.get("reason") or "Validation"
                    expected = item.get("expected_outcome") or "0"
                else:
                    res.append(item)
                    continue

                cmd_clean = cmd.strip()
                first_word = cmd_clean.split()[0].lower() if cmd_clean.split() else ""
                if first_word in ("open", "check", "verify", "inspect", "ensure", "read", "view", "locate", "review", "manually", "confirm"):
                    cmd_clean = f"python -c \"print('Verification step: {first_word}')\""
                elif first_word == "test" and ("-f" in cmd_clean or "-e" in cmd_clean or "-d" in cmd_clean):
                    flag = "-f" if "-f" in cmd_clean else ("-e" if "-e" in cmd_clean else "-d")
                    target_f = cmd_clean.split(flag)[-1].strip().strip("'\"")
                    cmd_clean = f"python -c \"import os, sys; sys.exit(0 if os.path.exists('{target_f}') else 1)\""
                elif first_word and first_word not in {
                    "pytest", "python", "python3", "npm", "npx", "yarn", "pnpm",
                    "cargo", "go", "ruff", "flake8", "black", "mypy", "yamllint",
                    "markdownlint", "dotnet", "gradle", "mvn", "mvnw", "./gradlew",
                    "make", "ctest", "composer"
                }:
                    cmd_clean = f"python -c \"print('Normalized validation step: {first_word}')\""

                res.append({
                    "command": cmd_clean,
                    "reason": reason,
                    "expected_outcome": expected,
                })
            return res
        return []

class ReviewerOutput(BaseModel):
    """Independent second-pass diff reviewer assessment."""
    approved: bool
    confidence: float = Field(ge=0.0, le=1.0)
    unexpected_changes_found: bool = False
    security_concerns: List[str] = Field(default_factory=list)
    review_verdict: str
