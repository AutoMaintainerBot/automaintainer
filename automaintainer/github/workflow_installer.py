from typing import Dict, Any, Optional
import yaml
from automaintainer.core.repo_config import RepoConfigEngine

class WorkflowInstallerError(Exception):
    pass

class WorkflowInstallerService:
    """
    Repository Bootstrap Protocol (.github/workflows/automaintainer.yml).
    1. Inspects existing CI conventions.
    2. Generates minimal, compatible workflow.
    3. Validates YAML syntax & security.
    4. Opens clearly labeled bootstrap PR (rather than direct write to default branch).
    5. Self-Protection Rule: Refuses to recursively modify its own workflow without explicit authorization.
    """

    DEFAULT_WORKFLOW_TEMPLATE = """name: AutoMaintainer Companion
on:
  pull_request:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      - name: AutoMaintainer Verification
        run: echo "AutoMaintainer companion workflow active"
"""

    @classmethod
    def generate_workflow_content(cls, repo_name: str) -> str:
        return cls.DEFAULT_WORKFLOW_TEMPLATE

    @classmethod
    def validate_workflow_yaml(cls, content: str) -> bool:
        try:
            parsed = yaml.safe_load(content)
            if not isinstance(parsed, dict):
                return False
            # Ensure permissions are bounded
            perms = parsed.get("permissions", {})
            if perms == "write-all":
                raise WorkflowInstallerError("Refusing to generate workflow with 'write-all' permissions")
            return True
        except Exception as e:
            raise WorkflowInstallerError(f"Invalid YAML workflow: {str(e)}")

    @classmethod
    def is_self_modification(cls, target_path: str) -> bool:
        """Self-Protection: detects if bot is modifying its own config or workflow."""
        norm = target_path.replace("\\", "/").lstrip("/")
        return norm in [
            ".github/workflows/automaintainer.yml",
            ".github/workflows/automaintainer.yaml",
            ".github/automaintainer.yml",
            ".github/automaintainer.yaml"
        ]
