import pytest
from automaintainer.core.models import PlannedDiff, FileDiff
from automaintainer.core.diff_firewall import DiffFirewall, DiffFirewallViolation

def test_diff_within_budget():
    firewall = DiffFirewall(max_files=5, max_lines_added=100, max_lines_deleted=50)
    diff = PlannedDiff(
        files=[
            FileDiff(path="src/utils.py", lines_added=20, lines_deleted=5),
            FileDiff(path="README.md", lines_added=10, lines_deleted=0)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert passed
    assert len(violations) == 0

def test_diff_rejects_workflow_files():
    firewall = DiffFirewall()
    diff = PlannedDiff(
        files=[
            FileDiff(path=".github/workflows/ci.yml", lines_added=2, lines_deleted=2)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert not passed
    assert any(".github/workflows" in v for v in violations)

def test_diff_rejects_secret_or_pem_files():
    firewall = DiffFirewall()
    diff = PlannedDiff(
        files=[
            FileDiff(path="config/server.key", lines_added=10, lines_deleted=0),
            FileDiff(path=".env.production", lines_added=5, lines_deleted=0)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert not passed
    assert len(violations) >= 2

def test_diff_rejects_line_budget_overflow():
    firewall = DiffFirewall(max_lines_added=50)
    diff = PlannedDiff(
        files=[
            FileDiff(path="main.py", lines_added=120, lines_deleted=0)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert not passed
    assert any("Diff added 120 lines" in v for v in violations)

def test_diff_rejects_binary_files():
    firewall = DiffFirewall(allow_binary=False)
    diff = PlannedDiff(
        files=[
            FileDiff(path="assets/logo.png", is_binary=True)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert not passed
    assert any("Binary file change detected" in v for v in violations)
