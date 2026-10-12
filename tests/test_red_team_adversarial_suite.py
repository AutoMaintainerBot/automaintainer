import pytest
from automaintainer.execution.network_security import ControlledEgressFilter, SSRFSecurityViolation
from automaintainer.github.workflow_installer import WorkflowInstallerService, WorkflowInstallerError
from automaintainer.core.diff_firewall import DiffFirewall, DiffFirewallViolation
from automaintainer.core.models import PlannedDiff, FileDiff
from automaintainer.discovery.lockfile_detector import LockfileRefreshDetector
from automaintainer.execution.gvisor_runtime import MicroVMSandboxRuntime
from automaintainer.execution.resource_limits import SandboxResourceLimits

def test_red_team_ssrf_and_cloud_metadata_attempt():
    """Adversarial Test: malicious code or test attempts to exfiltrate to cloud metadata endpoint."""
    with pytest.raises(SSRFSecurityViolation, match="Controlled Egress Violation"):
        ControlledEgressFilter.enforce("http://169.254.169.254/latest/meta-data")

    with pytest.raises(SSRFSecurityViolation, match="Controlled Egress Violation"):
        ControlledEgressFilter.enforce("http://127.0.0.1:8000/internal-admin")

def test_red_team_workflow_write_all_escalation_attempt():
    """Adversarial Test: model or malicious patch attempts to grant write-all GitHub permissions."""
    malicious_workflow = """
    name: Escalation
    permissions: write-all
    jobs:
      pwn:
        runs-on: ubuntu-latest
        steps:
          - run: echo "hacked"
    """
    with pytest.raises(WorkflowInstallerError, match="write-all"):
        WorkflowInstallerService.validate_workflow_yaml(malicious_workflow)

def test_red_team_forbidden_paths_in_diff_firewall():
    """Adversarial Test: candidate patch attempts to modify sensitive files."""
    firewall = DiffFirewall()
    diff = PlannedDiff(
        files=[
            FileDiff(path=".github/workflows/deploy.yml", lines_added=5),
            FileDiff(path="infra/terraform.tf", lines_added=10),
            FileDiff(path="server.key", lines_added=20),
            FileDiff(path=".env.production", lines_added=2)
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert passed is False
    assert len(violations) >= 4

def test_lockfile_refresh_detector():
    """Test lockfile refresh opportunity detection across ecosystems."""
    python_repo = ["pyproject.toml", "src/main.py"]
    opps = LockfileRefreshDetector.detect_lockfile_opportunities(python_repo)
    assert len(opps) == 1
    assert opps[0].lockfile_path == "poetry.lock"
    assert "poetry lock" in opps[0].regenerate_cmd

def test_microvm_gvisor_runtime_flags():
    """Test microVM runtime configuration flags."""
    runtime = MicroVMSandboxRuntime(use_gvisor=True)
    limits = SandboxResourceLimits(cpu_cores=2.0, memory_mb=2048, max_pids=64)
    flags = runtime.get_container_flags(limits)

    assert "--runtime=runsc" in flags
    assert "--cap-drop=ALL" in flags
    assert "--read-only" in flags
    assert "--pids-limit=64" in flags

def test_red_team_adversarial_prompt_injection_fixture():
    """Adversarial Test: repository README with adversarial system prompt overrides."""
    import os
    from automaintainer.agents.prompt_injection_guard import PromptInjectionGuard, PromptInjectionDetectedError

    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "adversarial_injection", "README.md")
    assert os.path.exists(fixture_path)
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    guard = PromptInjectionGuard()
    scan_res = guard.scan(content)
    assert scan_res.is_safe is False
    assert scan_res.risk_level in ("CRITICAL", "HIGH")

    with pytest.raises(PromptInjectionDetectedError):
        guard.scan_and_raise(content)

def test_red_team_adversarial_diff_symlink_and_binary():
    """Adversarial Test: candidate diff attempts to smuggle binary payloads or symlinks."""
    firewall = DiffFirewall(allow_binary=False, allow_symlinks=False)
    diff = PlannedDiff(
        files=[
            FileDiff(path="malicious.so", lines_added=1, is_binary=True),
            FileDiff(path="etc_passwd_link", lines_added=1, is_symlink=True),
        ]
    )
    passed, violations = firewall.inspect(diff)
    assert passed is False
    assert any("Binary" in v for v in violations)
    assert any("Symlink" in v for v in violations)

@pytest.mark.asyncio
async def test_red_team_kill_switch_blocks_mutation():
    """Adversarial Test: emergency kill switch active prevents all GitHub mutations."""
    from unittest.mock import AsyncMock
    from automaintainer.core.kill_switch import get_kill_switch_manager, KillSwitchActiveError
    from automaintainer.github.mutation_gateway import GitHubMutationGateway
    from automaintainer.core.models import MutationIntent, MutationOp, RiskTier, SessionState

    ks = get_kill_switch_manager()
    ks.set_global_kill(True)

    gateway = GitHubMutationGateway(kill_switch=ks)
    mock_executor = AsyncMock()

    intent = MutationIntent(
        session_id="sess_kill_switch_test",
        actor="pr_manager",
        operation=MutationOp.OPEN_PR,
        repository="target-org/test-repo",
        branch="automaintainer/patch-1",
        target_paths=["pyproject.toml"],
        risk=RiskTier.R1
    )

    from automaintainer.core.models import ResourceBoundCapability
    cap = ResourceBoundCapability(
        session_id="sess_kill_switch_test",
        repository_full_name="target-org/test-repo",
        branch="automaintainer/patch-1",
        allowed_operations={MutationOp.OPEN_PR},
        allowed_paths=["pyproject.toml"],
        lease_epoch="epoch-1"
    )

    try:
        with pytest.raises(KillSwitchActiveError):
            await gateway.submit_mutation(
                intent=intent,
                session_state=SessionState.PR_OPEN,
                actor_role="pr_manager",
                expected_paths=["pyproject.toml"],
                is_maintainer_authorized=True,
                executor=mock_executor,
                capability=cap
            )
        mock_executor.execute_mutation.assert_not_called()
    finally:
        ks.set_global_kill(False)
