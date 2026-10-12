"""
Comprehensive Test Suite for Hardened Production Architecture:
1. AST Code Synthesis & Syntax Validation (Python, YAML, TOML, JSON)
2. Compiler Error Feedback & Self-Healing Loop
3. Sandbox Egress Proxy Enforcement (git clone, subprocess, container)
4. Multi-Tenant Cloud Object Storage, Presigned URLs & KMS
5. Hardware Security, Dynamic Secrets (Vault/KMS URI Resolution)
6. Sandbox Runtime Factory & Production Containerization
"""
import pytest
import os
import json
from unittest.mock import MagicMock, patch
from automaintainer.agents.ast_patcher import AstPatcher, AstValidationError
from automaintainer.agents.patcher import MinimalPatcher
from automaintainer.agents.planner import MaintenancePlanner
from automaintainer.inference.schemas import PlannerOutput, ProposedEdit, ValidationStep
from automaintainer.core.models import TaskType, RiskTier
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.execution.resource_limits import SandboxResourceLimits
from automaintainer.execution.container_runtime import ContainerSandboxRuntime
from automaintainer.execution.gvisor_runtime import MicroVMSandboxRuntime
from automaintainer.execution.sandbox_factory import get_sandbox_runtime
from automaintainer.data.object_storage import ObjectStorageService, S3StorageBackend, GCSStorageBackend
from automaintainer.core.secrets_manager import UnifiedSecretResolver, decrypt_kms_envelope
from automaintainer.config import Settings, get_settings



def test_ast_patcher_validates_python_syntax():
    valid_python = "def add(a: int, b: int) -> int:\n    return a + b\n"
    is_valid, err = AstPatcher.validate_content("src/calculator.py", valid_python)
    assert is_valid is True
    assert err is None

    broken_python = "def add(a, b\n    return a +"
    is_valid, err = AstPatcher.validate_content("src/calculator.py", broken_python)
    assert is_valid is False
    assert "SyntaxError" in err


def test_ast_patcher_validates_yaml_and_toml():
    valid_yaml = "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    is_valid, err = AstPatcher.validate_content(".github/workflows/ci.yml", valid_yaml)
    assert is_valid is True

    broken_yaml = "name: CI\n  bad_indent:\n- mismatch"
    is_valid, err = AstPatcher.validate_content(".github/workflows/ci.yml", broken_yaml)
    assert is_valid is False

    valid_toml = '[project]\nname = "automaintainer"\nversion = "1.0.0"\n'
    is_valid, err = AstPatcher.validate_content("pyproject.toml", valid_toml)
    assert is_valid is True


def test_minimal_patcher_rejects_ast_violating_edits():
    patcher = MinimalPatcher()
    original_contents = {"src/app.py": "def main():\n    pass\n"}

    bad_plan = PlannerOutput(
        objective="Introduce broken code",
        task_type="test_repair",
        confidence=0.9,
        target_paths=["src/app.py"],
        proposed_edits=[
            ProposedEdit(
                path="src/app.py",
                operation="full_replace",
                rationale="syntax error",
                new_content="def broken_syntax(:\n"
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[],
        risk_tier=RiskTier.R2,
        requires_human_approval=False
    )

    result = patcher.apply(bad_plan, original_contents)
    assert result.success is False
    assert any("AST validation error" in e for e in result.errors)



@pytest.mark.asyncio
async def test_container_runtime_injects_egress_proxy_env():
    runtime = ContainerSandboxRuntime(use_docker=False)
    limits = SandboxResourceLimits(allow_network_egress=True)

    captured_env = {}

    async def mock_subprocess(*cmd, **kwargs):
        nonlocal captured_env
        captured_env = kwargs.get("env", {})
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = MagicMock()

        async def _comm():
            return b"ok", b""

        proc.communicate = _comm
        return proc

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess):
        ws = await runtime.prepare_workspace(repo_url="", commit_sha="")
        try:
            res = await runtime.execute_command(
                workspace_id=ws,
                command=["curl", "https://api.github.com"],
                limits=limits
            )
            assert res.exit_code == 0
            assert "HTTP_PROXY" in captured_env
            assert "HTTPS_PROXY" in captured_env
            assert "ALL_PROXY" in captured_env
            assert "http://127.0.0.1:8080" in captured_env["HTTP_PROXY"]
        finally:
            await runtime.destroy_workspace(ws)


def test_docker_container_flags_contain_egress_proxy():
    runtime = ContainerSandboxRuntime(use_docker=True)
    limits = SandboxResourceLimits(allow_network_egress=True)
    flags = runtime.get_container_flags(limits)
    assert "--network" in flags
    idx = flags.index("--network")
    assert flags[idx + 1] == "bridge"



def test_object_storage_presigned_urls_and_tenant_keys(tmp_path):
    storage = ObjectStorageService(storage_root=str(tmp_path))

    tenant_key = storage.format_tenant_key("tenant_acme", "sess_123", "diff.patch")
    assert tenant_key == "tenants/tenant_acme/sess_123/diff.patch"

    art = storage.put_object(tenant_key, b"diff content here")
    assert art.size_bytes == len(b"diff content here")

    presigned = storage.generate_presigned_url(tenant_key, expires_in_seconds=1800)
    assert "file:///" in presigned or "http" in presigned


def test_s3_storage_kms_encryption_parameters():
    mock_boto3 = MagicMock()
    mock_s3_client = MagicMock()
    mock_boto3.client.return_value = mock_s3_client

    with patch.dict("sys.modules", {"boto3": mock_boto3}):
        backend = S3StorageBackend(
            bucket_name="my-kms-bucket",
            kms_key_id="arn:aws:kms:us-east-1:123456789:key/abc-123"
        )
        backend._s3_client = mock_s3_client

        mock_s3_client.generate_presigned_url.return_value = "https://my-kms-bucket.s3.amazonaws.com/test?signed=true"
        url = backend.generate_presigned_url("test_key", expires_in_seconds=3600)
        assert url == "https://my-kms-bucket.s3.amazonaws.com/test?signed=true"

        backend.upload("test_key", b"sensitive data")
        mock_s3_client.put_object.assert_called_once()
        _, kwargs = mock_s3_client.put_object.call_args
        assert kwargs["ServerSideEncryption"] == "aws:kms"
        assert kwargs["SSEKMSKeyId"] == "arn:aws:kms:us-east-1:123456789:key/abc-123"



def test_unified_secret_resolver_uri_schemes():
    resolver = UnifiedSecretResolver()

    mock_vault_client = MagicMock()
    mock_vault_client.get_secret.return_value = "vault_private_rsa_key_contents"

    with patch("automaintainer.core.secrets_manager.VaultSecretClient", return_value=mock_vault_client):
        val = resolver.resolve("vault://secret/data/github-app#private_key")
        assert val == "vault_private_rsa_key_contents"
        mock_vault_client.get_secret.assert_called_with("secret/data/github-app", key_field="private_key")

    mock_aws_client = MagicMock()
    mock_aws_client.get_secret.return_value = json.dumps({"app_token": "aws_resolved_token_123"})

    with patch("automaintainer.core.secrets_manager.AWSSecretsManagerClient", return_value=mock_aws_client):
        val = resolver.resolve("aws-secrets://production/creds#app_token")
        assert val == "aws_resolved_token_123"


def test_settings_dynamic_secret_resolution():
    settings = Settings(
        GITHUB_WEBHOOK_SECRET="vault://secret/data/webhook#secret",
    )
    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = "high_entropy_vault_resolved_secret_32chars"

    with patch("automaintainer.config.get_secret_resolver", return_value=mock_resolver):
        resolved = settings.resolve_dynamic_secret("GITHUB_WEBHOOK_SECRET", settings.GITHUB_WEBHOOK_SECRET)
        assert resolved == "high_entropy_vault_resolved_secret_32chars"



def test_sandbox_factory_selection():
    runtime_jail = get_sandbox_runtime(override_backend="subprocess_jail")
    assert isinstance(runtime_jail, ContainerSandboxRuntime)
    assert runtime_jail.use_docker is False

    runtime_container = get_sandbox_runtime(override_backend="container")
    assert isinstance(runtime_container, ContainerSandboxRuntime)

    runtime_gvisor = get_sandbox_runtime(override_backend="gvisor")
    assert isinstance(runtime_gvisor, ContainerSandboxRuntime)


def test_gvisor_runtime_flags():
    gvisor = MicroVMSandboxRuntime(use_gvisor=True)
    limits = SandboxResourceLimits(cpu_cores=4.0, memory_mb=4096, max_pids=128)
    flags = gvisor.get_container_flags(limits)
    assert "--runtime=runsc" in flags
    assert "--cap-drop=ALL" in flags
    assert "--read-only" in flags
    assert "--cpus=4.0" in flags
    assert "--memory=4096m" in flags
    assert "--pids-limit=128" in flags



from automaintainer.agents.planner import InferenceExhaustedError

@pytest.mark.asyncio
async def test_planner_raises_inference_exhausted_when_no_gateway():
    planner = MaintenancePlanner(inference_gateway=None)
    opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        evidence=["actions/checkout@v3 -> v4"],
        target_paths=[".github/workflows/ci.yml"],
        risk_tier=RiskTier.R1,
        confidence=0.95,
        validation_recipe=["echo ok"],
        summary="Bump checkout action",
    )
    with pytest.raises(InferenceExhaustedError) as exc_info:
        await planner.plan(opp)
    assert "No inference gateway configured" in str(exc_info.value)


@pytest.mark.asyncio
async def test_planner_raises_inference_exhausted_when_keys_depleted():
    mock_pool = MagicMock()
    mock_pool.select_healthy_key.return_value = None
    mock_gateway = MagicMock()
    mock_gateway.key_pool = mock_pool

    planner = MaintenancePlanner(inference_gateway=mock_gateway)
    opp = DetectedOpportunity(
        task_type=TaskType.PACKAGE_METADATA,
        evidence=["missing license"],
        target_paths=["pyproject.toml"],
        risk_tier=RiskTier.R1,
        confidence=0.9,
        validation_recipe=["echo ok"],
        summary="Add license",
    )
    with pytest.raises(InferenceExhaustedError) as exc_info:
        await planner.plan(opp)
    assert "exhausted or in cooldown" in str(exc_info.value)


@pytest.mark.asyncio
async def test_planner_routes_all_tasks_through_llm_gateway():
    mock_pool = MagicMock()
    mock_pool.select_healthy_key.return_value = "gsk_prod_key_123"
    mock_gateway = MagicMock()
    mock_gateway.key_pool = mock_pool

    expected_output = PlannerOutput(
        objective="Bump actions/checkout",
        task_type="github_action_update",
        confidence=0.99,
        target_paths=[".github/workflows/ci.yml"],
        proposed_edits=[
            ProposedEdit(
                path=".github/workflows/ci.yml",
                operation="full_replace",
                rationale="LLM synthesized workflow bump",
                new_content="name: CI\n"
            )
        ],
        explicitly_unchanged=[],
        validation_steps=[ValidationStep(command="yamllint .", reason="syntax", expected_outcome="ok")],
        risk_tier=RiskTier.R1,
        requires_human_approval=False
    )
    mock_gateway.complete = MagicMock()
    async def _async_complete(*args, **kwargs):
        return '{"dummy": "json"}'
    mock_gateway.complete.side_effect = _async_complete
    mock_gateway.parse_structured_output.return_value = expected_output

    planner = MaintenancePlanner(inference_gateway=mock_gateway)
    opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        evidence=["actions/checkout@v3 -> v4"],
        target_paths=[".github/workflows/ci.yml"],
        risk_tier=RiskTier.R1,
        confidence=0.95,
        validation_recipe=["yamllint ."],
        summary="Bump checkout action",
    )

    plan = await planner.plan(opp)
    assert plan.objective == "Bump actions/checkout"
    assert plan.proposed_edits[0].rationale == "LLM synthesized workflow bump"
    mock_gateway.complete.assert_called_once()



from automaintainer.core.secrets_manager import VaultSecretClient, SecretRotationManager

def test_vault_approle_and_kubernetes_auth():
    vault = VaultSecretClient(vault_url="https://vault.internal:8200", vault_token=None)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"auth": {"client_token": "s.vault_approle_token_123"}}

    with patch("httpx.Client") as mock_client_cls:
        client_inst = MagicMock()
        client_inst.__enter__.return_value = client_inst
        client_inst.post.return_value = mock_resp
        mock_client_cls.return_value = client_inst

        token = vault.login_approle("role_123", "secret_abc")
        assert token == "s.vault_approle_token_123"
        assert vault.vault_token == "s.vault_approle_token_123"

    mock_k8s_resp = MagicMock()
    mock_k8s_resp.status_code = 200
    mock_k8s_resp.json.return_value = {"auth": {"client_token": "s.vault_k8s_token_456"}}

    with patch("httpx.Client") as mock_client_cls:
        client_inst = MagicMock()
        client_inst.__enter__.return_value = client_inst
        client_inst.post.return_value = mock_k8s_resp
        mock_client_cls.return_value = client_inst

        token = vault.login_kubernetes("automaintainer-role", jwt_token="eyJhbGciOiJSUzI1NiIs...")
        assert token == "s.vault_k8s_token_456"
        assert vault.vault_token == "s.vault_k8s_token_456"


def test_secret_rotation_manager():
    mgr = SecretRotationManager()
    mgr.track_secret("production/db_password", "v1", max_age_days=30)
    assert mgr.needs_rotation("production/db_password") is False

    mgr._secret_metadata["production/db_password"]["registered_at"] -= (31 * 86400)
    assert mgr.needs_rotation("production/db_password") is True



def test_bucket_lifecycle_configuration():
    mock_s3 = MagicMock()
    s3_backend = S3StorageBackend(bucket_name="prod-artifacts")
    s3_backend._s3_client = mock_s3

    ok = s3_backend.configure_bucket_lifecycle(expiration_days=90, glacier_transition_days=30)
    assert ok is True
    mock_s3.put_bucket_lifecycle_configuration.assert_called_once()
    call_args = mock_s3.put_bucket_lifecycle_configuration.call_args[1]
    assert call_args["Bucket"] == "prod-artifacts"
    assert call_args["LifecycleConfiguration"]["Rules"][0]["Transitions"][0]["StorageClass"] == "GLACIER"

    mock_bucket = MagicMock()
    mock_bucket.lifecycle_rules = []
    gcs_backend = GCSStorageBackend(bucket_name="prod-gcs-artifacts")
    gcs_backend._bucket = mock_bucket

    ok = gcs_backend.configure_bucket_lifecycle(expiration_days=60, nearline_transition_days=15)
    assert ok is True
    assert len(mock_bucket.lifecycle_rules) >= 2



from automaintainer.execution.sandbox_factory import is_gvisor_supported

def test_gvisor_capability_auto_detection():
    with patch("shutil.which", return_value=None):
        assert is_gvisor_supported() is False

    with patch("shutil.which", return_value="/usr/bin/docker"):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"runc": {"path": "runc"}, "runsc": {"path": "/usr/bin/runsc"}}'
        with patch("subprocess.run", return_value=mock_proc):
            assert is_gvisor_supported() is True

    with patch("shutil.which", return_value="/usr/bin/docker"):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"runc": {"path": "runc"}}'
        with patch("subprocess.run", return_value=mock_proc):
            assert is_gvisor_supported() is False



from automaintainer.apps.worker.daemon import WorkerDaemon
from automaintainer.queue.redis_queue import PartitionedLeasedQueue
from automaintainer.data.database import get_db_manager
from automaintainer.data.tables import SessionRecord, RepositoryRecord, PullRequestRecord, PlanRecord
from automaintainer.core.models import SessionState
from sqlalchemy import select

@pytest.mark.asyncio
async def test_worker_daemon_publishes_pr_on_validation_pass(tmp_path):
    db_mgr = get_db_manager()
    await db_mgr.init_models()

    session_id = "sess_worker_pr_pass_1"
    async with db_mgr.get_session() as db:
        repo = RepositoryRecord(
            id=101,
            github_repo_id=202,
            owner="testowner",
            name="testrepo",
            default_branch="main",
            installation_id=999,
        )
        db.add(repo)
        sess = SessionRecord(
            id=session_id,
            repository_id=101,
            state=SessionState.WORKING.value,
            version=1,
            risk_tier="R1",
        )
        db.add(sess)
        plan_rec = PlanRecord(
            id="plan_test_101",
            session_id=session_id,
            version=1,
            plan_hash="hash123",
            plan_json={
                "objective": "Bump package metadata",
                "task_type": "package_metadata",
                "confidence": 0.99,
                "target_paths": ["pyproject.toml"],
                "proposed_edits": [
                    {
                        "path": "pyproject.toml",
                        "operation": "full_replace",
                        "rationale": "bump version",
                        "new_content": '[project]\nname = "testrepo"\nversion = "1.0.1"\n'
                    }
                ],
                "explicitly_unchanged": [],
                "validation_steps": [],
                "risk_tier": "R1",
                "requires_human_approval": False,
            }
        )
        db.add(plan_rec)
        await db.commit()

    queue = PartitionedLeasedQueue()
    queue.enqueue("patch", session_id, "patch_task", {"target_paths": ["pyproject.toml"], "task_type": "package_metadata"})

    mock_sandbox = MagicMock()
    ws_dir = str(tmp_path / "workspace")
    os.makedirs(ws_dir, exist_ok=True)
    with open(os.path.join(ws_dir, "pyproject.toml"), "w") as f:
        f.write('[project]\nname = "testrepo"\nversion = "1.0.0"\n')

    async def _prep(*args, **kwargs):
        return ws_dir
    async def _destroy(*args, **kwargs):
        pass

    mock_sandbox.prepare_workspace = _prep
    mock_sandbox.destroy_workspace = _destroy

    mock_executor = MagicMock()
    async def _exec_mut(intent):
        if intent.operation.value == "create_commit":
            return {"commit_sha": "commit_sha_123", "parent_sha": "parent_sha_456"}
        elif intent.operation.value == "open_pr":
            return {"number": 42, "html_url": "https://github.com/testowner/testrepo/pull/42"}
        return {}
    mock_executor.execute_mutation = _exec_mut

    with patch("automaintainer.apps.worker.daemon.GitHubExecutor", return_value=mock_executor), \
         patch("automaintainer.apps.worker.daemon.InstallationTokenBroker") as mock_broker_cls:
        mock_broker = MagicMock()
        async def _get_tok(*args, **kwargs):
            return "ghs_mock_installation_token"
        mock_broker.get_installation_token = _get_tok
        mock_broker_cls.return_value = mock_broker

        daemon = WorkerDaemon(worker_id="test_worker_pr", queue=queue, sandbox=mock_sandbox)
        await daemon.start(poll_interval=0.01, max_iterations=1)

    async with db_mgr.get_session() as db:
        sess_rec = await db.get(SessionRecord, session_id)
        assert sess_rec.state == SessionState.MAINTAINER_REVIEW.value
        assert sess_rec.pr_number == 42
        assert sess_rec.branch_name == f"automaintainer/{session_id}"

        pr_stmt = select(PullRequestRecord).where(PullRequestRecord.session_id == session_id)
        pr_res = await db.execute(pr_stmt)
        pr_rec = pr_res.scalars().first()
        assert pr_rec is not None
        assert pr_rec.number == 42
        assert pr_rec.head_sha == "commit_sha_123"
        assert pr_rec.base_sha == "parent_sha_456"
        assert "pull/42" in pr_rec.url

