"""
Unit tests for the 4 production gap fixes:
1. AI Offline / Rate-limited -> Pause & re-queue task instead of regex fallback.
2. Multi-language AST verification with Tree-sitter integration & graceful fallbacks.
3. Cloud KMS & Hardware HSM external rotation driver (AWS/GCP/Vault).
4. Cloud Object Storage wiring (S3/GCS) & proper default directories.
"""
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from automaintainer.core.models import SessionState, RiskTier, TaskType
from automaintainer.data.tables import SessionRecord
from automaintainer.agents.planner import MaintenancePlanner, InferenceExhaustedError
from automaintainer.agents.ast_patcher import AstPatcher, _try_tree_sitter, _get_tree_sitter_parser
from automaintainer.core.session_orchestrator import SessionOrchestrator
from automaintainer.discovery.opportunity_detectors import DetectedOpportunity
from automaintainer.core.secrets_manager import (
    KmsRotationDriver,
    SecretRotationManager,
    UnifiedSecretResolver,
    get_secret_resolver
)
from automaintainer.data.object_storage import (
    ObjectStorageService,
    get_object_storage,
    S3StorageBackend,
    GCSStorageBackend
)



@pytest.mark.asyncio
async def test_planner_raises_inference_exhausted_when_gateway_missing():
    """Verify planner raises InferenceExhaustedError when no gateway is configured."""
    planner = MaintenancePlanner(inference_gateway=None)
    opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        risk_tier=RiskTier.R1,
        confidence=0.9,
        summary="Update action",
        target_paths=[".github/workflows/ci.yml"],
        evidence=["actions/checkout@v2 is outdated"],
        validation_recipe=[],
    )
    with pytest.raises(InferenceExhaustedError) as exc_info:
        await planner.plan(opp)
    assert "No inference gateway configured" in str(exc_info.value)


@pytest.mark.asyncio
async def test_orchestrator_requeues_when_inference_exhausted():
    """Verify orchestrator pauses and re-queues session on InferenceExhaustedError."""
    fake_db = AsyncMock()
    fake_db.flush = AsyncMock()

    mock_planner = MagicMock()
    mock_planner.plan = AsyncMock(side_effect=InferenceExhaustedError("All inference keys in cooldown"))

    mock_queue = MagicMock()
    mock_queue.enqueue = MagicMock(return_value=MagicMock())

    orchestrator = SessionOrchestrator(db=fake_db, planner=mock_planner)
    orchestrator._audit.record = AsyncMock()

    record = SessionRecord()
    record.id = "sess_ai_offline_1"
    record.state = SessionState.ANALYZING.value
    record.task_type = "github_action_update"
    record.metadata = {}

    opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        risk_tier=RiskTier.R1,
        confidence=0.9,
        summary="Update action",
        target_paths=[".github/workflows/ci.yml"],
        evidence=["actions/checkout@v2 is outdated"],
        validation_recipe=[],
    )

    with patch("automaintainer.core.session_orchestrator.get_partitioned_queue", return_value=mock_queue):
        res = await orchestrator._transition_to_planning(record, opp)

    assert res.state == SessionState.ANALYZING.value
    assert record.metadata["requeue_count"] == 1
    assert record.metadata["requeue_reason"] == "inference_exhausted"
    assert record.metadata["requeue_after"] > time.time()
    mock_queue.enqueue.assert_called_once()
    args, kwargs = mock_queue.enqueue.call_args
    assert kwargs.get("queue_name") == "analysis" or args[0] == "analysis"


@pytest.mark.asyncio
async def test_orchestrator_transitions_to_safety_stop_after_max_requeues():
    """Verify orchestrator stops at SAFETY_STOP after 5 failed AI retries."""
    fake_db = AsyncMock()
    fake_db.flush = AsyncMock()

    mock_planner = MagicMock()
    mock_planner.plan = AsyncMock(side_effect=InferenceExhaustedError("Quota exceeded"))

    orchestrator = SessionOrchestrator(db=fake_db, planner=mock_planner)
    orchestrator._transition = AsyncMock()

    record = SessionRecord()
    record.id = "sess_ai_offline_2"
    record.state = SessionState.ANALYZING.value
    record.metadata = {"requeue_count": 5}

    opp = DetectedOpportunity(
        task_type=TaskType.GITHUB_ACTION_UPDATE,
        risk_tier=RiskTier.R1,
        confidence=0.9,
        summary="Update action",
        target_paths=[".github/workflows/ci.yml"],
        evidence=["actions/checkout@v2 is outdated"],
        validation_recipe=[],
    )

    await orchestrator._transition_to_planning(record, opp)

    orchestrator._transition.assert_called_once()
    _, target_state, details = orchestrator._transition.call_args[0]
    assert target_state == SessionState.SAFETY_STOP
    assert "after 5 retries" in details.get("reason", "")



def test_ast_patcher_tree_sitter_graceful_fallback():
    """Verify that when tree-sitter is uninstalled, validation falls back gracefully."""
    with patch("automaintainer.agents.ast_patcher._get_tree_sitter_parser", return_value=None):
        valid, err = AstPatcher.validate_content("main.go", "package main\n\nfunc main() {}\n")
        assert valid is True
        assert err is None


def test_ast_patcher_tree_sitter_detects_error():
    """Verify that Tree-sitter error node is detected when Tree-sitter parser is present."""
    mock_error_node = MagicMock()
    mock_error_node.is_error = True
    mock_error_node.type = "ERROR"
    mock_error_node.start_point = (4, 2)
    mock_error_node.children = []

    mock_root = MagicMock()
    mock_root.has_error = True
    mock_root.is_error = False
    mock_root.is_missing = False
    mock_root.type = "source_file"
    mock_root.children = [mock_error_node]

    mock_tree = MagicMock()
    mock_tree.root_node = mock_root

    mock_parser = MagicMock()
    mock_parser.parse.return_value = mock_tree

    with patch("automaintainer.agents.ast_patcher._get_tree_sitter_parser", return_value=mock_parser):
        valid, err = _try_tree_sitter("broken code here", "go")
        assert valid is False
        assert "Tree-sitter Go AST SyntaxError at line 5, col 3" in err


def test_ast_patcher_valid_go_and_rust_delimiters():
    """Verify valid Go and Rust syntax passes structural delimiter checks."""
    go_code = """package main
import "fmt"
func main() {
    fmt.Println("Hello AutoMaintainer")
}
"""
    valid, err = AstPatcher.validate_content("service.go", go_code)
    assert valid is True

    rust_code = """pub fn compute() -> i32 {
    let x = 42;
    x * 2
}
"""
    valid, err = AstPatcher.validate_content("lib.rs", rust_code)
    assert valid is True



def test_kms_rotation_driver_aws_rotate():
    """Verify KMS rotation driver calls AWS Secrets Manager put_secret_value."""
    mock_boto = MagicMock()
    mock_sm = MagicMock()
    mock_boto.client.return_value = mock_sm

    driver = KmsRotationDriver(provider="aws", region_or_project="us-west-2", kms_key_id="alias/my-key")

    with patch.dict("sys.modules", {"boto3": mock_boto}):
        success = driver.rotate_secret("github_webhook_secret", "super_secret_new_hmac_12345678")

    assert success is True
    mock_sm.put_secret_value.assert_called_once()
    _, kwargs = mock_sm.put_secret_value.call_args
    assert kwargs["SecretId"] == "github_webhook_secret"
    assert kwargs["SecretString"] == "super_secret_new_hmac_12345678"


def test_kms_rotation_driver_vault_rotate():
    """Verify KMS rotation driver posts to HashiCorp Vault KV endpoint."""
    driver = KmsRotationDriver(
        provider="vault",
        vault_url="https://vault.corp:8200",
        vault_token="s.testtoken123"
    )

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_client.post.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__ = MagicMock()

    with patch("httpx.Client", return_value=mock_client):
        success = driver.rotate_secret("automaintainer/github_key", "-----BEGIN RSA PRIVATE KEY-----...")

    assert success is True
    mock_client.post.assert_called_once()
    call_url = mock_client.post.call_args[0][0]
    assert "automaintainer/github_key" in call_url


def test_secret_rotation_manager_tracks_and_rotates():
    """Verify SecretRotationManager rotates via driver and tracks age."""
    mock_driver = MagicMock()
    mock_driver.rotate_secret.return_value = True

    mgr = SecretRotationManager(driver=mock_driver)
    mgr.track_secret("webhook_secret", "v1", max_age_days=30)
    assert mgr.needs_rotation("webhook_secret") is False

    mgr._secret_metadata["webhook_secret"]["registered_at"] = time.time() - (31 * 86400)
    assert mgr.needs_rotation("webhook_secret") is True

    ok = mgr.rotate_secret("webhook_secret", "new_secret_val", new_version="v2")
    assert ok is True
    assert mgr._secret_metadata["webhook_secret"]["version"] == "v2"
    assert mgr.needs_rotation("webhook_secret") is False


def test_get_secret_resolver_returns_unified_resolver():
    """Verify get_secret_resolver returns instance of UnifiedSecretResolver."""
    resolver = get_secret_resolver()
    assert isinstance(resolver, UnifiedSecretResolver)



def test_object_storage_default_path_is_relative():
    """Verify ObjectStorageService does not use hardcoded absolute Windows path."""
    svc = ObjectStorageService(storage_root=None)
    assert "f:/automaintainer_artifacts" not in svc.storage_root.replace("\\", "/")
    assert "automaintainer_artifacts" in svc.storage_root


def test_get_object_storage_wires_gcs_when_configured():
    """Verify get_object_storage initializes GCSStorageBackend when GCS_BUCKET_NAME is set."""
    mock_settings = MagicMock()
    mock_settings.S3_BUCKET_NAME = None
    mock_settings.GCS_BUCKET_NAME = "automaintainer-prod-artifacts"
    mock_settings.GCS_PROJECT_ID = "gcp-maintainer-prod"
    mock_settings.GCS_KMS_KEY_NAME = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
    mock_settings.STORAGE_ROOT = "./test_artifacts"

    with patch("automaintainer.config.get_settings", return_value=mock_settings), \
         patch("automaintainer.data.object_storage._storage_service", None), \
         patch("automaintainer.data.object_storage.GCSStorageBackend") as mock_gcs_cls:

        storage = get_object_storage()
        assert storage is not None
        mock_gcs_cls.assert_called_once_with(
            bucket_name="automaintainer-prod-artifacts",
            project_id="gcp-maintainer-prod",
            kms_key_name="projects/p/locations/l/keyRings/r/cryptoKeys/k"
        )
