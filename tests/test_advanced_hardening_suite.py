import pytest
from automaintainer.execution.network_security import ControlledEgressFilter, SSRFSecurityViolation
from automaintainer.data.object_storage import ObjectStorageService
from automaintainer.core.reproducibility import ReproducibilityManifest
from automaintainer.app.auth import AuthUser, UserRole, create_access_token
from automaintainer.github.workflow_installer import WorkflowInstallerService, WorkflowInstallerError
from automaintainer.discovery.candidate_crawler import CandidateCrawler
from automaintainer.inference.rotation_runbook import GroqRotationRunbook
from automaintainer.inference.key_pool import KeyPoolRegistry, GroqKeyRecord

def test_ssrf_filter_blocks_cloud_metadata_and_loopback():
    assert ControlledEgressFilter.is_ip_forbidden("169.254.169.254") is True
    assert ControlledEgressFilter.is_ip_forbidden("127.0.0.1") is True
    assert ControlledEgressFilter.is_ip_forbidden("10.0.1.5") is True
    assert ControlledEgressFilter.is_ip_forbidden("192.168.1.1") is True

    allowed, reason = ControlledEgressFilter.validate_destination("http://169.254.169.254/latest/meta-data")
    assert allowed is False

    allowed_pkg, _ = ControlledEgressFilter.validate_destination("https://pypi.org/simple")
    assert allowed_pkg is True

def test_object_storage_integrity_and_retention(tmp_path):
    storage = ObjectStorageService(storage_root=str(tmp_path))
    content = b"sample diff and test log payload"
    art = storage.put_object("session_1/diff.patch", content, ttl_days=10)

    assert art.size_bytes == len(content)
    assert len(art.sha256) == 64

    fetched = storage.get_object("session_1/diff.patch")
    assert fetched == content

def test_reproducibility_manifest_generates_valid_hash():
    manifest = ReproducibilityManifest(
        session_id="sess_manifest_1",
        repo_sha="a1b2c3d4e5",
        base_image_digest="sha256:4f3b1234567890abcdef",
        model_id="llama-3.3-70b-versatile",
        patch_hash="sha256:11223344556677889900",
        toolchain_versions={"python": "3.12.3", "pip": "24.1"}
    )
    m_hash = manifest.compute_manifest_hash()
    assert len(m_hash) == 64

def test_workflow_installer_self_protection():
    assert WorkflowInstallerService.is_self_modification(".github/workflows/automaintainer.yml") is True
    assert WorkflowInstallerService.is_self_modification(".github/automaintainer.yml") is True
    assert WorkflowInstallerService.is_self_modification("src/main.py") is False

def test_groq_rotation_runbook_lifecycle():
    pool = KeyPoolRegistry()
    old_key = GroqKeyRecord(key_id="old_k", organization_id="org1", project_id="p1", secret_ref="ref/old")
    pool.register_key(old_key)

    runbook = GroqRotationRunbook(pool)
    res = runbook.execute_rotation(
        old_key_id="old_k",
        new_key_id="new_k",
        project_id="p1",
        organization_id="org1",
        secret_ref="ref/new"
    )

    assert res["status"] == "rotation_completed"
    assert pool.select_healthy_key().key_id == "new_k"
