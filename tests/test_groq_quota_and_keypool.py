import pytest
from automaintainer.inference.key_pool import KeyPoolRegistry, GroqKeyRecord, KeyStatus
from automaintainer.inference.quota_manager import OrgQuotaManager

def test_key_pool_selection_and_draining():
    pool = KeyPoolRegistry()
    
    key1 = GroqKeyRecord(
        key_id="key_1",
        organization_id="org_alpha",
        project_id="proj_prod",
        secret_ref="secrets/groq/key1"
    )
    key2 = GroqKeyRecord(
        key_id="key_2",
        organization_id="org_alpha",
        project_id="proj_prod",
        secret_ref="secrets/groq/key2"
    )
    
    pool.register_key(key1)
    pool.register_key(key2)
    
    selected = pool.select_healthy_key(project_id="proj_prod")
    assert selected is not None
    assert selected.key_id in ["key_1", "key_2"]
    
    pool.mark_draining("key_1")
    assert pool.select_healthy_key(project_id="proj_prod").key_id == "key_2"

def test_org_level_quota_limits_prevent_unbounded_calls():
    quota_mgr = OrgQuotaManager()
    quota_mgr.init_org_limits(org_id="org_alpha", rpm_limit=2, tpm_limit=5000)
    
    assert quota_mgr.check_and_reserve(org_id="org_alpha", estimated_tokens=1000) is True
    assert quota_mgr.check_and_reserve(org_id="org_alpha", estimated_tokens=1000) is True
    assert quota_mgr.check_and_reserve(org_id="org_alpha", estimated_tokens=1000) is False
