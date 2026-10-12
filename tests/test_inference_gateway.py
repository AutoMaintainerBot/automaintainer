import pytest
from automaintainer.inference.gateway import GroqInferenceGateway, InferenceGatewayError
from automaintainer.inference.schemas import PlannerOutput, ReviewerOutput
from automaintainer.inference.key_pool import KeyPoolRegistry
from automaintainer.inference.quota_manager import OrgQuotaManager
from automaintainer.core.models import RiskTier

def test_inference_gateway_strips_markdown_fences_and_parses():
    gw = GroqInferenceGateway(key_pool=KeyPoolRegistry(), quota_manager=OrgQuotaManager())
    raw_response = """
    ```json
    {
        "objective": "Bump actions/checkout from v3 to v4",
        "task_type": "github_action_update",
        "confidence": 0.95,
        "target_paths": [".github/workflows/ci.yml"],
        "proposed_edits": [
            {
                "path": ".github/workflows/ci.yml",
                "operation": "modify",
                "rationale": "Use Node 20 runner"
            }
        ],
        "validation_steps": [
            {
                "command": "yamllint .github/workflows/ci.yml",
                "reason": "Validate syntax",
                "expected_outcome": "exit 0"
            }
        ],
        "risk_tier": "R2"
    }
    ```
    """

    plan = gw.parse_structured_output(raw_response, PlannerOutput)
    assert plan.objective == "Bump actions/checkout from v3 to v4"
    assert plan.confidence == 0.95
    assert plan.target_paths == [".github/workflows/ci.yml"]
    assert plan.risk_tier == RiskTier.R2

    intent = gw.build_mutation_intent_from_plan(
        session_id="sess_123",
        repository="owner/repo",
        branch="automaintainer/update-ci",
        plan=plan
    )
    assert intent.session_id == "sess_123"
    assert intent.target_paths == [".github/workflows/ci.yml"]
    assert intent.risk == RiskTier.R2

def test_inference_gateway_rejects_malformed_json():
    gw = GroqInferenceGateway(key_pool=KeyPoolRegistry(), quota_manager=OrgQuotaManager())
    invalid_raw = "Sorry, I cannot help with this code."

    with pytest.raises(InferenceGatewayError):
        gw.parse_structured_output(invalid_raw, PlannerOutput)
