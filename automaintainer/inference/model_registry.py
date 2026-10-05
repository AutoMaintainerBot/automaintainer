import time
from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field

class ModelLifecycleState(str, Enum):
    PREVIEW = "PREVIEW"
    PRODUCTION = "PRODUCTION"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"
    QUARANTINED = "QUARANTINED"

class ModelMetadata(BaseModel):
    model_id: str
    lifecycle_state: ModelLifecycleState = ModelLifecycleState.PRODUCTION
    context_window: int = 128000
    recommended_fallback_id: Optional[str] = None
    deprecation_date: Optional[str] = None
    input_cost_per_m: float = 0.59
    output_cost_per_m: float = 0.79

class ModelRegistry:
    """
    Model Lifecycle & Deprecation Management:
    Tracks model lifecycle states, prevents hardcoded model churn,
    and maps automated fallback targets when a model is deprecated.
    """

    def __init__(self):
        self._models: Dict[str, ModelMetadata] = {
            "llama-3.3-70b-versatile": ModelMetadata(
                model_id="llama-3.3-70b-versatile",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                recommended_fallback_id="llama-3.1-70b-versatile"
            ),
            "llama-3.1-8b-instant": ModelMetadata(
                model_id="llama-3.1-8b-instant",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                recommended_fallback_id="llama-3.2-3b-preview"
            ),
            "llama-3.1-70b-versatile": ModelMetadata(
                model_id="llama-3.1-70b-versatile",
                lifecycle_state=ModelLifecycleState.PRODUCTION
            ),
            "mixtral-8x7b-32768": ModelMetadata(
                model_id="mixtral-8x7b-32768",
                lifecycle_state=ModelLifecycleState.DEPRECATED,
                recommended_fallback_id="llama-3.3-70b-versatile",
                deprecation_date="2026-03-01"
            ),
            # Cerebras Models
            "llama3.3-70b": ModelMetadata(
                model_id="llama3.3-70b",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                context_window=128000,
            ),
            "llama3.1-8b": ModelMetadata(
                model_id="llama3.1-8b",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                context_window=128000,
            ),
            # Google Gemini Models
            "gemini-2.0-flash": ModelMetadata(
                model_id="gemini-2.0-flash",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                context_window=1000000,
            ),
            "gemini-2.5-flash": ModelMetadata(
                model_id="gemini-2.5-flash",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                context_window=1000000,
            ),
            "gemini-1.5-pro": ModelMetadata(
                model_id="gemini-1.5-pro",
                lifecycle_state=ModelLifecycleState.PRODUCTION,
                context_window=2000000,
            ),
        }

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        return self._models.get(model_id)

    def resolve_active_model(self, requested_id: str) -> str:
        """
        Resolves model to an active production model.
        If DEPRECATED or RETIRED, cleanly returns its recommended fallback.
        """
        model = self._models.get(requested_id)
        if not model:
            return requested_id

        if model.lifecycle_state in (ModelLifecycleState.DEPRECATED, ModelLifecycleState.RETIRED):
            if model.recommended_fallback_id and model.recommended_fallback_id in self._models:
                return self._models[model.recommended_fallback_id].model_id

        return model.model_id

    def list_models(self) -> List[ModelMetadata]:
        return list(self._models.values())

    def update_lifecycle(self, model_id: str, state: ModelLifecycleState, fallback: Optional[str] = None):
        if model_id in self._models:
            self._models[model_id].lifecycle_state = state
            if fallback:
                self._models[model_id].recommended_fallback_id = fallback
        else:
            self._models[model_id] = ModelMetadata(
                model_id=model_id,
                lifecycle_state=state,
                recommended_fallback_id=fallback
            )


PROVIDER_MODEL_MAP = {
    "planner": {
        "cerebras": "gpt-oss-120b",
        "groq": "openai/gpt-oss-120b",
        "google": "gemini-3.8-flash",
    },
    "fast": {
        "cerebras": "gpt-oss-120b",
        "groq": "openai/gpt-oss-20b",
        "google": "gemini-3.8-flash",
    }
}


def resolve_model_for_provider(requested_model: str, provider: str) -> str:
    """
    Dynamically maps requested model to the best matching active model on target provider.
    Handles cross-provider failover:
      - If requested on Cerebras: maps to active Cerebras models (gpt-oss-120b, qwen-3.8-27b)
      - If requested on Groq: maps to active Groq models (openai/gpt-oss-120b, openai/gpt-oss-20b, qwen/qwen3.8-27b)
      - If requested on Google: maps to gemini-3.8-flash
    """
    prov = provider.lower().strip()
    req_lower = requested_model.lower().strip()

    if prov == "cerebras":
        if "qwen" in req_lower:
            return "qwen-3.8-27b"
        if "70b" in req_lower:
            return "llama3.3-70b"
        if "8b" in req_lower:
            return "llama3.1-8b"
        return "gpt-oss-120b"

    elif prov == "google":
        from automaintainer.config import get_settings
        st = get_settings()
        if "pro" in req_lower:
            return getattr(st, "GOOGLE_DEFAULT_PLANNER_MODEL", "gemini-3.8-flash")
        return getattr(st, "GOOGLE_DEFAULT_FAST_MODEL", "gemini-3.8-flash")

    elif prov == "groq":
        if "openai/" in req_lower or "qwen/" in req_lower or "gpt-oss" in req_lower:
            return requested_model
        from automaintainer.config import get_settings
        st = get_settings()
        if "8b" in req_lower or "fast" in req_lower or "instant" in req_lower:
            return st.GROQ_DEFAULT_FAST_MODEL or "openai/gpt-oss-20b"
        return st.GROQ_DEFAULT_PLANNER_MODEL or "openai/gpt-oss-120b"

    return requested_model


_model_registry: Optional[ModelRegistry] = None
def get_model_registry() -> ModelRegistry:
    global _model_registry
    if _model_registry is None:
        _model_registry = ModelRegistry()
    return _model_registry
