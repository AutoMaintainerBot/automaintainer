from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from automaintainer.inference.key_pool import get_global_key_pool
from automaintainer.inference.model_registry import get_model_registry
from automaintainer.config import get_settings
from automaintainer.app.auth import get_current_user, AuthUser

router = APIRouter(prefix="/v1/inference", tags=["Inference"])

class InferenceHealthResponse(BaseModel):
    provider: str
    status: str
    provider_available: bool
    active_providers: List[str] = []
    configured_priority: List[str] = []

class InferenceModelDetail(BaseModel):
    model_id: str
    lifecycle_state: str
    context_window: int
    fallback_model: Optional[str] = None
    deprecation_date: Optional[str] = None

class InferenceModelsResponse(BaseModel):
    models: List[InferenceModelDetail]

@router.get("/health", response_model=InferenceHealthResponse)
async def get_inference_health(user: AuthUser = Depends(get_current_user)):
    """
    GET /v1/inference/health - Active health check of inference providers and key pool.
    Requires authentication. For unauthenticated infrastructure health checks, use /health or /v1/ops/health.
    """
    settings = get_settings()
    pool = get_global_key_pool()
    active_providers = pool.get_available_providers()
    provider_available = (
        len(active_providers) > 0
        or bool(settings.CEREBRAS_API_KEY)
        or bool(settings.GROQ_API_KEY)
        or bool(settings.GOOGLE_API_KEY)
    )
    primary_provider = settings.INFERENCE_PROVIDER_PRIORITY[0] if settings.INFERENCE_PROVIDER_PRIORITY else "cerebras"

    return InferenceHealthResponse(
        provider=primary_provider,
        status="healthy" if provider_available else "degraded",
        provider_available=provider_available,
        active_providers=active_providers,
        configured_priority=settings.INFERENCE_PROVIDER_PRIORITY
    )

@router.get("/models", response_model=InferenceModelsResponse)
async def list_inference_models(user: AuthUser = Depends(get_current_user)):
    """GET /v1/inference/models - Approved model registry list and deprecation status."""
    reg = get_model_registry()
    models = reg.list_models()
    return InferenceModelsResponse(
        models=[
            InferenceModelDetail(
                model_id=m.model_id,
                lifecycle_state=m.lifecycle_state.value,
                context_window=m.context_window,
                fallback_model=m.recommended_fallback_id,
                deprecation_date=m.deprecation_date
            )
            for m in models
        ]
    )
