import json
import re
import fnmatch
from pathlib import PurePosixPath
from typing import Optional, Type, TypeVar, Tuple, Dict, Any, List
from pydantic import BaseModel, ValidationError
import httpx
from automaintainer.inference.key_pool import KeyPoolRegistry
from automaintainer.inference.quota_manager import OrgQuotaManager
from automaintainer.inference.schemas import PlannerOutput, ReviewerOutput
from automaintainer.core.models import MutationIntent, MutationOp, RiskTier

T = TypeVar("T", bound=BaseModel)

class InferenceGatewayError(Exception):
    """Raised when inference generation fails or violates schema/policy."""
    pass

import time


def _parse_header_int(val: Optional[str]) -> Optional[int]:
    if not val:
        return None
    val = val.strip().lower()
    try:
        if val.endswith('k'):
            return int(float(val[:-1]) * 1000)
        elif val.endswith('m'):
            return int(float(val[:-1]) * 1000000)
        return int(float(val))
    except (ValueError, TypeError):
        return None

def _parse_header_float(val: Optional[str]) -> Optional[float]:
    if not val:
        return None
    try:
        return float(val.strip())
    except (ValueError, TypeError):
        return None

from automaintainer.inference.model_registry import resolve_model_for_provider

DEFAULT_PROVIDER_BASE_URLS = {
    "cerebras": "https://api.cerebras.ai/v1",
    "groq": "https://api.groq.com/openai/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
}

class GroqInferenceGateway:
    """
    Production Multi-Provider Inference Gateway (Cerebras, Groq, Google Gemini):
    1. Selects healthy key from KeyPoolRegistry per provider.
    2. Multi-key shifting: shifts from Key 1 to Key 2 if rate-limited (429), auth-failed (401/403), or 5xx.
    3. Cross-provider fallback: if Cerebras fails, seamlessly fails over to Groq, then Google.
    4. Dynamic model selection: maps model IDs according to active provider capabilities.
    5. Enforces organization-level quotas via OrgQuotaManager.
    6. Parses and tracks HTTP response headers.
    7. Strips markdown fences (```json ... ```).
    8. Validates output strictly through Pydantic schemas.
    9. Enforces 'Model Output Never Equals Permission' boundary.
    """

    def __init__(
        self,
        key_pool: KeyPoolRegistry,
        quota_manager: OrgQuotaManager,
        api_base_url: Optional[str] = None,
        provider_priority: Optional[List[str]] = None,
        provider_base_urls: Optional[Dict[str, str]] = None
    ):
        self.key_pool = key_pool
        self.quota_manager = quota_manager

        # Default configuration
        default_priority = ["groq", "google", "cerebras"]
        default_urls = DEFAULT_PROVIDER_BASE_URLS.copy()

        try:
            from automaintainer.config import get_settings
            settings = get_settings()
            if hasattr(settings, "INFERENCE_PROVIDER_PRIORITY") and settings.INFERENCE_PROVIDER_PRIORITY:
                default_priority = settings.INFERENCE_PROVIDER_PRIORITY
            default_urls["cerebras"] = getattr(settings, "CEREBRAS_API_BASE_URL", DEFAULT_PROVIDER_BASE_URLS["cerebras"])
            default_urls["groq"] = getattr(settings, "GROQ_API_BASE_URL", DEFAULT_PROVIDER_BASE_URLS["groq"])
            default_urls["google"] = getattr(settings, "GOOGLE_API_BASE_URL", DEFAULT_PROVIDER_BASE_URLS["google"])
        except Exception:
            pass

        self.provider_priority = [p.lower().strip() for p in (provider_priority or default_priority)]
        self.provider_base_urls = dict(default_urls)
        if provider_base_urls:
            self.provider_base_urls.update(provider_base_urls)

        if api_base_url:
            self.api_base_url = api_base_url.rstrip("/")
            self.provider_base_urls["groq"] = self.api_base_url
        else:
            self.api_base_url = self.provider_base_urls.get("groq", "https://api.groq.com/openai/v1").rstrip("/")

        self.rate_limit_snapshot: Dict[str, Any] = {}
        self.last_inference_meta: Dict[str, Any] = {}

    def capture_rate_limit_headers(self, headers: httpx.Headers, key_id: Optional[str] = None) -> None:
        """Parses rate-limit headers from LLM provider responses safely."""
        remaining_requests = _parse_header_int(headers.get("x-ratelimit-remaining-requests"))
        remaining_tokens = _parse_header_int(headers.get("x-ratelimit-remaining-tokens"))
        reset_requests = headers.get("x-ratelimit-reset-requests")
        reset_tokens = headers.get("x-ratelimit-reset-tokens")
        retry_after = _parse_header_float(headers.get("retry-after"))

        self.rate_limit_snapshot = {
            "remaining_requests": remaining_requests,
            "remaining_tokens": remaining_tokens,
            "reset_requests": reset_requests,
            "reset_tokens": reset_tokens,
            "retry_after": retry_after
        }

        # Update key record in pool if key_id provided
        if key_id:
            key_record = self.key_pool.get_key(key_id)
            if key_record:
                key_record.update_rate_limits(
                    remaining_requests=remaining_requests,
                    remaining_tokens=remaining_tokens,
                    reset_time=time.time() + retry_after if retry_after else None
                )
                if remaining_tokens is not None and remaining_tokens < 5000:
                    self.key_pool.mark_draining(key_id)

    async def complete(
        self,
        messages: List[Dict[str, str]],
        model_id: str = "llama-3.3-70b-versatile",
        temperature: float = 0.1,
        max_tokens: int = 2048,
        project_id: Optional[str] = None,
        org_id: str = "default_org",
        provider_preference: Optional[List[str]] = None,
        client: Optional[httpx.AsyncClient] = None
    ) -> str:
        """
        Executes an inference request through multi-provider key pooling and failover pipeline:
        1. Quota reservation check
        2. Determine provider order (preference or configured priority: Cerebras -> Groq -> Google)
        3. Dynamic model resolution according to provider
        4. Key selection from pool with automatic shift to next key on 429/401/error
        5. Cross-provider fallback if all keys of current provider fail
        6. Header capture and outcome recording
        """
        if not self.quota_manager.check_and_reserve(org_id, estimated_tokens=max_tokens):
            raise InferenceGatewayError(f"Organization quota exceeded for '{org_id}'")

        # Determine candidate providers in order
        priority_list = [p.lower().strip() for p in (provider_preference or self.provider_priority)]
        available_providers = self.key_pool.get_available_providers()

        # Prioritize providers that have active keys in the pool
        candidate_providers: List[str] = []
        for p in priority_list:
            if p in available_providers and p not in candidate_providers:
                candidate_providers.append(p)
        for p in available_providers:
            if p not in candidate_providers:
                candidate_providers.append(p)
        if not candidate_providers:
            candidate_providers = priority_list

        errors_log: List[str] = []

        for provider in candidate_providers:
            base_url = self.provider_base_urls.get(provider, self.api_base_url).rstrip("/")
            resolved_model = resolve_model_for_provider(model_id, provider)

            active_keys_count = len(self.key_pool.get_active_keys(provider=provider))
            attempts_for_provider = max(2, min(5, active_keys_count + 1))

            for attempt in range(attempts_for_provider):
                key_record = self.key_pool.select_healthy_key(provider=provider, project_id=project_id)
                if not key_record:
                    errors_log.append(f"{provider}: no healthy key available (attempt {attempt+1})")
                    break

                key_record.in_flight_requests += 1
                start_time = time.time()
                api_key = key_record.secret_ref

                payload = {
                    "model": resolved_model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }

                try:
                    target_url = f"{base_url}/chat/completions"
                    if client:
                        resp = await client.post(target_url, headers=headers, json=payload, timeout=60.0)
                    else:
                        async with httpx.AsyncClient() as default_client:
                            resp = await default_client.post(target_url, headers=headers, json=payload, timeout=60.0)

                    latency_ms = (time.time() - start_time) * 1000.0
                    self.capture_rate_limit_headers(resp.headers, key_record.key_id)

                    if resp.status_code == 200:
                        self.key_pool.record_outcome(key_record.key_id, success=True, latency_ms=latency_ms, status_code=200)
                        data = resp.json()
                        choices = data.get("choices", [])
                        if choices:
                            self.last_inference_meta = {
                                "provider": provider,
                                "model": resolved_model,
                                "key_id": key_record.key_id,
                                "latency_ms": latency_ms
                            }
                            return choices[0]["message"]["content"]
                        raise InferenceGatewayError(f"Model response from {provider} ({resolved_model}) contained no choices")

                    elif resp.status_code == 429:
                        self.key_pool.record_outcome(key_record.key_id, success=False, latency_ms=latency_ms, status_code=429)
                        retry_after = self.rate_limit_snapshot.get("retry_after") or 1.0
                        key_record.reset_time = time.time() + retry_after
                        self.key_pool.mark_draining(key_record.key_id)
                        errors_log.append(f"{provider} key {key_record.key_id} rate-limited (429)")

                        import asyncio
                        await asyncio.sleep(min(retry_after, 0.2))
                        # Shifts immediately to next key in key pool for this provider
                        continue

                    elif resp.status_code in (401, 403):
                        self.key_pool.record_outcome(key_record.key_id, success=False, latency_ms=latency_ms, status_code=resp.status_code)
                        self.key_pool.mark_quarantined(key_record.key_id)
                        errors_log.append(f"{provider} key {key_record.key_id} auth failure ({resp.status_code})")
                        continue

                    elif resp.status_code == 402:
                        self.key_pool.record_outcome(key_record.key_id, success=False, latency_ms=latency_ms, status_code=resp.status_code)
                        self.key_pool.mark_quarantined(key_record.key_id)
                        errors_log.append(f"{provider} key {key_record.key_id} payment required / quota depleted (402)")
                        continue

                    else:
                        self.key_pool.record_outcome(key_record.key_id, success=False, latency_ms=latency_ms, status_code=resp.status_code)
                        if resp.status_code >= 500 and key_record.recent_5xx_count >= 2:
                            self.key_pool.mark_draining(key_record.key_id)
                        errors_log.append(f"{provider} HTTP {resp.status_code}: {resp.text[:200]}")
                        continue

                except Exception as e:
                    latency_ms = (time.time() - start_time) * 1000.0
                    self.key_pool.record_outcome(key_record.key_id, success=False, latency_ms=latency_ms, status_code=500)
                    errors_log.append(f"{provider} key {key_record.key_id} exception: {str(e)}")
                    continue
                finally:
                    key_record.in_flight_requests = max(0, key_record.in_flight_requests - 1)

        raise InferenceGatewayError(f"Inference failed across all providers: {'; '.join(errors_log)}")

    def clean_json_text(self, text: str) -> str:
        text = text.strip()
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
        if fence_match:
            return fence_match.group(1).strip()
        return text

    def parse_structured_output(self, raw_text: str, model_cls: Type[T]) -> T:
        cleaned = self.clean_json_text(raw_text)
        try:
            return model_cls.model_validate_json(cleaned)
        except (ValidationError, json.JSONDecodeError) as err:
            raise InferenceGatewayError(f"Model output failed schema validation for {model_cls.__name__}: {str(err)}")

    def build_mutation_intent_from_plan(
        self,
        session_id: str,
        repository: str,
        branch: str,
        plan: PlannerOutput,
        allowed_scope: Optional[List[str]] = None,
        forbidden_patterns: Optional[List[str]] = None
    ) -> MutationIntent:
        """
        'Model Output Never Equals Permission'
        Target paths proposed by LLM must be strictly validated against the opportunity's
        detected scope and forbidden paths before any mutation intent is constructed.
        """
        hard_forbidden = [
            "infra/",
            "secrets",
            ".env",
            "deploy/",
            "credentials",
            "*.pem",
            "*.key"
        ]
        # .github/workflows is forbidden unless explicitly authorized for workflow maintenance
        if plan.task_type != "github_action_update":
            hard_forbidden.append(".github/workflows")

        user_forbidden = forbidden_patterns or []
        all_forbidden = hard_forbidden + user_forbidden

        def is_forbidden(p_str: str, pattern: str) -> bool:
            p_clean = p_str.replace("\\", "/").strip("/").lower()
            pat = pattern.replace("\\", "/").strip("/").lower()
            if fnmatch.fnmatch(p_clean, pat) or fnmatch.fnmatch(PurePosixPath(p_clean).name, pat):
                return True
            if p_clean == pat or p_clean.startswith(pat + "/"):
                return True
            parts = p_clean.split("/")
            if pat in parts:
                return True
            for part in parts:
                if fnmatch.fnmatch(part, pat):
                    return True
            return False

        for p in plan.target_paths:
            normalized = p.replace("\\", "/").strip()
            if any(is_forbidden(normalized, f) for f in all_forbidden):
                raise InferenceGatewayError(
                    f"Model proposed modification to forbidden path '{p}'. Permission denied."
                )

        if allowed_scope is not None:
            def matches_scope(p_str: str, scope_list: List[str]) -> bool:
                p_clean = p_str.replace("\\", "/").strip("/").lower()
                for s in scope_list:
                    s_clean = s.replace("\\", "/").strip("/").lower()
                    if p_clean == s_clean or fnmatch.fnmatch(p_clean, s_clean) or p_clean.startswith(s_clean + "/"):
                        return True
                return False

            for p in plan.target_paths:
                normalized = p.replace("\\", "/").strip()
                if not matches_scope(normalized, allowed_scope):
                    raise InferenceGatewayError(
                        f"Model proposed path '{p}' outside of detector scope '{allowed_scope}'. Permission denied."
                    )

        return MutationIntent(
            session_id=session_id,
            actor="planner",
            operation=MutationOp.CREATE_COMMIT,
            repository=repository,
            branch=branch,
            target_paths=plan.target_paths,
            risk=plan.risk_tier,
            metadata={
                "objective": plan.objective,
                "task_type": plan.task_type,
                "confidence": plan.confidence,
                "validation_steps": [v.model_dump() for v in plan.validation_steps]
            }
        )

MultiProviderInferenceGateway = GroqInferenceGateway


