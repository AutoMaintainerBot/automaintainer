import pytest
import httpx
from automaintainer.inference.key_pool import KeyPoolRegistry, ProviderKeyRecord
from automaintainer.inference.quota_manager import OrgQuotaManager
from automaintainer.inference.gateway import GroqInferenceGateway, InferenceGatewayError
from automaintainer.inference.model_registry import resolve_model_for_provider
from automaintainer.config import Settings

def test_dynamic_model_resolution_per_provider():
    # Cerebras mapping
    assert resolve_model_for_provider("llama3.3-70b", "cerebras") == "llama3.3-70b"
    assert resolve_model_for_provider("llama-3.3-70b-versatile", "cerebras") == "llama3.3-70b"
    assert resolve_model_for_provider("llama3.1-8b", "cerebras") == "llama3.1-8b"
    assert resolve_model_for_provider("llama-3.1-8b-instant", "cerebras") == "llama3.1-8b"

    # Groq mapping
    assert resolve_model_for_provider("llama3.3-70b", "groq") == "openai/gpt-oss-120b"
    assert resolve_model_for_provider("llama-3.3-70b-versatile", "groq") == "openai/gpt-oss-120b"
    assert resolve_model_for_provider("llama3.1-8b", "groq") == "openai/gpt-oss-20b"
    assert resolve_model_for_provider("llama-3.1-8b-instant", "groq") == "openai/gpt-oss-20b"

    # Google Gemini mapping
    assert resolve_model_for_provider("llama3.3-70b", "google") == "gemini-3.8-flash"
    assert resolve_model_for_provider("llama-3.1-8b-instant", "google") == "gemini-3.8-flash"
    assert resolve_model_for_provider("gemini-3.8-flash", "google") == "gemini-3.8-flash"

def test_key_pool_registers_multi_keys_from_settings():
    pool = KeyPoolRegistry()
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="development",
        GITHUB_WEBHOOK_SECRET="test_webhook_secret_min_16_chars_valid",
        CEREBRAS_API_KEYS="csk-cerebras-1, csk-cerebras-2",
        GROQ_API_KEYS="gsk-groq-1, gsk-groq-2",
        GOOGLE_API_KEYS="AIzaSy-google-1, AIzaSy-google-2",
    )
    pool.populate_from_settings(mock_settings)

    cerebras_keys = pool.get_active_keys(provider="cerebras")
    groq_keys = pool.get_active_keys(provider="groq")
    google_keys = pool.get_active_keys(provider="google")

    assert len(cerebras_keys) == 2
    assert len(groq_keys) == 2
    assert len(google_keys) == 2
    assert pool.get_available_providers() == ["cerebras", "groq", "google"]

def test_key_pool_registers_numbered_env_vars(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY_1", "gsk-num-1")
    monkeypatch.setenv("GROQ_API_KEY_2", "gsk-num-2")
    monkeypatch.setenv("CEREBRAS_API_KEY_1", "csk-num-1")
    monkeypatch.setenv("CEREBRAS_API_KEY_2", "csk-num-2")
    monkeypatch.setenv("GOOGLE_API_KEY_1", "AIzaSy-num-1")

    pool = KeyPoolRegistry()
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="development",
        GITHUB_WEBHOOK_SECRET="test_webhook_secret_min_16_chars_valid",
    )
    pool.populate_from_settings(mock_settings)

    assert len(pool.get_active_keys(provider="groq")) == 2
    assert len(pool.get_active_keys(provider="cerebras")) == 2
    assert len(pool.get_active_keys(provider="google")) == 1


def test_key_pool_registers_non_underscore_numbered_env_vars(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY1", "gsk-no-underscore-1")
    monkeypatch.setenv("GROQ_API_KEY2", "gsk-no-underscore-2")
    monkeypatch.setenv("GOOGLE_API_KEY1", "AIzaSy-no-underscore-1")
    monkeypatch.setenv("CEREBRAS_API_KEY1", "csk-no-underscore-1")

    pool = KeyPoolRegistry()
    mock_settings = Settings(
        _env_file=None,
        ENVIRONMENT="development",
        GITHUB_WEBHOOK_SECRET="test_webhook_secret_min_16_chars_valid",
    )
    pool.populate_from_settings(mock_settings)

    assert len(pool.get_active_keys(provider="groq")) == 2
    assert len(pool.get_active_keys(provider="cerebras")) == 1
    assert len(pool.get_active_keys(provider="google")) == 1


@pytest.mark.asyncio
async def test_cerebras_multi_key_shifting_on_429():
    """If Key 1 of Cerebras hits 429 rate limit, gateway automatically shifts to Key 2."""
    pool = KeyPoolRegistry()
    pool.register_key(ProviderKeyRecord(
        key_id="cerebras_key_1",
        provider="cerebras",
        secret_ref="csk-key-1"
    ))
    pool.register_key(ProviderKeyRecord(
        key_id="cerebras_key_2",
        provider="cerebras",
        secret_ref="csk-key-2"
    ))

    gw = GroqInferenceGateway(
        key_pool=pool,
        quota_manager=OrgQuotaManager(),
        provider_priority=["cerebras"]
    )

    request_calls = []

    def mock_transport_handler(request: httpx.Request):
        auth_header = request.headers.get("authorization", "")
        request_calls.append(auth_header)

        # Key 1 fails with 429
        if "csk-key-1" in auth_header:
            return httpx.Response(
                429,
                headers={"retry-after": "0.01"},
                json={"error": {"message": "Rate limit reached for key 1"}}
            )
        # Key 2 succeeds
        elif "csk-key-2" in auth_header:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Success from Cerebras Key 2"}}]}
            )
        return httpx.Response(500)

    transport = httpx.MockTransport(mock_transport_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await gw.complete(
            messages=[{"role": "user", "content": "hello"}],
            model_id="llama3.3-70b",
            client=client
        )

    assert result == "Success from Cerebras Key 2"
    assert "Bearer csk-key-1" in request_calls
    assert "Bearer csk-key-2" in request_calls
    assert gw.last_inference_meta["provider"] == "cerebras"
    assert gw.last_inference_meta["key_id"] == "cerebras_key_2"

@pytest.mark.asyncio
async def test_cross_provider_fallback_cerebras_to_groq_with_model_resolution():
    """If all Cerebras keys fail, failover shifts to Groq and maps the model accordingly."""
    pool = KeyPoolRegistry()
    pool.register_key(ProviderKeyRecord(
        key_id="cerebras_key_1",
        provider="cerebras",
        secret_ref="csk-exhausted-key"
    ))
    pool.register_key(ProviderKeyRecord(
        key_id="groq_key_1",
        provider="groq",
        secret_ref="gsk-groq-healthy"
    ))

    gw = GroqInferenceGateway(
        key_pool=pool,
        quota_manager=OrgQuotaManager(),
        provider_priority=["cerebras", "groq", "google"]
    )

    recorded_models = []

    def mock_transport_handler(request: httpx.Request):
        import json
        body = json.loads(request.content.decode("utf-8"))
        recorded_models.append(body.get("model"))
        auth_header = request.headers.get("authorization", "")

        # Cerebras request
        if "csk-exhausted-key" in auth_header:
            return httpx.Response(429, headers={"retry-after": "0.01"}, json={"error": "Rate limit"})

        # Groq request
        if "gsk-groq-healthy" in auth_header:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Success from Groq fallback"}}]}
            )
        return httpx.Response(500)

    transport = httpx.MockTransport(mock_transport_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await gw.complete(
            messages=[{"role": "user", "content": "Plan maintenance"}],
            model_id="llama3.3-70b",
            client=client
        )

    assert result == "Success from Groq fallback"
    assert gw.last_inference_meta["provider"] == "groq"
    assert gw.last_inference_meta["model"] == "openai/gpt-oss-120b"
    assert "llama3.3-70b" in recorded_models
    assert "openai/gpt-oss-120b" in recorded_models

@pytest.mark.asyncio
async def test_cross_provider_fallback_all_the_way_to_google():
    """If Cerebras and Groq both fail, failover shifts to Google Gemini."""
    pool = KeyPoolRegistry()
    pool.register_key(ProviderKeyRecord(
        key_id="cerebras_1",
        provider="cerebras",
        secret_ref="csk-fail"
    ))
    pool.register_key(ProviderKeyRecord(
        key_id="groq_1",
        provider="groq",
        secret_ref="gsk-fail"
    ))
    pool.register_key(ProviderKeyRecord(
        key_id="google_1",
        provider="google",
        secret_ref="AIzaSy-google-key"
    ))

    gw = GroqInferenceGateway(
        key_pool=pool,
        quota_manager=OrgQuotaManager(),
        provider_priority=["cerebras", "groq", "google"]
    )

    def mock_transport_handler(request: httpx.Request):
        auth_header = request.headers.get("authorization", "")
        if "csk-fail" in auth_header:
            return httpx.Response(429, headers={"retry-after": "0.01"}, json={"error": "Rate limit"})
        if "gsk-fail" in auth_header:
            return httpx.Response(503, json={"error": "Service Unavailable"})
        if "AIzaSy-google-key" in auth_header:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Success from Google Gemini"}}]}
            )
        return httpx.Response(500)

    transport = httpx.MockTransport(mock_transport_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await gw.complete(
            messages=[{"role": "user", "content": "Review PR"}],
            model_id="llama3.3-70b",
            client=client
        )

    assert result == "Success from Google Gemini"
    assert gw.last_inference_meta["provider"] == "google"
    assert gw.last_inference_meta["model"] == "gemini-3.8-flash"
