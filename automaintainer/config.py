from typing import Optional
import os
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from automaintainer.core.secrets_manager import get_secret_resolver

INSECURE_DEFAULT_JWT_SECRETS = {
    "automaintainer_default_jwt_secret_min_32_chars_123456",
    "changeme",
    "secret",
    "default_jwt_secret",
}

INSECURE_DEFAULT_WEBHOOK_SECRETS = {
    "automaintainer_default_webhook_secret_32_chars!",
    "secret",
    "default_webhook_secret",
    "changeme",
}

class Settings(BaseSettings):
    """
    Production-grade application configuration.
    Secrets and configurations can be injected via environment variables,
    .env files, or dynamically resolved from AWS/GCP Secret Manager / Vault.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENVIRONMENT: str = Field(default="development", description="development | staging | production")
    APP_NAME: str = "AutoMaintainer"

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///automaintainer.db",
        description="Async database connection string. Defaults to SQLite in development, PostgreSQL in production."
    )
    DB_POOL_SIZE: int = Field(default=20, description="Connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=10, description="Max overflow connections")

    # Distributed Queue (Redis Streams)
    REDIS_URL: Optional[str] = Field(
        default=None,
        description="Redis connection URL (e.g. redis://localhost:6379/0). Required in production and staging when QUEUE_BACKEND=redis. Lower environments may fall back to in-memory only when ALLOW_IN_MEMORY_QUEUE=True."
    )

    # Cloud & Local Object Storage
    STORAGE_ROOT: str = Field(default="./automaintainer_artifacts", description="Root directory for artifact storage")
    S3_BUCKET_NAME: Optional[str] = Field(default=None, description="S3 / MinIO artifact bucket name")
    S3_ENDPOINT_URL: Optional[str] = Field(default=None, description="Custom S3 endpoint URL (for MinIO/LocalStack)")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, description="AWS Access Key ID for S3 storage")
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, description="AWS Secret Access Key for S3 storage")
    AWS_REGION: str = Field(default="us-east-1", description="AWS Region")

    # Google Cloud Storage (GCS) Object Storage
    GCS_BUCKET_NAME: Optional[str] = Field(default=None, description="GCS artifact bucket name")
    GCS_PROJECT_ID: Optional[str] = Field(default=None, description="GCP Project ID for Cloud Storage and Secret Manager")
    GCS_KMS_KEY_NAME: Optional[str] = Field(default=None, description="Cloud KMS key name for GCS customer-managed encryption")

    # Cloud KMS & Hardware HSM Driver Settings
    KMS_ROTATION_PROVIDER: str = Field(default="aws", description="External rotation driver provider: aws | gcp | vault")
    KMS_KEY_ARN: Optional[str] = Field(default=None, description="AWS KMS Key ARN or Alias for HSM encryption")
    KMS_KEY_NAME: Optional[str] = Field(default=None, description="GCP Cloud KMS Key Resource Name for HSM encryption")
    AWS_SECRET_MANAGER_ENABLED: bool = Field(default=False, description="Enable AWS Secrets Manager dynamic resolution")
    GCP_SECRET_MANAGER_ENABLED: bool = Field(default=False, description="Enable GCP Secret Manager dynamic resolution")
    VAULT_ADDR: Optional[str] = Field(default=None, description="HashiCorp Vault URL")
    VAULT_TOKEN: Optional[str] = Field(default=None, description="HashiCorp Vault Token")

    # GitHub App Credentials & Personal Fallback
    GITHUB_APP_ID: str = Field(default="", description="GitHub App ID")
    GITHUB_APP_PRIVATE_KEY: str = Field(default="", description="GitHub App RSA Private Key PEM")
    GITHUB_TOKEN: Optional[str] = Field(default=None, description="Optional GitHub PAT fallback for public mode")
    GITHUB_BOT_ORG: str = Field(default="AutoMaintainerBot", description="GitHub organization or account where disposable public forks are created")
    PUBLIC_DISCOVERY_ENABLED: bool = Field(default=False, description="Enable crawling and autonomous discovery on uninstalled public repositories (default: False)")
    MANAGED_REPOSITORIES_FILE: str = Field(default="config/managed_repositories.yaml", description="Path to file listing repositories explicitly managed by AutoMaintainer")
    MANAGED_REPOSITORIES_POLL_INTERVAL: int = Field(default=20, description="Interval in seconds for scanning the managed repositories file")
    GITHUB_WEBHOOK_SECRET: Optional[str] = Field(
        default=None,
        description="High-entropy webhook HMAC secret. REQUIRED in production/staging."
    )
    GITHUB_API_BASE_URL: str = "https://api.github.com"

    # Multi-Provider Inference Settings (Groq, Cerebras, Google)
    INFERENCE_PROVIDER_PRIORITY: list[str] = Field(
        default=["groq", "google", "cerebras"],
        description="Priority order of LLM inference providers for automatic failover: groq, google, cerebras"
    )

    # Groq Settings
    GROQ_ENABLED: bool = Field(default=True, description="Enable Groq inference provider")
    GROQ_PROJECT_REGISTRY_REF: str = Field(default="groq/projects", description="Secret manager key registry path")
    GROQ_SECRET_NAMESPACE: str = Field(default="groq_keys", description="Prefix namespace for Groq key pool")
    GROQ_API_KEY: Optional[str] = Field(default=None, description="Groq API key")
    GROQ_API_KEYS: Optional[str] = Field(default=None, description="Comma-separated list of Groq API keys for key pooling/rotation")
    GROQ_API_BASE_URL: str = "https://api.groq.com/openai/v1"
    GROQ_ORG_ID: str = Field(default="default_org", description="Groq Organization ID for quota management")
    GROQ_DEFAULT_PLANNER_MODEL: str = "openai/gpt-oss-120b"
    GROQ_DEFAULT_FAST_MODEL: str = "openai/gpt-oss-20b"

    # Cerebras Cloud Settings
    CEREBRAS_ENABLED: bool = Field(default=True, description="Enable Cerebras inference provider")
    CEREBRAS_API_KEY: Optional[str] = Field(default=None, description="Cerebras API key")
    CEREBRAS_API_KEYS: Optional[str] = Field(default=None, description="Comma-separated list of Cerebras API keys for key pooling/rotation")
    CEREBRAS_API_BASE_URL: str = "https://api.cerebras.ai/v1"
    CEREBRAS_DEFAULT_PLANNER_MODEL: str = "llama3.3-70b"
    CEREBRAS_DEFAULT_FAST_MODEL: str = "llama3.1-8b"

    # Google Gemini Settings
    GOOGLE_ENABLED: bool = Field(default=True, description="Enable Google Gemini inference provider")
    GOOGLE_API_KEY: Optional[str] = Field(default=None, description="Google Gemini API key")
    GEMINI_API_KEY: Optional[str] = Field(default=None, description="Alias for Google Gemini API key")
    GOOGLE_API_KEYS: Optional[str] = Field(default=None, description="Comma-separated list of Google Gemini API keys for key pooling/rotation")
    GOOGLE_API_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    GOOGLE_DEFAULT_PLANNER_MODEL: str = "gemini-3.8-flash"
    GOOGLE_DEFAULT_FAST_MODEL: str = "gemini-3.8-flash"

    # Authentication & Secrets
    JWT_SECRET: Optional[str] = Field(
        default=None,
        description="High-entropy HMAC secret for signing JWT tokens. REQUIRED in production/staging."
    )
    ADMIN_USERNAME: str = Field(default="admin", description="Admin username for protected dashboard and docs")
    ADMIN_PASSWORD: Optional[str] = Field(
        default=None,
        description="Admin password protecting /admin dashboard and /docs. Must be supplied via ADMIN_PASSWORD environment variable."
    )

    # Distributed Queue Configuration
    QUEUE_BACKEND: str = Field(default="memory", description="redis | memory")
    ALLOW_IN_MEMORY_QUEUE: bool = Field(default=False, description="Allow in-memory queue fallback")

    # Defensive Safeguards & Rate Limiting
    MAX_PRS_PER_HOUR: int = Field(default=2, description="Defensive rate limit: maximum PRs AutoMaintainer can open globally per hour")

    # Sandbox & Execution Security
    SANDBOX_BACKEND: str = Field(default="container", description="container | subprocess_jail | gvisor")
    ALLOW_HOST_SUBPROCESS: bool = Field(default=False, description="Allow host subprocess execution instead of container sandbox (strictly forbidden in production)")
    DOCKER_BASE_IMAGE: str = "python:3.12-slim"
    EGRESS_PROXY_HOST: str = "127.0.0.1"
    EGRESS_PROXY_PORT: int = 8080

    @field_validator("GITHUB_WEBHOOK_SECRET")
    @classmethod
    def validate_webhook_secret(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return None
        v_clean = v.strip()
        if not v_clean:
            return None
        return v_clean

    @model_validator(mode="after")
    def validate_production_hardening(self) -> "Settings":
        import secrets as _secrets
        env = self.ENVIRONMENT.lower().strip()
        is_prod = env in ("production", "staging")

        # JWT Secret validation
        if is_prod:
            if not self.JWT_SECRET or len(self.JWT_SECRET.strip()) < 32 or self.JWT_SECRET.strip() in INSECURE_DEFAULT_JWT_SECRETS or "default_jwt_secret" in self.JWT_SECRET.lower():
                raise ValueError(
                    "JWT_SECRET must be explicitly configured with a secure, high-entropy secret (min 32 characters) "
                    "in production/staging environments. Insecure or publicly known default secrets are strictly forbidden."
                )
        else:
            if not self.JWT_SECRET or self.JWT_SECRET.strip() in INSECURE_DEFAULT_JWT_SECRETS:
                self.JWT_SECRET = _secrets.token_urlsafe(32)

        # Webhook Secret validation
        if is_prod:
            if not self.GITHUB_WEBHOOK_SECRET or len(self.GITHUB_WEBHOOK_SECRET.strip()) < 16 or self.GITHUB_WEBHOOK_SECRET.strip() in INSECURE_DEFAULT_WEBHOOK_SECRETS or "default_webhook_secret" in self.GITHUB_WEBHOOK_SECRET.lower():
                raise ValueError(
                    "GITHUB_WEBHOOK_SECRET must be explicitly configured with a secure, high-entropy secret (min 16 characters) "
                    "in production/staging environments. Insecure or publicly known default secrets are strictly forbidden."
                )
        else:
            if not self.GITHUB_WEBHOOK_SECRET or self.GITHUB_WEBHOOK_SECRET.strip() in INSECURE_DEFAULT_WEBHOOK_SECRETS:
                self.GITHUB_WEBHOOK_SECRET = _secrets.token_hex(20)

        if is_prod:
            if "postgres:postgres@localhost" in self.DATABASE_URL or "postgres:postgres@" in self.DATABASE_URL:
                raise ValueError("Insecure default database credentials ('postgres:postgres') detected in production/staging environment.")

        is_paas = bool(
            os.environ.get("RENDER")
            or os.environ.get("FLY_APP_NAME")
            or os.environ.get("CONTAINER_ISOLATED")
        )

        if is_prod:
            if is_paas:
                # PaaS single-instance deployment (e.g. Render free/starter without Redis addon)
                if self.REDIS_URL:
                    self.QUEUE_BACKEND = "redis"
                    self.ALLOW_IN_MEMORY_QUEUE = False
                else:
                    self.QUEUE_BACKEND = "memory"
                    self.ALLOW_IN_MEMORY_QUEUE = True
            else:
                if self.QUEUE_BACKEND == "memory" or self.ALLOW_IN_MEMORY_QUEUE:
                    raise ValueError(
                        "In-memory queue (QUEUE_BACKEND='memory' or ALLOW_IN_MEMORY_QUEUE=True) is strictly prohibited in production and staging environments. "
                        "A durable distributed queue (QUEUE_BACKEND='redis' with REDIS_URL configured) is mandatory so jobs survive restarts and scale across instances."
                    )
                if self.QUEUE_BACKEND == "redis":
                    if not self.REDIS_URL:
                        raise ValueError("REDIS_URL must be configured when running in production or staging with QUEUE_BACKEND=redis.")
                elif self.QUEUE_BACKEND != "redis":
                    raise ValueError(
                        f"Unsupported or non-durable QUEUE_BACKEND='{self.QUEUE_BACKEND}' in production/staging. "
                        "A durable distributed queue (QUEUE_BACKEND='redis') is required."
                    )

            if self.ALLOW_HOST_SUBPROCESS and not is_paas:
                raise ValueError(
                    "ALLOW_HOST_SUBPROCESS cannot be enabled in production or staging environments. "
                    "Container isolation (Docker or gVisor) is mandatory for untrusted code execution."
                )

            if self.SANDBOX_BACKEND not in ("container", "gvisor") and not is_paas:
                raise ValueError(
                    f"SANDBOX_BACKEND='{self.SANDBOX_BACKEND}' is forbidden in production/staging environments. "
                    "Only isolated container runtimes ('container' or 'gvisor') are allowed."
                )

            if not self.GITHUB_TOKEN and (not self.GITHUB_APP_ID or not self.GITHUB_APP_PRIVATE_KEY):
                raise ValueError("Either GITHUB_TOKEN or GITHUB_APP_ID/GITHUB_APP_PRIVATE_KEY must be configured in production/staging environments.")

        return self

    def resolve_dynamic_secret(self, key_name: str, current_value: Optional[str] = None) -> Optional[str]:
        """Resolves secret dynamically from Vault, KMS, or Cloud Secret Manager."""
        if current_value and not any(current_value.startswith(scheme) for scheme in ("vault://", "aws-secrets://", "gcp-secrets://")):
            return current_value
        resolver = get_secret_resolver()
        lookup_key = current_value if (current_value and any(current_value.startswith(s) for s in ("vault://", "aws-secrets://", "gcp-secrets://"))) else key_name
        return resolver.resolve(lookup_key, default=current_value)

# Lazy singleton
_settings: Optional[Settings] = None

def get_settings() -> Settings:
    global _settings
    if _settings is None:
        # Auto-load Render Secret Files (stored in /etc/secrets)
        for sdir in ("/etc/secrets", "/secrets"):
            if os.path.exists(sdir):
                try:
                    from dotenv import load_dotenv
                    for fname in os.listdir(sdir):
                        fpath = os.path.join(sdir, fname)
                        if os.path.isfile(fpath):
                            load_dotenv(fpath, override=False)
                except Exception:
                    pass
        _settings = Settings()
        # Dynamically enrich from Secret Manager if configured or referenced via URI
        if not _settings.GROQ_API_KEY or any(str(_settings.GROQ_API_KEY).startswith(s) for s in ("vault://", "aws-secrets://", "gcp-secrets://")):
            resolved = _settings.resolve_dynamic_secret("GROQ_API_KEY", _settings.GROQ_API_KEY)
            if resolved:
                _settings.GROQ_API_KEY = resolved

        if not _settings.GITHUB_APP_PRIVATE_KEY or any(str(_settings.GITHUB_APP_PRIVATE_KEY).startswith(s) for s in ("vault://", "aws-secrets://", "gcp-secrets://")):
            resolved = _settings.resolve_dynamic_secret("GITHUB_APP_PRIVATE_KEY", _settings.GITHUB_APP_PRIVATE_KEY)
            if resolved:
                _settings.GITHUB_APP_PRIVATE_KEY = resolved

        if _settings.GITHUB_WEBHOOK_SECRET and any(str(_settings.GITHUB_WEBHOOK_SECRET).startswith(s) for s in ("vault://", "aws-secrets://", "gcp-secrets://")):
            resolved = _settings.resolve_dynamic_secret("GITHUB_WEBHOOK_SECRET", _settings.GITHUB_WEBHOOK_SECRET)
            if resolved:
                _settings.GITHUB_WEBHOOK_SECRET = resolved
    return _settings
