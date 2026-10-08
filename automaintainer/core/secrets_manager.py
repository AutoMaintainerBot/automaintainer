import os
import json
import base64
import uuid
import time
import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

logger = logging.getLogger("automaintainer.secrets")

class ISecretManager(ABC):
    @abstractmethod
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve secret by name or path."""
        pass

class EnvSecretProvider(ISecretManager):
    """Fetches secrets from environment variables."""
    def get_secret(self, secret_name: str) -> Optional[str]:
        return os.environ.get(secret_name)

class AWSSecretsManagerClient(ISecretManager):
    """
    AWS Secrets Manager Driver:
    Fetches JSON or string secrets dynamically using boto3.
    """
    def __init__(self, region_name: Optional[str] = None):
        self.region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client("secretsmanager", region_name=self.region_name)
            except ImportError:
                logger.warning("boto3 is not installed; AWS Secrets Manager is unavailable.")
                return None
        return self._client

    def get_secret(self, secret_name: str) -> Optional[str]:
        client = self._get_client()
        if not client:
            return None
        try:
            response = client.get_secret_value(SecretId=secret_name)
            if "SecretString" in response:
                secret = response["SecretString"]
                try:
                    parsed = json.loads(secret)
                    if isinstance(parsed, dict) and secret_name in parsed:
                        return parsed[secret_name]
                except json.JSONDecodeError:
                    pass
                return secret
        except Exception as e:
            logger.debug(f"AWS Secrets Manager failed to fetch '{secret_name}': {e}")
            return None
        return None

class GCPSecretManagerClient(ISecretManager):
    """
    GCP Secret Manager Driver:
    Fetches secrets using google-cloud-secret-manager client.
    """
    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.environ.get("GCP_PROJECT_ID")
        self._client = None

    def _get_client(self):
        if self._client is None:
            try:
                from google.cloud import secretmanager
                self._client = secretmanager.SecretManagerServiceClient()
            except ImportError:
                return None
        return self._client

    def get_secret(self, secret_name: str) -> Optional[str]:
        client = self._get_client()
        if not client or not self.project_id:
            return None
        try:
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = client.access_secret_version(name=name)
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            logger.debug(f"GCP Secret Manager failed to fetch '{secret_name}': {e}")
            return None

class VaultSecretClient(ISecretManager):
    """
    HashiCorp Vault Secret Driver:
    Fetches secrets from Vault KV v2 engine via HTTP/AppRole/Kubernetes auth.
    """
    def __init__(
        self,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
        role_id: Optional[str] = None,
        secret_id: Optional[str] = None,
        k8s_role: Optional[str] = None,
    ):
        self.vault_url = vault_url or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self._client = None

        # Auto-login via AppRole or Kubernetes auth if token not explicitly supplied
        if not self.vault_token and self.vault_url:
            effective_role_id = role_id or os.environ.get("VAULT_ROLE_ID")
            effective_secret_id = secret_id or os.environ.get("VAULT_SECRET_ID")
            effective_k8s_role = k8s_role or os.environ.get("VAULT_K8S_ROLE")

            if effective_role_id and effective_secret_id:
                self.login_approle(effective_role_id, effective_secret_id)
            elif effective_k8s_role:
                self.login_kubernetes(effective_k8s_role)

    def login_approle(self, role_id: str, secret_id: str) -> Optional[str]:
        """Authenticates with Vault using AppRole credentials."""
        if not self.vault_url:
            return None
        try:
            import httpx
            url = f"{self.vault_url.rstrip('/')}/v1/auth/approle/login"
            with httpx.Client(timeout=5.0) as client:
                res = client.post(url, json={"role_id": role_id, "secret_id": secret_id})
                if res.status_code == 200:
                    data = res.json()
                    token = data.get("auth", {}).get("client_token")
                    if token:
                        self.vault_token = token
                        return token
        except Exception as e:
            logger.debug(f"Vault AppRole login failed: {e}")
        return None

    def login_kubernetes(self, role: str, jwt_token: Optional[str] = None, mount_point: str = "kubernetes") -> Optional[str]:
        """Authenticates with Vault using Kubernetes ServiceAccount JWT."""
        if not self.vault_url:
            return None
        try:
            import httpx
            jwt_val = jwt_token
            if not jwt_val:
                k8s_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
                if os.path.exists(k8s_token_path):
                    with open(k8s_token_path, "r", encoding="utf-8") as f:
                        jwt_val = f.read().strip()
            if not jwt_val:
                return None

            url = f"{self.vault_url.rstrip('/')}/v1/auth/{mount_point}/login"
            with httpx.Client(timeout=5.0) as client:
                res = client.post(url, json={"role": role, "jwt": jwt_val})
                if res.status_code == 200:
                    data = res.json()
                    token = data.get("auth", {}).get("client_token")
                    if token:
                        self.vault_token = token
                        return token
        except Exception as e:
            logger.debug(f"Vault Kubernetes login failed: {e}")
        return None

    def get_secret(self, secret_name: str, key_field: Optional[str] = None) -> Optional[str]:
        if not self.vault_url or not self.vault_token:
            return None
        try:
            import httpx
            headers = {"X-Vault-Token": self.vault_token}
            clean_name = secret_name.lstrip("/")
            if not clean_name.startswith("secret/data/") and not clean_name.startswith("v1/"):
                clean_name = f"secret/data/{clean_name}"
            url = f"{self.vault_url.rstrip('/')}/v1/{clean_name.lstrip('/')}"
            with httpx.Client(timeout=5.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    payload = data.get("data", {}).get("data", {})
                    if key_field and key_field in payload:
                        return str(payload[key_field])
                    if "value" in payload:
                        return str(payload["value"])
                    if payload and len(payload) == 1:
                        return str(list(payload.values())[0])
                    return json.dumps(payload)
        except Exception:
            return None
        return None

def decrypt_kms_envelope(ciphertext_b64: str, provider: str = "aws", region_or_project: Optional[str] = None) -> Optional[str]:
    """Envelope decrypts KMS-encrypted ciphertext blobs using AWS KMS or GCP Cloud KMS HSM."""
    try:
        raw_bytes = base64.b64decode(ciphertext_b64)
        if provider == "aws":
            import boto3
            kms = boto3.client("kms", region_name=region_or_project or os.environ.get("AWS_REGION", "us-east-1"))
            res = kms.decrypt(CiphertextBlob=raw_bytes)
            return res["Plaintext"].decode("utf-8")
        elif provider == "gcp":
            from google.cloud import kms_v1
            client = kms_v1.KeyManagementServiceClient()
            res = client.decrypt(request={"name": region_or_project, "ciphertext": raw_bytes})
            return res.plaintext.decode("utf-8")
    except Exception as e:
        logger.debug(f"KMS decryption failed: {e}")
        return None
    return None

class KmsRotationDriver:
    """
    External rotation driver for GitHub App private keys, webhook HMAC secrets,
    and API credentials backed by AWS Secrets Manager / KMS, GCP Secret Manager / Cloud KMS HSM,
    or HashiCorp Vault.
    """
    def __init__(
        self,
        provider: str = "aws",
        region_or_project: Optional[str] = None,
        kms_key_id: Optional[str] = None,
        vault_url: Optional[str] = None,
        vault_token: Optional[str] = None,
    ):
        self.provider = (provider or "aws").lower()
        self.region_or_project = region_or_project or os.environ.get("AWS_REGION") or os.environ.get("GCP_PROJECT_ID")
        self.kms_key_id = kms_key_id or os.environ.get("KMS_KEY_ARN") or os.environ.get("KMS_KEY_NAME")
        self.vault_url = vault_url or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")

    def encrypt_data(self, plaintext: str) -> Optional[str]:
        """Hardware HSM / KMS envelope encryption of sensitive credentials."""
        try:
            data_bytes = plaintext.encode("utf-8")
            if self.provider == "aws":
                import boto3
                kms = boto3.client("kms", region_name=self.region_or_project or "us-east-1")
                res = kms.encrypt(KeyId=self.kms_key_id or "alias/automaintainer", Plaintext=data_bytes)
                return base64.b64encode(res["CiphertextBlob"]).decode("utf-8")
            elif self.provider == "gcp":
                from google.cloud import kms_v1
                client = kms_v1.KeyManagementServiceClient()
                res = client.encrypt(request={"name": self.kms_key_id, "plaintext": data_bytes})
                return base64.b64encode(res.ciphertext).decode("utf-8")
        except Exception as e:
            logger.error(f"KMS encryption failed with provider '{self.provider}': {e}")
            return None
        return None

    def decrypt_data(self, ciphertext_b64: str) -> Optional[str]:
        """Hardware HSM / KMS envelope decryption of sensitive credentials."""
        return decrypt_kms_envelope(ciphertext_b64, provider=self.provider, region_or_project=self.region_or_project)

    def rotate_secret(self, secret_name: str, new_value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Rotates a secret in the external vault/KMS backend.
        Supports AWS Secrets Manager, GCP Secret Manager, and HashiCorp Vault.
        """
        logger.info(f"Initiating external rotation for secret '{secret_name}' via provider '{self.provider}'")
        try:
            if self.provider == "aws":
                import boto3
                sm = boto3.client("secretsmanager", region_name=self.region_or_project or "us-east-1")
                kwargs = {"SecretId": secret_name, "SecretString": new_value}
                if self.kms_key_id:
                    kwargs["ClientRequestToken"] = str(uuid.uuid4())
                sm.put_secret_value(**kwargs)
                logger.info(f"Successfully rotated secret '{secret_name}' on AWS Secrets Manager")
                return True

            elif self.provider == "gcp":
                from google.cloud import secretmanager
                client = secretmanager.SecretManagerServiceClient()
                parent = f"projects/{self.region_or_project}/secrets/{secret_name}"
                client.add_secret_version(
                    request={"parent": parent, "payload": {"data": new_value.encode("utf-8")}}
                )
                logger.info(f"Successfully rotated secret '{secret_name}' on GCP Secret Manager")
                return True

            elif self.provider == "vault":
                if not self.vault_url or not self.vault_token:
                    logger.error("Vault rotation failed: VAULT_ADDR or VAULT_TOKEN not configured")
                    return False
                import httpx
                headers = {"X-Vault-Token": self.vault_token}
                clean_name = secret_name.lstrip("/")
                if not clean_name.startswith("secret/data/") and not clean_name.startswith("v1/"):
                    clean_name = f"secret/data/{clean_name}"
                url = f"{self.vault_url.rstrip('/')}/v1/{clean_name.lstrip('/')}"
                with httpx.Client(timeout=5.0) as client:
                    payload = {"data": {"value": new_value}}
                    if metadata:
                        payload["data"].update(metadata)
                    res = client.post(url, headers=headers, json=payload)
                    if res.status_code in (200, 204):
                        logger.info(f"Successfully rotated secret '{secret_name}' on HashiCorp Vault")
                        return True
                    else:
                        logger.error(f"Vault secret rotation returned HTTP {res.status_code}: {res.text}")
                        return False
        except Exception as e:
            logger.error(f"External rotation failed for secret '{secret_name}': {e}")
            try:
                get_security_alert_dispatcher().send_alert_sync(
                    event_type="secret_rotation_failed",
                    details={"secret_name": secret_name, "provider": self.provider, "error": str(e)},
                    severity="critical"
                )
            except Exception:
                pass
            return False
        return False

    def schedule_rotation(self, secret_name: str, interval_days: int = 90, rotation_lambda_arn: Optional[str] = None) -> bool:
        """Configures automated rotation rules for the secret."""
        try:
            if self.provider == "aws":
                import boto3
                sm = boto3.client("secretsmanager", region_name=self.region_or_project or "us-east-1")
                kwargs = {
                    "SecretId": secret_name,
                    "RotationRules": {"AutomaticallyAfterDays": interval_days}
                }
                if rotation_lambda_arn:
                    kwargs["RotationLambdaARN"] = rotation_lambda_arn
                sm.rotate_secret(**kwargs)
                return True
            elif self.provider == "gcp":
                from google.cloud import secretmanager
                from google.protobuf import duration_pb2
                client = secretmanager.SecretManagerServiceClient()
                name = f"projects/{self.region_or_project}/secrets/{secret_name}"
                rotation = {
                    "rotation_period": duration_pb2.Duration(seconds=interval_days * 86400)
                }
                client.update_secret(request={"secret": {"name": name, "rotation": rotation}, "update_mask": {"paths": ["rotation"]}})
                return True
        except Exception as e:
            logger.warning(f"Could not schedule cloud rotation for '{secret_name}': {e}")
            return False
        return False


class SecurityAlertDispatcher:
    """
    Security Operator Alerting:
    Dispatches notifications to security operators via:
      - Generic Webhook (SECURITY_ALERT_WEBHOOK_URL)
      - Slack Webhook (SLACK_WEBHOOK_URL)
      - PagerDuty Events v2 (PAGERDUTY_ROUTING_KEY / PAGERDUTY_URL)
      - Structured Audit Logging (always active)
    Triggered upon:
      - Secret rotation success or failure
      - Secret quarantine or exposed credential detection
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
        pagerduty_url: str = "https://events.pagerduty.com/v2/enqueue",
    ):
        self.webhook_url = webhook_url or os.environ.get("SECURITY_ALERT_WEBHOOK_URL")
        self.slack_webhook_url = slack_webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.pagerduty_routing_key = pagerduty_routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY")
        self.pagerduty_url = pagerduty_url or os.environ.get("PAGERDUTY_URL", "https://events.pagerduty.com/v2/enqueue")

    async def send_alert(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "warning",
        client: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Dispatches security notification to configured endpoints.
        Returns a summary of dispatch outcomes.
        """
        import httpx
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        alert_payload = {
            "source": "automaintainer-security-plane",
            "event_type": event_type,
            "severity": severity,
            "timestamp": timestamp,
            "details": details,
        }

        log_msg = f"[SECURITY_ALERT] event={event_type} severity={severity} details={details}"
        if severity == "critical":
            logger.critical(log_msg)
        elif severity in ("error", "high"):
            logger.error(log_msg)
        else:
            logger.warning(log_msg)

        outcomes = {"audit_log": True, "webhook": None, "slack": None, "pagerduty": None}

        async def _dispatch_http(c: httpx.AsyncClient):
            if self.webhook_url:
                try:
                    resp = await c.post(self.webhook_url, json=alert_payload, timeout=5.0)
                    outcomes["webhook"] = resp.status_code in (200, 201, 202, 204)
                except Exception as e:
                    logger.warning(f"Failed to deliver security alert to webhook: {e}")
                    outcomes["webhook"] = False

            if self.slack_webhook_url:
                slack_msg = {
                    "text": f":rotating_light: *AutoMaintainer Security Alert* [{severity.upper()}]\n*Event:* `{event_type}`\n```{json.dumps(details, indent=2)}```"
                }
                try:
                    resp = await c.post(self.slack_webhook_url, json=slack_msg, timeout=5.0)
                    outcomes["slack"] = resp.status_code in (200, 204)
                except Exception as e:
                    logger.warning(f"Failed to deliver security alert to Slack: {e}")
                    outcomes["slack"] = False

            if self.pagerduty_routing_key:
                pd_payload = {
                    "routing_key": self.pagerduty_routing_key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": f"AutoMaintainer Security: {event_type}",
                        "severity": severity if severity in ("critical", "error", "warning", "info") else "warning",
                        "source": "automaintainer",
                        "custom_details": details,
                    }
                }
                try:
                    resp = await c.post(self.pagerduty_url, json=pd_payload, timeout=5.0)
                    outcomes["pagerduty"] = resp.status_code in (200, 202)
                except Exception as e:
                    logger.warning(f"Failed to deliver security alert to PagerDuty: {e}")
                    outcomes["pagerduty"] = False

        if client:
            await _dispatch_http(client)
        else:
            try:
                async with httpx.AsyncClient() as c:
                    await _dispatch_http(c)
            except Exception as e:
                logger.debug(f"HTTP alert dispatch exception: {e}")

        return outcomes

    def send_alert_sync(
        self,
        event_type: str,
        details: Dict[str, Any],
        severity: str = "warning",
    ) -> Dict[str, Any]:
        """Synchronous wrapper for alert dispatching in non-async contexts."""
        try:
            import asyncio
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                asyncio.create_task(self.send_alert(event_type, details, severity))
                return {"dispatched_async": True}
            else:
                return asyncio.run(self.send_alert(event_type, details, severity))
        except Exception:
            return {"dispatched_fallback": True}

_alert_dispatcher: Optional[SecurityAlertDispatcher] = None
def get_security_alert_dispatcher() -> SecurityAlertDispatcher:
    global _alert_dispatcher
    if _alert_dispatcher is None:
        _alert_dispatcher = SecurityAlertDispatcher()
    return _alert_dispatcher


class SecretRotationManager:
    """
    Tracks secret versions, enforces rotation intervals, and interfaces with
    external KMS/Vault drivers for proactive key rotation.
    """
    def __init__(
        self,
        resolver: Optional[Any] = None,
        driver: Optional[KmsRotationDriver] = None,
        alert_dispatcher: Optional[SecurityAlertDispatcher] = None,
    ):
        self.resolver = resolver
        self.driver = driver or KmsRotationDriver()
        self.alert_dispatcher = alert_dispatcher or get_security_alert_dispatcher()
        self._secret_metadata: Dict[str, Dict[str, Any]] = {}

    def track_secret(self, secret_name: str, current_version: str, max_age_days: int = 90):
        self._secret_metadata[secret_name] = {
            "version": current_version,
            "max_age_days": max_age_days,
            "registered_at": time.time(),
        }

    def needs_rotation(self, secret_name: str) -> bool:
        meta = self._secret_metadata.get(secret_name)
        if not meta:
            return False
        age_seconds = time.time() - meta["registered_at"]
        return age_seconds > (meta["max_age_days"] * 86400)

    def rotate_secret(self, secret_name: str, new_value: str, new_version: Optional[str] = None) -> bool:
        """Rotates secret externally via driver and updates rotation tracker."""
        ok = self.driver.rotate_secret(secret_name, new_value)
        if ok:
            ver = new_version or str(uuid.uuid4())[:8]
            max_age = self._secret_metadata.get(secret_name, {}).get("max_age_days", 90)
            self.track_secret(secret_name, ver, max_age)
            try:
                self.alert_dispatcher.send_alert_sync(
                    event_type="secret_rotated",
                    details={"secret_name": secret_name, "version": ver, "provider": self.driver.provider},
                    severity="info"
                )
            except Exception:
                pass
        else:
            try:
                self.alert_dispatcher.send_alert_sync(
                    event_type="secret_rotation_failed",
                    details={"secret_name": secret_name, "provider": self.driver.provider},
                    severity="critical"
                )
            except Exception:
                pass
        return ok

class UnifiedSecretResolver:
    """
    Priority Resolution Order:
    1. URI Scheme references:
       - vault://secret_path#key
       - aws-secrets://secret_name#key
       - gcp-secrets://secret_name
    2. AWS Secrets Manager (if AWS_SECRET_MANAGER_ENABLED=true)
    3. GCP Secret Manager (if GCP_PROJECT_ID configured)
    4. HashiCorp Vault (if VAULT_ADDR and VAULT_TOKEN configured)
    5. Environment Variables / .env files
    """
    def __init__(self):
        self.providers = []
        if os.environ.get("AWS_SECRET_MANAGER_ENABLED", "false").lower() == "true":
            self.providers.append(AWSSecretsManagerClient())
        if os.environ.get("GCP_SECRET_MANAGER_ENABLED", "false").lower() == "true" or os.environ.get("GCP_PROJECT_ID"):
            self.providers.append(GCPSecretManagerClient())
        if os.environ.get("VAULT_ADDR"):
            self.providers.append(VaultSecretClient())
        # Always fallback to env
        self.providers.append(EnvSecretProvider())

    def resolve(self, secret_name_or_ref: str, default: Optional[str] = None) -> Optional[str]:
        if not secret_name_or_ref:
            return default

        # Handle URI scheme: vault://path/to/secret#key
        if secret_name_or_ref.startswith("vault://"):
            ref = secret_name_or_ref[len("vault://"):]
            path, _, fragment = ref.partition("#")
            client = VaultSecretClient()
            val = client.get_secret(path, key_field=fragment or None)
            if val is not None:
                return val

        # Handle URI scheme: aws-secrets://path#key
        elif secret_name_or_ref.startswith("aws-secrets://"):
            ref = secret_name_or_ref[len("aws-secrets://"):]
            path, _, fragment = ref.partition("#")
            client = AWSSecretsManagerClient()
            val = client.get_secret(path)
            if val is not None:
                if fragment:
                    try:
                        parsed = json.loads(val)
                        if isinstance(parsed, dict) and fragment in parsed:
                            return str(parsed[fragment])
                    except Exception:
                        pass
                return val

        # Handle URI scheme: gcp-secrets://name
        elif secret_name_or_ref.startswith("gcp-secrets://"):
            ref = secret_name_or_ref[len("gcp-secrets://"):]
            client = GCPSecretManagerClient()
            val = client.get_secret(ref)
            if val is not None:
                return val

        for provider in self.providers:
            val = provider.get_secret(secret_name_or_ref)
            if val is not None and val != "":
                return val
        return default

_secret_resolver: Optional[UnifiedSecretResolver] = None
def get_secret_resolver() -> UnifiedSecretResolver:
    global _secret_resolver
    if _secret_resolver is None:
        _secret_resolver = UnifiedSecretResolver()
    return _secret_resolver
