import hmac
import hashlib
import pytest
from automaintainer.github.webhook_verifier import GitHubWebhookVerifier, WebhookVerificationError

def test_webhook_signature_verification_success():
    secret = "super_secret_webhook_key"
    raw_body = b'{"action": "opened", "pull_request": {"id": 123}}'
    
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    
    assert GitHubWebhookVerifier.verify(raw_body, signature, secret) is True

def test_webhook_signature_tampered_payload_rejected():
    secret = "super_secret_webhook_key"
    raw_body = b'{"action": "opened", "pull_request": {"id": 123}}'
    tampered_body = b'{"action": "opened", "pull_request": {"id": 999}}'
    
    signature = "sha256=" + hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    
    with pytest.raises(WebhookVerificationError):
        GitHubWebhookVerifier.verify(tampered_body, signature, secret)

def test_webhook_missing_signature_rejected():
    secret = "super_secret_webhook_key"
    raw_body = b'{"action": "opened"}'
    
    with pytest.raises(WebhookVerificationError):
        GitHubWebhookVerifier.verify(raw_body, None, secret)
