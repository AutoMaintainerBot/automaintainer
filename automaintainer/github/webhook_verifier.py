import hmac
import hashlib
from typing import Optional

class WebhookVerificationError(Exception):
    """Raised when webhook signature verification fails."""
    pass

class GitHubWebhookVerifier:
    """
    Constant-time HMAC-SHA256 signature verification against raw request body bytes.
    CRITICAL: Must evaluate raw bytes before any JSON parsing.
    """

    @staticmethod
    def verify(raw_body: bytes, signature_header: Optional[str], secret: str) -> bool:
        """
        Verify GitHub signature (format: 'sha256=<hex_digest>')
        """
        if not signature_header:
            raise WebhookVerificationError("Missing X-Hub-Signature-256 header")

        if not signature_header.startswith("sha256="):
            raise WebhookVerificationError("Invalid signature format: missing 'sha256=' prefix")

        expected_sig = signature_header[len("sha256="):].strip()
        computed_sig = hmac.new(
            key=secret.encode("utf-8") if isinstance(secret, str) else secret,
            msg=raw_body,
            digestmod=hashlib.sha256
        ).hexdigest()

        # Constant-time comparison prevents timing attacks
        if not hmac.compare_digest(expected_sig, computed_sig):
            raise WebhookVerificationError("HMAC signature mismatch")

        return True
