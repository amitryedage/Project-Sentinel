

from __future__ import annotations

import hashlib
import hmac


def verify_razorpay_webhook(raw_body: bytes, signature: str, secret: str) -> bool:
    """Constant-time HMAC-SHA256 check of a raw webhook body. Never raises."""
    if not secret or not signature or not isinstance(raw_body, (bytes, bytearray)):
        return False
    expected = hmac.new(secret.encode("utf-8"), bytes(raw_body), hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, signature.strip().lower())
    except Exception:
        return False
