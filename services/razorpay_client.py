"""Razorpay gateway client"""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional, Protocol

from ..config import get_settings
from .integrity import canonicalize


class GatewayError(Exception):
   

    def __init__(self, message: str, *, kind: str = "rejected") -> None:
        super().__init__(message)
        self.kind = kind


class Gateway(Protocol):
    mode: str  # "mock" | "live"

    def get_payment(self, payment_id: str) -> dict: ...
    def hold_payment(self, payment_id: str, reason: str) -> dict: ...
    def create_refund(self, payment_id: str, amount_in_paise: int, reason: str) -> dict: ...


def _stable_id(prefix: str, *parts: str) -> str:
    """Deterministic demo id (uuid5) — the same action always yields the same ref."""
    return f"{prefix}_{uuid.uuid5(uuid.NAMESPACE_URL, ':'.join(parts)).hex[:12]}"


class MockGateway:
    

    mode = "mock"

    def __init__(self) -> None:
        self.payments: dict[str, dict] = {}
        self.holds: dict[str, dict] = {}
        self.refunds: dict[str, dict] = {}
        self.refunded: dict[str, int] = {}  # payment_id -> cumulative refunded paise
        # Round-3: gateway ops are called from API worker threads (uvicorn
        # threadpool) — the refund-cap check-then-insert must be atomic or two
        # concurrent refunds can both pass the cap (TOCTOU). The GIL does not
        # make the check+insert pair atomic.
        self._lock = threading.Lock()

    def _refunded_total(self, payment_id: str) -> int:
        # Recompute from the refund store: the single source of truth.
        return sum(r["amount"] for r in self.refunds.values()
                   if r.get("payment_id") == payment_id)

    # -- registration (demo seeds / pipeline can register the payment shape) --
    def register_payment(
        self,
        payment_id: str,
        *,
        amount_in_paise: int,
        currency: str = "INR",
        status: str = "captured",
        method: str = "upi",
        merchant_id: str = "",
        signature: str = "",
    ) -> None:
        self.payments[payment_id] = {
            "id": payment_id,
            "amount": amount_in_paise,
            "currency": currency,
            "status": status,
            "method": method,
            "merchant_id": merchant_id,
            "created_at": int(datetime.now(timezone.utc).timestamp()),
        }
        if signature:
            self.payments[payment_id]["signature"] = signature

    #  gateway operations 
    def get_payment(self, payment_id: str) -> dict:
        if payment_id not in self.payments:
            raise GatewayError(f"payment {payment_id} not found")
        return dict(self.payments[payment_id])

    def hold_payment(self, payment_id: str, reason: str) -> dict:
        """Contract: api/v1/payments/hold/{id} (proposed Razorpay integration).

        In live test mode this maps to refund-creation + dispute response (P1).
        """
        pay = self.get_payment(payment_id)  # raises if unknown
        with self._lock:  # atomic cap check (Round-3 TOCTOU fix)
            if self._refunded_total(payment_id) >= pay["amount"]:
                raise GatewayError(
                    f"payment {payment_id} already fully refunded; hold not applicable")
            hold_id = _stable_id("hold", payment_id, reason)
            hold = {
                "id": hold_id,
                "payment_id": payment_id,
                "status": "active",
                "reason": reason,
                "created_at": int(datetime.now(timezone.utc).timestamp()),
            }
            self.holds[hold_id] = hold
        return dict(hold)

    def create_refund(self, payment_id: str, amount_in_paise: int, reason: str) -> dict:
        pay = self.get_payment(payment_id)
        with self._lock:  # atomic cap check-then-insert (Round-3 TOCTOU fix)
            cum = self._refunded_total(payment_id)
            if cum + amount_in_paise > pay["amount"]:
                # Provider-invariant mirror (real Razorpay: 409 CONFLICT) — the
                # cumulative refunded amount may never exceed the payment amount.
                raise GatewayError(
                    f"refund amount exceeds payment amount "
                    f"(already refunded {cum} of {pay['amount']} paise)")
            refund_id = _stable_id("rfnd", payment_id, str(amount_in_paise), reason)
            refund = {
                "id": refund_id,
                "payment_id": payment_id,
                "amount": amount_in_paise,
                "currency": pay["currency"],
                "status": "processed",
                "reason": reason,
                "created_at": int(datetime.now(timezone.utc).timestamp()),
            }
            self.refunds[refund_id] = refund
        return dict(refund)

    def verify_signature(self, payload: dict, signature: str) -> bool:
        """Mock of Razorpay's HMAC check: sha256 over canonical payload (float-free)."""
        expected = hashlib.sha256(canonicalize(payload)).hexdigest()
        return signature == expected


class LiveGateway:
   

    mode = "live"
    TIMEOUT_S = 10.0

    def __init__(self) -> None:
        s = get_settings()
        if not (s.razorpay_key_id and s.razorpay_key_secret):
            raise GatewayError("LiveGateway requires RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET (test mode)")
        self._auth = (s.razorpay_key_id, s.razorpay_key_secret)
        self.API_BASE = str(s.razorpay_api_base or "https://api.razorpay.com/v1").rstrip("/")
        # Audit SEC-09: a non-TLS API base is only allowed for loopback (the
        # local test emulator). Basic-auth credentials must never cross a
        # remote network in the clear.
        if self.API_BASE.startswith("http://"):
            from urllib.parse import urlparse
            host = urlparse(self.API_BASE).hostname or ""
            if host not in ("127.0.0.1", "localhost"):
                raise GatewayError(
                    "RAZORPAY_API_BASE with http:// is only allowed for loopback "
                    "(local test emulator); use https:// for any remote host"
                )

    def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        import httpx  # local import: mock mode never touches the network

        try:
            r = httpx.request(
                method, f"{self.API_BASE}{path}",
                auth=self._auth, json=json_body, timeout=self.TIMEOUT_S,
            )
        except httpx.HTTPError as e:
            # R2-13: transport failure — retry later makes sense.
            raise GatewayError(f"razorpay transport error: {type(e).__name__}",
                               kind="unreachable") from e
        if r.status_code >= 400:
            # R2-13: the gateway refused the action (e.g. 409 double refund).
            raise GatewayError(f"razorpay {r.status_code}: {r.text[:200]}",
                               kind="rejected")
        try:
            return r.json()
        except ValueError as e:
            raise GatewayError("razorpay returned non-JSON") from e

    def get_payment(self, payment_id: str) -> dict:
        return self._request("GET", f"/payments/{payment_id}")

    def hold_payment(self, payment_id: str, reason: str) -> dict:
        # No public hold API (P1): live mapping = full refund + dispute notes.
        pay = self.get_payment(payment_id)
        # FINAL F5: a misbehaving/misconfigured gateway can return 1e999
        # (→ inf) or junk; int() would OverflowError → 500. Fail closed.
        try:
            amount = int(pay.get("amount", 0))
        except (TypeError, ValueError, OverflowError):
            raise GatewayError(
                f"payment {payment_id} returned a non-integer amount "
                f"({pay.get('amount')!r})")
        if amount <= 0:
            raise GatewayError(f"payment {payment_id} has no refundable amount")
        refund = self.create_refund(payment_id, amount, reason)
        return {**refund, "mapped_from": "hold", "payment_id": payment_id}

    def create_refund(self, payment_id: str, amount_in_paise: int, reason: str) -> dict:
        return self._request("POST", "/refunds", {
            "payment_id": payment_id,
            "amount": amount_in_paise,
            "currency": "INR",
            "notes": {"sentinel": "remediation", "sentinel_reason": reason[:200]},
        })

    def verify_signature(self, payload: dict, signature: str) -> bool:
        """Protocol-compat shim (R2-11, documented): no route calls this on
        the live gateway. Real webhook verification runs over the RAW body in
        services/webhook_verify (see api/routes/webhook.py); this re-routes a
        CANONICALIZED payload for interface parity only."""
        from .integrity import canonicalize
        from .webhook_verify import verify_razorpay_webhook

        s = get_settings()
        if not s.razorpay_webhook_secret:
            return False
        return verify_razorpay_webhook(canonicalize(payload), signature, s.razorpay_webhook_secret)


# process-wide singleton 
_gateway: Optional[Gateway] = None


def get_gateway() -> Gateway:
    global _gateway
    if _gateway is None:
        s = get_settings()
        if s.razorpay_live:
            try:
                _gateway = LiveGateway()
            except Exception as e:
                # R2-05: fail soft to mock for the demo (the badge + /health
                # show the mode) — but a live INTENT degrading to mock must be
                # loud in the logs, never silent.
                import logging
                logging.getLogger("sentinel.razorpay_client").critical(
                    "RAZORPAY_LIVE=1 but LiveGateway initialization failed (%s: %s) — "
                    "falling back to the in-memory MOCK gateway. Check "
                    "RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET/RAZORPAY_API_BASE.",
                    type(e).__name__, e,
                )
                _gateway = MockGateway()
        else:
            _gateway = MockGateway()
    return _gateway
