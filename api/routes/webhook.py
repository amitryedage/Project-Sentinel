"""Razorpay webhook receiver — the only external writer (Phase 3, Stage 4).

POST /api/v1/webhooks/razorpay  (NO x-api-key: the caller is Razorpay's
webhook delivery service, authenticated instead by HMAC-SHA256 over the RAW
request body with the per-endpoint webhook secret).

Security model:
- Fail-closed: no webhook secret configured  → 503 (webhooks disabled).
- Bad/missing signature                     → 400, nothing touched.
- Invalid JSON                              → 400.
- Replay: a previously applied ``event_id`` is acknowledged as
  ``duplicate`` without re-applying (idempotent).
- Every VERIFIED event appends a ``gateway_event`` row to the tamper-evident
  evidence ledger (float-free payload, signature_verified=true) — external
  gateway state becomes chain-bound evidence, not just a DB column update.
- Unknown payment (webhook raced ahead of ingest, or foreign payment):
  acknowledged 200 ``ignored`` so the gateway does not retry forever; the
  race window is documented (edge_missing.md).
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DbSession

from ...config import get_settings
from ...database import get_db
from ...models import EvidenceLedger, PaymentEvent, WebhookEvent
from ...security import _s
from ...services.integrity import chain_hash
from ...services.webhook_verify import verify_razorpay_webhook

logger = logging.getLogger("sentinel.webhook")

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

# Gateway statuses we trust onto the payment row (bounded vocabulary).
_PAYMENT_STATUSES = {"created", "authorized", "captured", "failed", "refunded"}


def _ledger_tail(db: DbSession, session_id: str) -> tuple[int, str]:
    row = (
        db.query(EvidenceLedger)
        .filter_by(session_id=session_id)
        .order_by(EvidenceLedger.seq.desc())
        .first()
    )
    if row is None:
        from ...services.integrity import genesis_hash
        return 0, genesis_hash()
    return row.seq, row.hash


def _extract_entity(evt: dict) -> tuple[str, dict]:
    """Return (source_kind, entity) for payment.* and refund.* events."""
    payload = evt.get("payload") or {}
    if isinstance(payload.get("payment"), dict) and isinstance(payload["payment"].get("entity"), dict):
        return "payment", payload["payment"]["entity"]
    if isinstance(payload.get("refund"), dict) and isinstance(payload["refund"].get("entity"), dict):
        return "refund", payload["refund"]["entity"]
    return "", {}


@router.post("/razorpay")
async def razorpay_webhook(request: Request, db: DbSession = Depends(get_db)):
    s = get_settings()
    if not s.razorpay_webhook_secret:
        return JSONResponse(status_code=503, content={"detail": "webhook verification not configured"})

    raw = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    if not verify_razorpay_webhook(raw, signature, s.razorpay_webhook_secret):
        logger.warning("Rejected webhook: invalid signature (%d bytes)", len(raw))
        return JSONResponse(status_code=400, content={"detail": "invalid signature"})

    try:
        evt = json.loads(raw)
        if not isinstance(evt, dict):
            raise ValueError("not an object")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return JSONResponse(status_code=400, content={"detail": "invalid JSON"})

    event_id = str(evt.get("id") or "")[:128]
    if not event_id:
        # Audit SEC-06: fail closed — an event without an id cannot be
        # replay-checked, so it must not be applied (previously every delivery
        # of an id-less event was re-applied, growing the ledger unbounded).
        logger.warning("Rejected webhook: missing event id")
        return JSONResponse(status_code=400, content={"detail": "event id required"})
    event_type = str(evt.get("event") or "")[:32]
    kind, entity = _extract_entity(evt)
    payment_id = str(entity.get("payment_id") or entity.get("id") or "")[:64]
    if kind not in ("payment", "refund") or not payment_id:
        # Verified but not a payment/refund event we act on (e.g. order.*).
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "unhandled_event", "event_id": event_id})

    # Replay protection: durable unique-indexed registry (audit R-02) — O(1)
    # lookup instead of loading every gateway_event row per delivery.
    if db.query(WebhookEvent).filter_by(event_id=event_id).first() is not None:
        return JSONResponse(status_code=200, content={"status": "duplicate", "event_id": event_id})

    rows = db.query(PaymentEvent).filter(PaymentEvent.payment_id == payment_id).all()
    if not rows:
        # Webhook raced ahead of ingest (or foreign payment). Ack, do not
        # 4xx — the gateway would retry into a loop. Documented residual.
        logger.info("Webhook %s for unknown payment %s — acknowledged, not applied",
                    _s(event_type), _s(payment_id))
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "payment_unknown", "event_id": event_id})

    # Determine the new payment status (bounded vocabulary; refund events map
    # to "refunded" only when the refund finalized).
    raw_status = str(entity.get("status") or "").lower()[:32]
    if kind == "refund":
        new_status = "refunded" if raw_status in ("processed", "success") else None
    else:
        new_status = raw_status if raw_status in _PAYMENT_STATUSES else None

    # R2-02: strict money parsing. JSON accepts `1e999` (→ inf) and Python's
    # round(inf) raises OverflowError — which the old (TypeError, ValueError)
    # clause did NOT catch → unhandled 500 → the gateway would retry the
    # event forever. Accept only finite int/float (bool and str rejected —
    # same strictness as the ingest money validators); anything else → None.
    _amt = entity.get("amount")
    if isinstance(_amt, bool) or not isinstance(_amt, (int, float)):
        amount = None
    elif isinstance(_amt, int):
        amount = _amt  # exact — no float() (10**400 would OverflowError)
    elif math.isfinite(_amt):
        amount = int(round(_amt))  # int paise, float-free
    else:
        amount = None
    currency = str(entity.get("currency") or "INR")[:8]

    now = datetime.now(timezone.utc)
    applied_sessions = []
    for payment in rows:
        if new_status:
            payment.status = new_status
        seq, prev = _ledger_tail(db, payment.session_id)
        ledger_payload = {
            "event_id": event_id,
            "event": event_type,
            "payment_id": payment_id,
            "source": kind,
            "status": new_status or raw_status,
            "amount_in_paise": amount,
            "currency": currency,
            "signature_verified": True,
        }
        db.add(EvidenceLedger(
            session_id=payment.session_id, seq=seq + 1, event_type="gateway_event",
            payload=ledger_payload, prev_hash=prev,
            hash=chain_hash(prev, ledger_payload), recorded_at=now,
        ))
        applied_sessions.append(payment.session_id)
    db.add(WebhookEvent(event_id=event_id, recorded_at=now))  # commit with the apply
    db.commit()

    logger.info("Webhook %s applied to payment %s (sessions=%s)",
                _s(event_type), _s(payment_id), ",".join(_s(s) for s in applied_sessions))
    return JSONResponse(status_code=200, content={
        "status": "applied",
        "event_id": event_id,
        "payment_id": payment_id,
        "new_status": new_status,
        "sessions": applied_sessions,
    })
