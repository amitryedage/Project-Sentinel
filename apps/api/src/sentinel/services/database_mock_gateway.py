"""Mock gateway whose state survives function restarts and separate workers."""
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..database import SessionLocal
from ..models import MockGatewayOperation, PaymentEvent
from .razorpay_client import GatewayError, _stable_id


class DatabaseMockGateway:
    mode = "mock"

    @staticmethod
    def _payment(db, payment_id, *, lock=False):
        # Always lock the oldest row for a payment, even across duplicate sessions.
        query = select(PaymentEvent).where(PaymentEvent.payment_id == payment_id).order_by(PaymentEvent.id).limit(1)
        if lock:
            query = query.with_for_update()
        pay = db.scalars(query).first()
        if pay is None:
            raise GatewayError("payment not found")
        return pay

    def get_payment(self, payment_id):
        with SessionLocal() as db:
            pay = self._payment(db, payment_id)
            return {"id": payment_id, "amount": pay.amount_in_paise,
                    "currency": pay.currency, "status": pay.status,
                    "merchant_id": pay.merchant_id, "method": pay.method}

    def _record(self, action, payment_id, amount, reason):
        reference = _stable_id("rfnd" if action == "refund" else "hold", payment_id, str(amount), reason)
        with SessionLocal.begin() as db:
            pay = self._payment(db, payment_id, lock=True)
            existing = db.get(MockGatewayOperation, reference)
            if existing:
                return dict(existing.payload)
            refunded = db.scalar(select(func.coalesce(func.sum(MockGatewayOperation.amount), 0)).where(
                MockGatewayOperation.payment_id == payment_id))
            if action == "refund" and (amount <= 0 or refunded + amount > pay.amount_in_paise):
                raise GatewayError("refund amount exceeds remaining payment amount or is not positive")
            if action == "hold" and refunded >= pay.amount_in_paise:
                raise GatewayError("payment already fully refunded")
            payload = {"id": reference, "payment_id": payment_id,
                       "status": "processed" if action == "refund" else "active",
                       "reason": reason, "created_at": int(datetime.now(timezone.utc).timestamp())}
            if action == "refund":
                payload.update(amount=amount, currency=pay.currency)
            db.add(MockGatewayOperation(reference=reference, payment_id=payment_id,
                                        amount=amount, payload=payload))
            return dict(payload)

    def hold_payment(self, payment_id, reason):
        return self._record("hold", payment_id, 0, reason)

    def create_refund(self, payment_id, amount_in_paise, reason):
        return self._record("refund", payment_id, amount_in_paise, reason)
