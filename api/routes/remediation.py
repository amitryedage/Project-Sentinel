"""Remediation endpoints — the human-in-the-loop gate (Slice 2 design §3).

Gate invariant: no gateway call executes without an explicit approve carrying
`approved_by`. The pipeline and engines never touch the gateway.
Every execution/approval/rejection is appended to the evidence ledger
(chain-of-custody — the case file records WHO approved WHAT).

Concurrency (SEC-A6): approve/reject win by atomic conditional UPDATE
(proposed -> executing), so concurrent callers cannot double-execute a
gateway action; failed executions roll the claim back to 'proposed'.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.remediation")
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from ...database import get_db
from ...models import EvidenceLedger, EvidencePacket, Incident, PaymentEvent, Remediation
from ...security import _s
from ...services.integrity import chain_hash, genesis_hash
from ...services.razorpay_client import GatewayError, get_gateway
from .incidents import _incident_or_404

router = APIRouter(tags=["remediation"])

VALID_ACTIONS = {"hold", "refund", "review", "step_up"}

# packet-level action names → API-level actions
ACTION_ALIASES = {"temporary_payout_hold": "hold", "hold": "hold", "none": "none"}

# Identity charset for approved_by (blocks CR/LF log injection, SEC-A4)
APPROVER_PATTERN = r"^[A-Za-z0-9 ._@\-]{3,128}$"


class Proposal(BaseModel):
    action: Optional[str] = None  # default: the packet's suggested action
    reason: Optional[str] = None


class ApproveRequest(BaseModel):
    approved_by: str = Field(min_length=3, max_length=128, pattern=APPROVER_PATTERN)


class RejectRequest(BaseModel):
    approved_by: str = Field(min_length=3, max_length=128, pattern=APPROVER_PATTERN)
    reason: str = Field(default="", max_length=2000)


def _rem_or_404(db: DbSession, remediation_id: int) -> Remediation:
    rem = db.query(Remediation).filter_by(id=remediation_id).first()
    if rem is None:
        raise HTTPException(status_code=404, detail="remediation not found")
    return rem


def _claim_remediation(db: DbSession, remediation_id: int) -> Remediation:
    """Atomically transition proposed -> executing (SEC-A6 race fix).

    The conditional UPDATE is a single statement, so under concurrency exactly
    one caller wins the claim; the loser sees rowcount 0 and gets a 409.
    On exception the surrounding transaction rolls back and the claim is
    released, so a failed gateway call never leaves the row stuck or lets a
    second caller double-execute.
    """
    result = db.execute(
        update(Remediation)
        .where(Remediation.id == remediation_id, Remediation.status == "proposed")
        .values(status="executing")
    )
    db.flush()
    if result.rowcount == 0:
        existing = db.query(Remediation).filter_by(id=remediation_id).first()
        if existing is None:
            raise HTTPException(status_code=404, detail="remediation not found")
        raise HTTPException(
            status_code=409, detail=f"remediation is {existing.status!r}, not 'proposed'")
    return db.query(Remediation).filter_by(id=remediation_id).first()


def _packet(db: DbSession, inc: Incident) -> dict:
    pkt = db.query(EvidencePacket).filter_by(incident_id=inc.id).first()
    if pkt is None:
        raise HTTPException(status_code=503, detail="evidence packet not found")
    return pkt.packet


def _principal_payment(db: DbSession, session_id: str) -> Optional[PaymentEvent]:
    """Deterministic target for gateway actions (audit SEC-14): the session's
    largest payment, id as tie-break. A multi-payment (split-attack) session
    must not have its hold/refund land on an arbitrary row (no bare .first())."""
    return (
        db.query(PaymentEvent)
        .filter_by(session_id=session_id)
        .order_by(PaymentEvent.amount_in_paise.desc(), PaymentEvent.id.asc())
        .first()
    )


def _append_remediation_event(db: DbSession, inc: Incident, payload: dict, now: datetime) -> None:
    row = (
        db.query(EvidenceLedger)
        .filter_by(session_id=inc.session_id)
        .order_by(EvidenceLedger.seq.desc())
        .first()
    )
    seq, prev = (row.seq, row.hash) if row else (0, genesis_hash())
    h = chain_hash(prev, payload)
    db.add(EvidenceLedger(
        session_id=inc.session_id, seq=seq + 1, event_type="remediation",
        payload=payload, prev_hash=prev, hash=h, recorded_at=now,
    ))


@router.post("/api/v1/incidents/{incident_id}/remediation", status_code=201)
def propose(incident_id: str, body: Proposal, db: DbSession = Depends(get_db)):
    inc = _incident_or_404(db, incident_id)
    packet = _packet(db, inc)
    suggested = packet["suggested_remediation"]["action"].lower()
    action = ACTION_ALIASES.get((body.action or suggested).lower(), (body.action or suggested).lower())
    if action == "none":
        raise HTTPException(status_code=400, detail="packet suggests no action for this incident")
    if action not in VALID_ACTIONS:
        raise HTTPException(status_code=422, detail=f"action must be one of {sorted(VALID_ACTIONS)}")
    rem = Remediation(incident_id=inc.id, action=action, status="proposed")
    db.add(rem)
    db.commit()
    db.refresh(rem)
    return {
        "remediation_id": rem.id,
        "incident_id": incident_id,
        "action": action,
        "status": "proposed",
        "suggested_reason": packet["suggested_remediation"]["reason"],
    }


@router.post("/api/v1/remediation/{remediation_id}/approve")
def approve(remediation_id: int, body: ApproveRequest, db: DbSession = Depends(get_db)):
    rem = _claim_remediation(db, remediation_id)  # atomic proposed->executing (SEC-A6)
    inc = db.query(Incident).filter_by(id=rem.incident_id).first()
    if inc is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="incident not found")

    packet = _packet(db, inc)
    reason = packet["suggested_remediation"]["reason"]
    gateway = get_gateway()
    now = datetime.now(timezone.utc)

    # Phase 1 (EDG-205): commit the claim BEFORE the external side effect.
    # Even if this request then crashes, no concurrent approver can re-claim,
    # so a gateway action can never be executed twice.
    db.commit()

    ref: Optional[str] = None
    pay = None
    try:
        if rem.action in ("hold", "refund"):
            pay = _principal_payment(db, inc.session_id)
            if pay is None:
                raise GatewayError("no payment event on session")
            if rem.action == "hold":
                result = gateway.hold_payment(pay.payment_id, f"sentinel: {reason}")
            else:
                result = gateway.create_refund(pay.payment_id, pay.amount_in_paise, f"sentinel: {reason}")
            # Audit SEC-07: clamp to the column width so an over-long gateway ref
            # cannot DataError the recording commit AFTER the side effect.
            ref = str(result.get("id") or "")[:64]
        else:  # review / step_up — human process, no gateway call
            ref = None
    except GatewayError as e:
        rem.status = "proposed"  # no side effect happened; release the claim
        db.commit()
        logger.warning("approve %s failed at gateway: %s", _s(remediation_id), _s(str(e)))
        # R2-13: stable machine-usable reason token — operators/automation can
        # tell "retry later" (unreachable) from "retry is pointless"
        # (rejected, e.g. double-refund cap) without parsing prose.
        raise HTTPException(status_code=502, detail=f"gateway error ({e.kind}): {e}")

    # Phase 2: record the executed action. Bounded retry covers concurrent
    # ledger appends on the same session (seq unique constraint). After a
    # successful gateway call the claim is NEVER auto-released: if recording
    # finally fails, the row stays 'executing' for operator review — a visible
    # inconsistency, never a silent double execution.
    payload = {
        "action": rem.action, "status": "executed",
        "approved_by": body.approved_by, "razorpay_ref": ref, "reason": reason,
        # Audit SEC-14: evidence of WHICH payment the gateway action targeted
        # (the deterministic principal payment, never an arbitrary row).
        "payment_id": pay.payment_id if pay is not None else None,
    }
    recorded = False
    for _attempt in range(5):
        try:
            _append_remediation_event(db, inc, payload, now)
            rem.status = "executed"
            rem.approved_by = body.approved_by
            rem.executed_at = now
            rem.razorpay_ref = ref
            # Audit SEC-02: an executed action makes the case 'remediated' — a
            # durable, export-visible disposition (frozen against re-evaluation;
            # see pipeline.ingest_and_evaluate).
            inc.status = "remediated"
            db.commit()
            recorded = True
            break
        except IntegrityError as e:
            db.rollback()
            logger.warning("ledger append contention on approve %s (attempt %s): %s",
                           _s(remediation_id), _attempt + 1, _s(str(e)))
    if not recorded:
        db.commit()
        logger.critical("approve %s: gateway executed (ref=%s) but ledger recording failed; "
                        "row left in 'executing' for operator review", _s(remediation_id), _s(ref))
        raise HTTPException(
            status_code=500,
            detail="action executed but could not be recorded; remediation left in 'executing' for operator review")
    return {
        "remediation_id": rem.id,
        "status": "executed",
        "action": rem.action,
        "approved_by": body.approved_by,
        "razorpay_ref": ref,
        "gateway": gateway.mode,
    }


@router.post("/api/v1/remediation/{remediation_id}/reject")
def reject(remediation_id: int, body: RejectRequest, db: DbSession = Depends(get_db)):
    # Same atomic claim as approve: concurrent approve/reject cannot both win.
    rem = _claim_remediation(db, remediation_id)
    inc = db.query(Incident).filter_by(id=rem.incident_id).first()
    if inc is None:
        db.rollback()
        raise HTTPException(status_code=404, detail="incident not found")
    db.commit()  # commit the claim (no external side effect; safe to release on failure)
    now = datetime.now(timezone.utc)
    recorded = False
    for _attempt in range(5):
        try:
            _append_remediation_event(db, inc, {
                "action": rem.action, "status": "rejected",
                "approved_by": body.approved_by, "razorpay_ref": None, "reason": body.reason,
            }, now)
            rem.status = "rejected"
            rem.approved_by = body.approved_by
            db.commit()
            recorded = True
            break
        except IntegrityError as e:
            db.rollback()
            logger.warning("ledger append contention on reject %s (attempt %s): %s",
                           _s(remediation_id), _attempt + 1, _s(str(e)))
    if not recorded:
        rem.status = "proposed"  # no side effect; safe to release the claim
        db.commit()
        logger.critical("reject %s could not be recorded; remediation reset to 'proposed'",
                        _s(remediation_id))
        raise HTTPException(status_code=500, detail="rejection could not be recorded; retry")
    return {"remediation_id": rem.id, "status": "rejected", "approved_by": body.approved_by}


@router.get("/api/v1/incidents/{incident_id}/remediations")
def remediation_history(incident_id: str, db: DbSession = Depends(get_db)):
    inc = _incident_or_404(db, incident_id)
    rows = db.query(Remediation).filter_by(incident_id=inc.id).order_by(Remediation.id).all()
    return [
        {
            "remediation_id": r.id,
            "action": r.action,
            "status": r.status,
            "approved_by": r.approved_by,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "razorpay_ref": r.razorpay_ref,
        }
        for r in rows
    ]
