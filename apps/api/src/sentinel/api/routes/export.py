"""Dispute & evidence export — the Stage 4 deliverable (Phase 4).

GET /api/v1/incidents/{incident_id}/export
    A self-contained, AAA-shaped dispute packet (architecture Listing 4.1 +
    the full case file): scores with explicit derivation, flags, mandate /
    payment / trace / ledger evidence, and a tamper-evident proof block
    carrying the chain head, live chain verification, the packet hash, and a
    timestamp-authority signature (HMAC-SHA256, the HSM equivalent of
    Listing 4.1's `timestamp_authority_signature`).

GET /api/v1/incidents/export?status=flagged&limit=50
    Batch export (e.g. every flagged incident for a dispute submission).

Security:
- Read-only, behind the shared API key.
- The signature is a one-way HMAC: the export proves authenticity and
  integrity to anyone holding the (out-of-band) signing secret, without the
  secret ever appearing in the artifact.
- Signing secret: SENTINEL_SIGNING_SECRET, falling back to the API key.
- Float-free: every money value is int paise; the payload is canonicalized
  before signing, so ANY byte change breaks the signature.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from ...config import get_settings
from ...database import get_db
from ...engines.evidence import jsonable
from ...models import (
    ConstraintCheck,
    EvidenceLedger,
    EvidencePacket,
    Incident,
    Mandate,
    PaymentEvent,
    Remediation,
    Score,
    SemanticResult,
    TraceStep,
)
from ...services.integrity import canonicalize, verify_chain
from .incidents import _incident_or_404

logger = logging.getLogger("sentinel.export")

router = APIRouter(tags=["export"])

VALID_STATUS_FILTERS = {"clear", "review", "flagged", "remediated"}
BATCH_LIMIT_CAP = 100


def _signing_secret() -> str:
    s = get_settings()
    return s.sentinel_signing_secret or s.api_key


def _signing_base(doc: dict) -> dict:
    """Signing input: the document with the signature field set to null."""
    base = dict(doc)
    proof = dict(base.get("tamper_evident_proof") or {})
    proof["timestamp_authority_signature"] = None
    base["tamper_evident_proof"] = proof
    return base


def _sign(doc: dict) -> str:
    """HMAC-SHA256 over the canonical signing input (signature field = null)."""
    mac = hmac.new(
        _signing_secret().encode("utf-8"), canonicalize(_signing_base(doc)), hashlib.sha256
    ).hexdigest()
    return f"sha256hmac:{mac}"


def verify_signature(doc: dict) -> bool:
    """Verifier side (anyone holding the signing secret): recompute + compare.

    Never raises: a malformed artifact (non-ASCII signature bytes, float-tainted
    fields, missing structure) is a FAILED verification, not a 500 (audit
    SEC-05) — a verifier that throws on attacker-shaped input is itself a
    bug.
    """
    sig = str((doc.get("tamper_evident_proof") or {}).get("timestamp_authority_signature") or "")
    try:
        return hmac.compare_digest(_sign(doc), sig)
    except (TypeError, ValueError):
        # TypeError: compare_digest refuses non-ASCII str operands.
        # ValueError: canonicalize rejects float-tainted payloads.
        return False


def _build_export(db: DbSession, inc: Incident) -> dict:
    pkt = db.query(EvidencePacket).filter_by(incident_id=inc.id).first()
    if pkt is None:
        raise HTTPException(status_code=503, detail="evidence packet not found")
    score = db.query(Score).filter_by(incident_id=inc.id).first()
    sem = db.query(SemanticResult).filter_by(incident_id=inc.id).first()
    mandate = db.query(Mandate).filter_by(session_id=inc.session_id).first()
    payments = (
        db.query(PaymentEvent).filter_by(session_id=inc.session_id).all()
    )
    trace = (
        db.query(TraceStep).filter_by(session_id=inc.session_id)
        .order_by(TraceStep.step).all()
    )
    ledger = (
        db.query(EvidenceLedger).filter_by(session_id=inc.session_id)
        .order_by(EvidenceLedger.seq).all()
    )
    checks = (
        db.query(ConstraintCheck).filter_by(incident_id=inc.id)
        .order_by(ConstraintCheck.id).all()
    )
    rems = (
        db.query(Remediation).filter_by(incident_id=inc.id).order_by(Remediation.id).all()
    )

    ok, broken = verify_chain(
        [(r.seq, r.payload, r.prev_hash, r.hash) for r in ledger]
    )

    packet = pkt.packet
    executed_rems = [r for r in rems if r.status == "executed"]
    if executed_rems:
        state_note = (
            "Incident status is FROZEN at 'remediated': "
            f"{len(executed_rems)} remediation action(s) executed on this case (see "
            "evidence.remediations). Re-evaluation updates scores and appends to the "
            "ledger but does not change the disposition. The immutable ledger below "
            "contains the full history of every evaluation."
        )
    else:
        state_note = (
            "No executed remediation: status reflects the latest evaluation run. "
            "Evidence.payments/trace are current-state snapshots; the immutable "
            "ledger below preserves every prior state."
        )
    export = {
        "format": "sentinel.dispute-export/1",
        "incident_id": f"inc_{inc.id}",
        "session_id": inc.session_id,
        "evaluation_timestamp": packet.get("evaluation_timestamp"),
        "policy_version": packet.get("policy_version"),
        "status": inc.status,
        "state_note": state_note,
        "divergence_point": inc.divergence_point,
        "scores": {
            "deterministic_valid": bool(score and score.s_det >= 1.0),
            "semantic_alignment_score": str(sem.alignment_score) if sem else None,
            "final_integrity_score": str(score.tis) if score else None,
            "engine": packet.get("engine"),
            "derivation": (score.derivation if score else None),
        },
        "flags": packet.get("flags", []),
        "suggested_remediation": packet.get("suggested_remediation"),
        "evidence": {
            "mandate": {
                "original_query": mandate.original_query,
                "budget_limit_paise": mandate.budget_limit_paise,
                "allowed_categories": mandate.allowed_categories,
                "allowed_merchants": mandate.allowed_merchants,
            } if mandate else None,
            "payments": [
                {
                    "payment_id": p.payment_id, "amount_in_paise": p.amount_in_paise,
                    "currency": p.currency, "merchant_id": p.merchant_id,
                    "merchant_name": p.merchant_name, "status": p.status,
                    "method": p.method,
                    "claimed_timestamp": p.claimed_timestamp.isoformat() if p.claimed_timestamp else None,
                }
                for p in payments
            ],
            "trace": [
                {"step": t.step, "action": t.action,
                 "parameters": t.parameters, "result_summary": t.result_summary}
                for t in trace
            ],
            "constraint_checks": [
                {"constraint": c.constraint, "scope": c.scope, "step_no": c.step_no,
                 "passed": c.passed, "observed_value": c.observed_value,
                 "limit_value": c.limit_value, "severity": c.severity}
                for c in checks
            ],
            "remediations": [
                {"action": r.action, "status": r.status, "approved_by": r.approved_by,
                 "razorpay_ref": r.razorpay_ref,
                 "executed_at": r.executed_at.isoformat() if r.executed_at else None}
                for r in rems
            ],
            # The full tamper-evident case file — every chained event.
            "ledger": [
                {"seq": r.seq, "event_type": r.event_type, "payload": r.payload,
                 "prev_hash": r.prev_hash, "hash": r.hash,
                 "recorded_at": r.recorded_at.isoformat() if r.recorded_at else None}
                for r in ledger
            ],
        },
        "tamper_evident_proof": {
            "hash_chain": pkt.chain_head,
            "chain_length": len(ledger),
            "chain_valid": ok,
            "first_broken_seq": broken,
            "packet_hash": packet.get("tamper_evident_proof", {}).get("packet_hash"),
            "timestamp_authority_signature": None,  # filled below
            "signing_input": (
                "canonicalize(export) with tamper_evident_proof."
                "timestamp_authority_signature set to null; "
                "signature = HMAC-SHA256(sentinel signing secret, signing input)"
            ),
        },
    }
    # Float-free + canonical-portable artifact (G1): floats → strings, dates →
    # iso. This makes the HMAC signing input well-defined and the export
    # self-contained for dispute submission.
    export = jsonable(export)
    export["tamper_evident_proof"]["timestamp_authority_signature"] = _sign(export)
    return export


@router.get("/api/v1/incidents/{incident_id}/export")
def export_incident(incident_id: str, db: DbSession = Depends(get_db)):
    inc = _incident_or_404(db, incident_id)
    return _build_export(db, inc)


@router.get("/api/v1/incidents/export")
def export_batch(
    status: str | None = None, limit: int = 50, db: DbSession = Depends(get_db)
):
    if status is not None and status not in VALID_STATUS_FILTERS:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of {sorted(VALID_STATUS_FILTERS)}",
        )
    # Consistent clamp (audit Q-07): absent or non-positive -> default, cap at 100.
    limit = 50 if (limit is None or limit <= 0) else min(limit, BATCH_LIMIT_CAP)
    q = db.query(Incident).order_by(Incident.created_at, Incident.id)
    if status is not None:
        q = q.filter(Incident.status == status)
    rows = q.limit(limit).all()
    return {
        "format": "sentinel.dispute-export-batch/1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status_filter": status,
        "count": len(rows),
        "incidents": [_build_export(db, inc) for inc in rows],
    }
