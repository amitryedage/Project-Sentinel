"""Incident read endpoints — list, detail, trace replay, evidence (design §8)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from ...database import get_db
from ...models import (
    ConstraintCheck,
    EvidencePacket,
    EvidenceLedger,
    Incident,
    PaymentEvent,
    Score,
    SemanticResult,
    Finding,
    Session,
    TraceStep,
)
from ...services.integrity import verify_chain

router = APIRouter(tags=["incidents"])


def _incident_or_404(db: DbSession, incident_id: str) -> Incident:
    if not incident_id.startswith("inc_"):
        raise HTTPException(status_code=404, detail="incident_id must look like inc_<n>")
    try:
        n = int(incident_id.split("_", 1)[1])
    except ValueError:
        raise HTTPException(status_code=404, detail="invalid incident_id")
    inc = db.query(Incident).filter_by(id=n).first()
    if inc is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return inc


LIST_LIMIT_DEFAULT = 200
LIST_LIMIT_CAP = 1000


@router.get("/api/v1/incidents")
def list_incidents(
    limit: int = LIST_LIMIT_DEFAULT, offset: int = 0, db: DbSession = Depends(get_db)
):
    """Incident board. Paginated + batched (audit R-01): exactly 3 queries per
    page regardless of page size (was 1 + 2N). Backward-compatible: callers
    without params get the first 200, as before (demos hold tens)."""
    # Consistent clamp (audit Q-07 + FINAL F6): absent or non-positive ->
    # default 200, cap 1000 — same semantics as the batch export limit.
    limit = LIST_LIMIT_DEFAULT if limit is None or limit <= 0 else min(limit, LIST_LIMIT_CAP)
    offset = max(0, offset)
    incs = (
        db.query(Incident)
        .order_by(Incident.created_at, Incident.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    if not incs:
        return []
    ids = [i.id for i in incs]
    session_ids = [i.session_id for i in incs]
    pay_by_session: dict[str, PaymentEvent] = {}
    # Order by amount desc so setdefault keeps the session's PRINCIPAL payment
    # (largest) — the same deterministic rule the gateway actions use (SEC-14).
    for p in (db.query(PaymentEvent)
              .filter(PaymentEvent.session_id.in_(session_ids))
              .order_by(PaymentEvent.amount_in_paise.desc(), PaymentEvent.id.asc()).all()):
        pay_by_session.setdefault(p.session_id, p)
    score_by_inc = {
        s.incident_id: s
        for s in db.query(Score).filter(Score.incident_id.in_(ids)).all()
    }
    out = []
    for inc in incs:
        pay = pay_by_session.get(inc.session_id)
        s = score_by_inc.get(inc.id)
        out.append({
            "incident_id": f"inc_{inc.id}",
            "session_id": inc.session_id,
            "status": inc.status,
            "tis": s.tis if s else None,
            "amount_in_paise": pay.amount_in_paise if pay else None,
            "merchant_name": pay.merchant_name if pay else None,
            "divergence_point": inc.divergence_point,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
        })
    return out


@router.get("/api/v1/incidents/{incident_id}")
def incident_detail(incident_id: str, db: DbSession = Depends(get_db)):
    inc = _incident_or_404(db, incident_id)
    checks = db.query(ConstraintCheck).filter_by(incident_id=inc.id).order_by(ConstraintCheck.id).all()
    findings = db.query(Finding).filter_by(incident_id=inc.id).order_by(Finding.id).all()
    sem = db.query(SemanticResult).filter_by(incident_id=inc.id).first()
    score = db.query(Score).filter_by(incident_id=inc.id).first()
    return {
        "incident_id": incident_id,
        "session_id": inc.session_id,
        "status": inc.status,
        "divergence_point": inc.divergence_point,
        "constraint_checks": [
            {
                "constraint": c.constraint, "scope": c.scope, "step_no": c.step_no,
                "passed": c.passed, "observed_value": c.observed_value,
                "limit_value": c.limit_value, "severity": c.severity,
            }
            for c in checks
        ],
        "findings": [
            {
                "finding_type": f.finding_type, "severity": f.severity,
                "description": f.description, "evidence_ref": f.evidence_ref,
            }
            for f in findings
        ],
        "semantic": {
            "alignment_score": sem.alignment_score,
            "engine_mode": sem.engine_mode,
            "engine_id": sem.engine_id,
            # Phase 3: full engine output incl. the LLM attempt record
            # (model, latency, fallback reason, added/corroborated findings).
            # Read-only, behind the API key — operator-grade audit detail.
            "raw": sem.raw,
        } if sem else None,
        "score": {
            "s_det": score.s_det, "s_sem": score.s_sem, "w_det": score.w_det,
            "w_sem": score.w_sem, "tis": score.tis,
            "override_applied": score.override_applied, "derivation": score.derivation,
        } if score else None,
    }


@router.get("/api/v1/sessions/{session_id}/trace")
def session_trace(session_id: str, db: DbSession = Depends(get_db)):
    """Replay feed: steps in causal order, per-step flags, divergence highlighted."""
    if db.query(Session).filter_by(session_id=session_id).first() is None:
        raise HTTPException(status_code=404, detail="session not found")
    inc = db.query(Incident).filter_by(session_id=session_id).first()
    step_flags = (
        db.query(ConstraintCheck)
        .join(Incident, Incident.id == ConstraintCheck.incident_id)
        .filter(Incident.session_id == session_id, ConstraintCheck.scope == "step")
        .all()
    )
    flags_by_step: dict[int, list[dict]] = {}
    for c in step_flags:
        if c.step_no is not None:
            flags_by_step.setdefault(c.step_no, []).append(
                {"constraint": c.constraint, "passed": c.passed, "severity": c.severity}
            )
    steps = db.query(TraceStep).filter_by(session_id=session_id).order_by(TraceStep.step).all()
    return {
        "session_id": session_id,
        "divergence_point": inc.divergence_point if inc else None,
        "status": inc.status if inc else None,
        "steps": [
            {
                "step": t.step,
                "action": t.action,
                "parameters": t.parameters,
                "result_summary": t.result_summary,
                "flags": flags_by_step.get(t.step, []),
                "is_divergence_point": inc is not None and t.step == inc.divergence_point,
            }
            for t in steps
        ],
    }


@router.get("/api/v1/incidents/{incident_id}/evidence")
def incident_evidence(incident_id: str, db: DbSession = Depends(get_db)):
    """The evidence packet + live chain verification (tamper-evident proof)."""
    inc = _incident_or_404(db, incident_id)
    pkt = db.query(EvidencePacket).filter_by(incident_id=inc.id).first()
    if pkt is None:
        raise HTTPException(status_code=404, detail="evidence packet not found")
    rows = (
        db.query(EvidenceLedger)
        .filter_by(session_id=inc.session_id)
        .order_by(EvidenceLedger.seq)
        .all()
    )
    ok, broken = verify_chain(
        [(r.seq, r.payload, r.prev_hash, r.hash) for r in rows]
    )
    return {
        **pkt.packet,
        "verify": {"ok": ok, "first_broken_seq": broken, "chain_rows": len(rows)},
    }
