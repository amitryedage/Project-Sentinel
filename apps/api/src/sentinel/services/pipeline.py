"""Evaluation pipeline — orchestrates"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session as DbSession

from ..config import get_settings, merchant_registry as reg_cache, policy as policy_cache, policy_version
from ..engines.deterministic import run as det_run
from ..engines.evidence import build_packet, finalize_proof, jsonable
from ..engines.llm import enhance as llm_enhance
from ..engines.scoring import compute as score_compute
from ..engines.semantic import ENGINE_ID, analyze as sem_analyze
from ..models import (
    ConstraintCheck,
    EvidenceLedger,
    EvidencePacket,
    EvaluationRun,
    Finding,
    Incident,
    Mandate,
    PaymentEvent,
    PolicyVersion,
    Remediation,
    Score,
    SemanticResult,
    Session,
    TraceStep,
)
from ..schemas.ingest import InboundTelemetry, inr_to_paise, normalize_trace
from .integrity import chain_hash, genesis_hash
from .razorpay_client import MockGateway, get_gateway


def _mandate_payload(m: Mandate) -> dict:
    return {
        "original_query": m.original_query,
        "budget_limit_paise": m.budget_limit_paise,
        "allowed_categories": m.allowed_categories,
        "allowed_merchants": m.allowed_merchants,
        "mandate_source": m.mandate_source,
    }


def _step_payload(t: TraceStep) -> dict:
    return {
        "step": t.step,
        "action": t.action,
        "parameters": jsonable(t.parameters),
        "result_summary": t.result_summary,
    }


def _payment_payload(p: PaymentEvent) -> dict:
    return {
        "payment_id": p.payment_id,
        "amount_in_paise": p.amount_in_paise,
        "currency": p.currency,
        "merchant_id": p.merchant_id,
        "merchant_name": p.merchant_name,
        "status": p.status,
        "method": p.method,
        "signature": p.signature,
        "claimed_timestamp": p.claimed_timestamp.isoformat() if p.claimed_timestamp else None,
    }


def _ledger_tail(db: DbSession, session_id: str) -> tuple[int, str]:
    row = (
        db.query(EvidenceLedger)
        .filter_by(session_id=session_id)
        .order_by(EvidenceLedger.seq.desc())
        .first()
    )
    if row is None:
        return 0, genesis_hash()
    return row.seq, row.hash


def ingest_and_evaluate(db: DbSession, tel: InboundTelemetry) -> dict:
    now = datetime.now(timezone.utc)
    policy = policy_cache()      # audit Q-04: cached (versioned, restart-reload)
    registry = reg_cache()
    pver = policy_version()
    trace = normalize_trace(tel.agent_trace_logs)
    pe = tel.razorpay_payment_event

    #  1. persist telemetry 
    sess = db.query(Session).filter_by(session_id=tel.session_id).first()
    if sess is None:
        sess = Session(session_id=tel.session_id, ingested_at=now, status="pending")
        db.add(sess)
        db.flush()

    mandate = db.query(Mandate).filter_by(session_id=tel.session_id).first()
    if mandate is None:  # first mandate wins on re-ingest
        mandate = Mandate(
            session_id=tel.session_id,
            original_query=tel.user_mandate.original_query,
            budget_limit_paise=inr_to_paise(tel.user_mandate.budget_limit_inr),
            allowed_categories=tel.user_mandate.allowed_categories,
            allowed_merchants=tel.user_mandate.allowed_merchants,
            mandate_source="principal",
        )
        db.add(mandate)
        db.flush()

    db.query(TraceStep).filter_by(session_id=tel.session_id).delete()
    for t in trace:
        db.add(
            TraceStep(
                session_id=tel.session_id, step=t.step, action=t.action,
                parameters=t.parameters, result_summary=t.result_summary,
            )
        )

    payment = (
        db.query(PaymentEvent)
        .filter_by(session_id=tel.session_id, payment_id=pe.payment_id)
        .first()
    )
    if payment is None:
        payment = PaymentEvent(session_id=tel.session_id, **{
            "payment_id": pe.payment_id, "amount_in_paise": pe.amount_in_paise,
            "currency": pe.currency, "merchant_id": pe.merchant_id,
            "merchant_name": pe.merchant_name, "status": pe.status,
            "method": pe.method, "signature": pe.signature,
            "claimed_timestamp": tel.timestamp, "raw": pe.model_dump(),
        })
        db.add(payment)
    else:
        prev_status = payment.status
        for k in ("amount_in_paise", "currency", "merchant_id", "merchant_name",
                  "status", "method", "signature"):
            setattr(payment, k, getattr(pe, k))
       
        if prev_status == "refunded":
            payment.status = "refunded"
        payment.claimed_timestamp = tel.timestamp
        payment.raw = pe.model_dump()
    db.flush()

    duplicate = (
        db.query(PaymentEvent)
        .filter(PaymentEvent.payment_id == pe.payment_id,
                PaymentEvent.session_id != tel.session_id)
        .first()
        is not None
    )

    
    gateway = get_gateway()
    if isinstance(gateway, MockGateway):
        gateway.register_payment(
            pe.payment_id, amount_in_paise=pe.amount_in_paise, currency=pe.currency,
            status=pe.status, method=pe.method, merchant_id=pe.merchant_id,
            signature=pe.signature,
        )

    #  first ingest chains the telemetry events 
    if db.query(EvidenceLedger).filter_by(session_id=tel.session_id).count() == 0:
        seq, prev = 0, genesis_hash()
        for etype, payload in (
            [("mandate", _mandate_payload(mandate))]
            + [("trace_step", _step_payload(t)) for t in trace]
            + [("payment_event", _payment_payload(payment))]
        ):
            seq += 1
            h = chain_hash(prev, payload)
            db.add(EvidenceLedger(
                session_id=tel.session_id, seq=seq, event_type=etype, payload=payload,
                prev_hash=prev, hash=h, recorded_at=now,
            ))
            prev = h
        db.flush()

    #  engines
  
    session_payments = [
        (p.payment_id, p.amount_in_paise)
        for p in db.query(PaymentEvent).filter_by(session_id=tel.session_id).all()
    ]
    det = det_run(
        tel.user_mandate, trace, pe,
        policy=policy, registry=registry,
        duplicate_payment=duplicate, claimed_time=tel.timestamp,
        session_payments=session_payments,
    )
    sem = sem_analyze(
        tel.user_mandate, trace, pe,
        markup_tolerance_pct=float(policy["tolerances"]["markup_tolerance_pct"]),
        drift_max_overlap=float(
            policy["tolerances"].get("semantic_drift_max_overlap", 0.45)
        ),
    )
 
    settings = get_settings()
    if settings.semantic_mode == "llm" and settings.llm_api_base and settings.llm_model:
        sem = llm_enhance(sem, tel.user_mandate, trace, pe, settings)
    score = score_compute(det, sem, policy=policy, policy_version=pver)

    # --- 4. persist incident + children (recomputed per run) --------------
    incident = db.query(Incident).filter_by(session_id=tel.session_id).first()
    if incident is None:
        incident = Incident(session_id=tel.session_id, status="pending", created_at=now)
        db.add(incident)
        db.flush()
    for model in (ConstraintCheck, Finding, SemanticResult, Score, EvidencePacket):
        db.query(model).filter_by(incident_id=incident.id).delete()

    for c in det.constraint_checks:
        limit_str = (
            ",".join(str(x) for x in c.limit_value)
            if isinstance(c.limit_value, (list, tuple))
            else str(c.limit_value)
        )
      
        db.add(ConstraintCheck(
            incident_id=incident.id, constraint=c.constraint, scope=c.scope,
            step_no=c.step_no, passed=c.passed,
            observed_value=str(c.observed_value)[:512],
            limit_value=limit_str[:512], severity=c.severity,
        ))
    for f in [*det.findings, *sem.findings]:
        db.add(Finding(
            incident_id=incident.id, finding_type=f.finding_type, severity=f.severity,
            description=f.description, evidence_ref=f.evidence_ref, penalty=f.penalty,
        ))
    db.add(SemanticResult(
        incident_id=incident.id, alignment_score=sem.alignment_score,
        engine_mode=sem.engine_mode, engine_id=sem.engine_id, raw=jsonable(sem.raw),
    ))
    db.add(Score(
        incident_id=incident.id, s_det=score.s_det, s_sem=score.s_sem,
        w_det=score.w_det, w_sem=score.w_sem, tis=score.tis,
        override_applied=score.override_applied, derivation=jsonable(score.derivation),
    ))
   
    executed = (
        db.query(Remediation)
        .filter_by(incident_id=incident.id, status="executed")
        .first()
        is not None
    )
    incident.status = "remediated" if executed else score.status
    incident.divergence_point = det.divergence_point

    # evaluation ledger event (append-only) + packet 
    seq, prev = _ledger_tail(db, tel.session_id)
    eval_payload = {
        "status": score.status,
        "tis_x10": int(round(score.tis * 10)),
        "divergence_point": det.divergence_point,
        "policy_version": pver,
        "engine_mode": sem.engine_mode,
        "engine_id": sem.engine_id,
        "hard_failures": score.derivation["override"]["hard_failures"],
        "findings": sorted({f.finding_type for f in [*det.findings, *sem.findings]}),
    }
    h = chain_hash(prev, eval_payload)
    db.add(EvidenceLedger(
        session_id=tel.session_id, seq=seq + 1, event_type="evaluation",
        payload=eval_payload, prev_hash=prev, hash=h, recorded_at=now,
    ))
    db.flush()

    incident_id_str = f"inc_{incident.id}"
    packet = build_packet(
        incident_id=incident_id_str, session_id=tel.session_id, policy_version=pver,
        det=det, sem=sem, score=score, mandate=tel.user_mandate, payment=pe,
        evaluation_timestamp=now,
    )
    packet = finalize_proof(packet, chain_head=h, chain_length=seq + 1)
    db.add(EvidencePacket(
        incident_id=incident.id, packet=packet, chain_head=h,
        packet_hash=packet["tamper_evident_proof"]["packet_hash"], created_at=now,
    ))

    if db.query(PolicyVersion).filter_by(version=pver).first() is None:
        db.add(PolicyVersion(version=pver, policy=policy, created_at=now))
    run_seq = db.query(EvaluationRun).filter_by(session_id=tel.session_id).count() + 1
    db.add(EvaluationRun(
        session_id=tel.session_id, run_seq=run_seq, policy_version=pver,
        engine_mode=sem.engine_mode, engine_id=sem.engine_id, started_at=now, finished_at=now,
    ))

    sess.status = incident.status
    db.commit()

    return {
        "session_id": tel.session_id,
        "incident_id": incident_id_str,
        # Audit SEC-02: report the incident's ACTUAL status — 'remediated' when
        # frozen (an executed remediation), not the fresh score's status.
        "status": incident.status,
        "tis": score.tis,
        "divergence_point": det.divergence_point,
        "findings": sorted({f.finding_type for f in [*det.findings, *sem.findings]}),
        "chain_length": seq + 1,
    }
