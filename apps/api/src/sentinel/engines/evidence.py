"""Stage 4 — Evidence packet builder (design §4.4/§8, Listing 4.1 + extensions).

The stored packet is FLOAT-FREE (floats stringified) so it can be canonically
hashed — the artifact is self-verifying: chain_head binds it to the ledger,
packet_hash binds the artifact itself.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from ..schemas.ingest import RazorpayPaymentEvent, UserMandate, inr_to_paise
from ..services.integrity import canonicalize
from .contracts import DeterministicOutput, ScoreOutput, SemanticOutput

SEVERITY_ORDER = {"CRITICAL": 0, "MAJOR": 1, "MINOR": 2}


def jsonable(x: Any) -> Any:
    """float → str, datetime → iso; everything else passes through.

    Used for anything that will be canonically hashed (ledger payloads, packet).
    """
    if isinstance(x, float):
        return str(x)
    if isinstance(x, datetime):
        return x.isoformat()
    if isinstance(x, dict):
        return {k: jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [jsonable(v) for v in x]
    return x


def _flags(det: DeterministicOutput, sem: SemanticOutput) -> list[dict]:
    flags = [
        {"severity": f.severity, "type": f.finding_type, "description": f.description, "evidence_ref": f.evidence_ref}
        for f in [*det.findings, *sem.findings]
    ]
    return sorted(flags, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["type"]))


def _suggested_remediation(score: ScoreOutput, det: DeterministicOutput, sem: SemanticOutput, payment_id: str) -> dict:
    hard = score.derivation["override"]["hard_failures"]
    types = {f.finding_type for f in [*det.findings, *sem.findings]}
    if not hard and score.status == "clear":
        return {"action": "NONE", "reason": "No action required — transaction is consistent with the mandate."}
    reasons = []
    if "budget" in hard:
        reasons.append("budget exceeded")
    if "merchant" in hard:
        reasons.append("settlement merchant not allowed")
    if "trace_gateway" in hard:
        reasons.append("declared vs settled amount mismatch")
    if "duplicate_payment" in hard:
        reasons.append("duplicate payment id across sessions")
    if "PROMPT_INJECTION" in types:
        reasons.append("suspected prompt injection")
    if "PRODUCT_SUBSTITUTION" in types:
        reasons.append("product substitution")
    if "PRICE_MARKUP" in types:
        reasons.append("price markup")
    return {
        "action": "TEMPORARY_PAYOUT_HOLD",
        "razorpay_gateway_trigger": f"api/v1/payments/hold/{payment_id}",
        "live_mode_mapping": "api/v1/refunds (test mode); hold is a proposed Razorpay integration contract",
        "step_up_verification": "PROMPT_INJECTION" in types,
        "reason": "; ".join(reasons) or "integrity score below threshold",
    }


def build_packet(
    *,
    incident_id: str,
    session_id: str,
    policy_version: str,
    det: DeterministicOutput,
    sem: SemanticOutput,
    score: ScoreOutput,
    mandate: UserMandate,
    payment: RazorpayPaymentEvent,
    evaluation_timestamp: datetime,
) -> dict:
    return {
        "incident_id": incident_id,
        "session_id": session_id,
        "evaluation_timestamp": evaluation_timestamp.isoformat(),
        "policy_version": policy_version,
        "engine": {"mode": sem.engine_mode, "id": sem.engine_id},
        "status": score.status,
        "divergence_point": det.divergence_point,
        "mandate_summary": {
            "original_query": mandate.original_query,
            "budget_limit_paise": inr_to_paise(mandate.budget_limit_inr),
            "allowed_categories": list(mandate.allowed_categories),
            "allowed_merchants": list(mandate.allowed_merchants),
        },
        "payment_summary": {
            "payment_id": payment.payment_id,
            "amount_in_paise": payment.amount_in_paise,
            "currency": payment.currency,
            "merchant_id": payment.merchant_id,
            "merchant_name": payment.merchant_name,
            "status": payment.status,
        },
        "scores": {
            "constraint_checks": [
                {
                    "constraint": c.constraint, "scope": c.scope, "step_no": c.step_no,
                    "passed": c.passed, "observed_value": jsonable(c.observed_value),
                    "limit_value": jsonable(c.limit_value), "severity": c.severity,
                }
                for c in det.constraint_checks
            ],
            "s_det": str(score.s_det),
            "s_sem": str(score.s_sem),
            "w_det": str(score.w_det),
            "w_sem": str(score.w_sem),
            "final_integrity_score": str(score.tis),
        },
        "flags": _flags(det, sem),
        "derivation": jsonable(score.derivation),
        "suggested_remediation": _suggested_remediation(score, det, sem, payment.payment_id),
        "tamper_evident_proof": {"chain_head": None, "chain_length": None, "packet_hash": None},
    }


def packet_hash(packet: dict) -> str:
    """sha256 over the canonical packet with only packet_hash nulled (chain_head/length ARE covered)."""
    p = dict(packet)
    proof = dict(p["tamper_evident_proof"])
    proof["packet_hash"] = None
    p["tamper_evident_proof"] = proof
    return hashlib.sha256(canonicalize(p)).hexdigest()


def finalize_proof(packet: dict, *, chain_head: str, chain_length: int) -> dict:
    p = dict(packet)
    proof = dict(p["tamper_evident_proof"])
    proof.update({"chain_head": chain_head, "chain_length": chain_length})
    p["tamper_evident_proof"] = proof
    p["tamper_evident_proof"]["packet_hash"] = packet_hash(p)
    return p
