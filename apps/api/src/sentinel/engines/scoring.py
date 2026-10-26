"""TIS (Transaction Integrity Score) — per-constraint, severity-weighted (design §4.4).

Redesign of the architecture doc's binary formula: a small breach and a full
substitution now score differently. The full math is exposed in `derivation`
(G6: "explicit reasons, not a black-box probability").

Penalty table (one penalty per constraint — payment and step rows deduped):
    budget            0.30 + 0.20 × min(1, breach_ratio)
    cumulative_budget 0.30 + 0.20 × min(1, breach_ratio)   (Phase 2)
    merchant          0.50
    merchant_drift    0.35                                  (Phase 2)
    trace_gateway     0.40
    duplicate_payment 0.40
    repeated_action   0.15                                  (Phase 2)
    post_checkout     0.10                                  (Phase 2)
    category          0.10
    time_window       0.10

s_det = max(0, 1 − Σ constraint penalties)
s_sem = semantic alignment score (0..1)
TIS   = round(100 × (w_det·s_det + w_sem·s_sem), 1)
Hard override: any PAYMENT-scope hard failure ⇒ status flagged regardless of TIS.
"""

from .contracts import DeterministicOutput, ScoreOutput, SemanticOutput

CONSTRAINT_PENALTIES_FIXED = {
    "merchant": 0.50,
    "merchant_drift": 0.35,
    "trace_gateway": 0.40,
    "duplicate_payment": 0.40,
    "repeated_action": 0.15,
    "post_checkout": 0.10,
    "category": 0.10,
    "time_window": 0.10,
}


def _constraint_penalty(constraint: str, breach_ratio: float) -> float:
    if constraint in ("budget", "cumulative_budget"):
        return round(0.30 + 0.20 * min(1.0, breach_ratio), 4)
    return CONSTRAINT_PENALTIES_FIXED.get(constraint, 0.10)


def compute(
    det: DeterministicOutput,
    sem: SemanticOutput,
    *,
    policy: dict,
    policy_version: str,
) -> ScoreOutput:
    w_det = float(policy["weights"]["w_det"])
    w_sem = float(policy["weights"]["w_sem"])
    clear_min = float(policy["status_thresholds"]["clear_min_tis"])
    flagged_max = float(policy["status_thresholds"]["flagged_max_tis"])

    # Dedupe by constraint (payment + step rows); keep max breach_ratio.
    by_constraint: dict[str, tuple[bool, str, float]] = {}
    for c in det.constraint_checks:
        if c.passed:
            continue
        cur = by_constraint.get(c.constraint)
        if cur is None or c.breach_ratio > cur[2]:
            by_constraint[c.constraint] = (False, c.severity, c.breach_ratio)

    penalties = {
        name: _constraint_penalty(name, breach)
        for name, (_, _, breach) in by_constraint.items()
    }
    s_det = max(0.0, round(1.0 - sum(penalties.values()), 4))
    s_sem = sem.alignment_score

    hard_failures = sorted(
        name for name, (_, severity, _) in by_constraint.items() if severity == "hard"
    )
    # Phase 2: a CRITICAL finding (deterministic OR semantic) also forces the
    # flag — e.g. prompt injection with otherwise clean constraints must not
    # sit in 'review' indefinitely. (Regression-safe: seeds 001-003 unchanged.)
    critical_findings = sorted({
        f.finding_type for f in [*det.findings, *sem.findings] if f.severity == "CRITICAL"
    })
    override_applied = bool(hard_failures or critical_findings)
    tis = round(100.0 * (w_det * s_det + w_sem * s_sem), 1)

    if override_applied or tis < flagged_max:
        status = "flagged"
    elif tis < clear_min:
        status = "review"
    else:
        status = "clear"

    derivation = {
        "formula": "TIS = round(100 * (w_det*s_det + w_sem*s_sem), 1)",
        "policy_version": policy_version,
        "weights": {"w_det": w_det, "w_sem": w_sem},
        "deterministic": {
            "failed_constraints": {
                name: {"severity": sev, "breach_ratio": breach, "penalty": penalties[name]}
                for name, (failed, sev, breach) in by_constraint.items()
            },
            "s_det": s_det,
        },
        "semantic": {
            "engine_mode": sem.engine_mode,
            "engine_id": sem.engine_id,
            "findings": [f.finding_type for f in sem.findings],
            "s_sem": s_sem,
        },
        "override": {
            "applied": override_applied,
            "hard_failures": hard_failures,
            "critical_findings": critical_findings,
        },
    }

    return ScoreOutput(
        s_det=s_det, s_sem=s_sem, w_det=w_det, w_sem=w_sem, tis=tis,
        override_applied=override_applied, derivation=derivation, status=status,
    )
