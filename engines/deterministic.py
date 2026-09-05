"""Stage 2 — Deterministic gate (zero-LLM, pure functions).

Design §4.2. Inputs are validated schema objects + plain policy/registry dicts;
output is DeterministicOutput (contracts.py). No I/O, fully unit-testable.

Trust rule: the gateway payload (payment) is ground truth; trace steps are
untrusted. The merchant check prefers the registry domain bound to
payment.merchant_id over any domain the trace claims (the rail breaks ties).
"""

import json
from datetime import datetime
from typing import Optional

from ..schemas.ingest import RazorpayPaymentEvent, TraceLog, UserMandate, inr_to_paise
from .contracts import ConstraintCheckResult, DeterministicOutput, FindingResult


def _budget_limit_paise(mandate: UserMandate) -> int:
    return inr_to_paise(mandate.budget_limit_inr)


def _last(trace: list[TraceLog], action: str) -> Optional[TraceLog]:
    for t in reversed(trace):
        if t.action == action:
            return t
    return None


def _trace_merchant_domain(trace: list[TraceLog]) -> tuple[Optional[str], Optional[str]]:
    """Return (domain, evidence_ref) of the last trace step declaring a domain."""
    for t in reversed(trace):
        d = t.parameters.get("merchant_domain")
        if d:
            return d, f"trace.step:{t.step}.parameters.merchant_domain"
    return None, None


def run(
    mandate: UserMandate,
    trace: list[TraceLog],
    payment: RazorpayPaymentEvent,
    *,
    policy: dict,
    registry: dict,
    duplicate_payment: bool = False,
    claimed_time: Optional[datetime] = None,
    session_payments: Optional[list[tuple[str, int]]] = None,
) -> DeterministicOutput:
    out = DeterministicOutput()
    tol_paise = int(policy["tolerances"]["amount_tolerance_paise"])
    markup_tol_pct = float(policy["tolerances"]["markup_tolerance_pct"])
    limit_paise = _budget_limit_paise(mandate)
    sev = {k: v.get("severity", "soft") for k, v in policy["constraints"].items()}

    # --- 4.2.1 payment-level checks ---------------------------------------

    # budget (hard)
    breach_ratio = 0.0
    if limit_paise > 0:
        breach_ratio = max(0.0, (payment.amount_in_paise - limit_paise) / limit_paise)
    budget_pass = payment.amount_in_paise <= limit_paise + tol_paise
    out.constraint_checks.append(
        ConstraintCheckResult(
            constraint="budget", scope="payment", step_no=None, passed=budget_pass,
            observed_value=payment.amount_in_paise, limit_value=limit_paise,
            severity=sev.get("budget", "hard"), breach_ratio=round(breach_ratio, 4),
        )
    )
    if not budget_pass:
        out.findings.append(
            FindingResult(
                "BUDGET_EXCEEDED", "CRITICAL",
                f"Settled amount {payment.amount_in_paise} paise exceeds budget "
                f"{limit_paise} paise (breach {breach_ratio:.1%}).",
                "payment.amount_in_paise",
            )
        )

    # merchant (hard) — registry (ground truth) wins over trace claims
    registry_domain = (registry.get(payment.merchant_id) or {}).get("domain")
    trace_domain, trace_domain_ref = _trace_merchant_domain(trace)
    incomplete = False
    if registry_domain:
        settled_domain = registry_domain
        evidence_ref = "payment.merchant_id"
    elif trace_domain:
        settled_domain = trace_domain
        evidence_ref = trace_domain_ref
        incomplete = True  # untrusted source only
    else:
        settled_domain = None
        evidence_ref = "payment.merchant_id"
        incomplete = True
    # Audit SEC-13: domain comparison is case-insensitive — "Amazon.in" and
    # "amazon.in" are the same merchant; case differences must not raise
    # spurious CRITICAL findings (false-positive alarm fatigue).
    allowed_lc = {str(m).lower() for m in mandate.allowed_merchants}
    merchant_pass = settled_domain is not None and str(settled_domain).lower() in allowed_lc
    out.constraint_checks.append(
        ConstraintCheckResult(
            constraint="merchant", scope="payment", step_no=None, passed=merchant_pass,
            observed_value=settled_domain or "unknown", limit_value=list(mandate.allowed_merchants),
            severity=sev.get("merchant", "hard"),
        )
    )
    if not merchant_pass:
        out.findings.append(
            FindingResult(
                "MERCHANT_NOT_ALLOWED", "CRITICAL",
                f"Settlement merchant domain '{settled_domain or 'unknown'}' is not in the "
                f"allowed list {mandate.allowed_merchants}.",
                evidence_ref,
            )
        )
    if incomplete:
        out.findings.append(
            FindingResult(
                "TELEMETRY_INCOMPLETE", "MINOR",
                "No registry entry for merchant_id and/or no trace merchant_domain; "
                "merchant verified from best available source only.",
                evidence_ref,
            )
        )
    return _finish_payment_checks(out, mandate, trace, payment, policy, sev,
                                   tol_paise, markup_tol_pct, limit_paise,
                                   duplicate_payment, claimed_time,
                                   session_payments)


def _finish_payment_checks(out, mandate, trace, payment, policy, sev,
                           tol_paise, markup_tol_pct, limit_paise,
                           duplicate_payment, claimed_time,
                           session_payments: Optional[list[tuple[str, int]]] = None) -> DeterministicOutput:
    # category (soft) — from last select_item; skip + flag if absent
    last_select = _last(trace, "select_item")
    item_category = last_select.parameters.get("item_category") if last_select else None
    if item_category is None:
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="category", scope="payment", step_no=None, passed=True,
                observed_value="unspecified", limit_value=list(mandate.allowed_categories),
                severity=sev.get("category", "soft"),
            )
        )
        out.findings.append(
            FindingResult(
                "TELEMETRY_INCOMPLETE", "MINOR",
                "No item_category provided in trace; category constraint not verifiable.",
                "trace.select_item.parameters.item_category",
            )
        )
    else:
        cat_pass = item_category in mandate.allowed_categories
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="category", scope="payment", step_no=None, passed=cat_pass,
                observed_value=item_category, limit_value=list(mandate.allowed_categories),
                severity=sev.get("category", "soft"),
            )
        )
        if not cat_pass:
            out.findings.append(
                FindingResult(
                    "CATEGORY_NOT_ALLOWED", "MAJOR",
                    f"Item category '{item_category}' not in allowed categories "
                    f"{mandate.allowed_categories}.",
                    _select_item_ref(trace, "item_category"),
                )
            )

    # time_window (soft) — agent-claimed timestamp judged, never trusted for ordering
    window = policy["constraints"]["time_window"].get("window_hours", [8, 20])
    window_label = f"{window[0]:02d}:00-{window[1]:02d}:00"
    if claimed_time is None:
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="time_window", scope="payment", step_no=None, passed=True,
                observed_value="unspecified", limit_value=window_label,
                severity=sev.get("time_window", "soft"),
            )
        )
        out.findings.append(
            FindingResult(
                "TELEMETRY_INCOMPLETE", "MINOR",
                "No claimed payment timestamp; time-window constraint not verifiable.",
                "timestamp",
            )
        )
    else:
        hour_frac = claimed_time.hour + claimed_time.minute / 60.0
        tw_pass = window[0] <= hour_frac < window[1]
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="time_window", scope="payment", step_no=None, passed=tw_pass,
                observed_value=claimed_time.strftime("%H:%M"), limit_value=window_label,
                severity=sev.get("time_window", "soft"),
            )
        )
        if not tw_pass:
            out.findings.append(
                FindingResult(
                    "TIME_WINDOW_VIOLATION", "MINOR",
                    f"Payment at {claimed_time.strftime('%H:%M')} outside permitted window {window_label}.",
                    "timestamp",
                )
            )

    # trace_gateway (hard) — G4: agent's declared total vs settled amount (int paise)
    last_checkout = _last(trace, "click_checkout")
    declared_paise = last_checkout.parameters.get("declared_total_inr_paise") if last_checkout else None
    if declared_paise is None:
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="trace_gateway", scope="payment", step_no=None, passed=True,
                observed_value="unspecified", limit_value="n/a",
                severity=sev.get("trace_gateway", "hard"),
            )
        )
        out.findings.append(
            FindingResult(
                "TELEMETRY_INCOMPLETE", "MINOR",
                "No declared_total_inr in final checkout step; trace/gateway amount "
                "cross-check not verifiable.",
                "trace.click_checkout.parameters.declared_total_inr_paise",
            )
        )
    else:
        diff_pct = (abs(payment.amount_in_paise - declared_paise) / declared_paise * 100.0) if declared_paise > 0 else 100.0
        tg_pass = diff_pct <= markup_tol_pct
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="trace_gateway", scope="payment", step_no=None, passed=tg_pass,
                observed_value=payment.amount_in_paise, limit_value=int(declared_paise),
                severity=sev.get("trace_gateway", "hard"),
            )
        )
        if not tg_pass:
            out.findings.append(
                FindingResult(
                    "TRACE_GATEWAY_MISMATCH", "CRITICAL",
                    f"Agent declared total {int(declared_paise)} paise at checkout but gateway "
                    f"settled {payment.amount_in_paise} paise (diff {diff_pct:.1%}).",
                    "trace.click_checkout.parameters.declared_total_inr_paise",
                )
            )

    # duplicate detection (hard) — cross-session payment_id reuse
    if duplicate_payment:
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="duplicate_payment", scope="payment", step_no=None, passed=False,
                observed_value=payment.payment_id, limit_value="unique across sessions",
                severity="hard",
            )
        )
        out.findings.append(
            FindingResult(
                "DUPLICATE_PAYMENT", "CRITICAL",
                f"payment_id {payment.payment_id} already recorded under a different session.",
                "payment.payment_id",
            )
        )

    # cumulative_budget (hard) — budget splitting across multiple payments in
    # one session. Only meaningful with >=2 distinct payments, so a single
    # oversized payment is penalized once (by 'budget'), never twice.
    if session_payments and len(session_payments) >= 2 and limit_paise > 0:
        total = sum(a for _, a in session_payments)
        cum_breach = max(0.0, (total - limit_paise) / limit_paise)
        cum_pass = total <= limit_paise + tol_paise
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="cumulative_budget", scope="payment", step_no=None,
                passed=cum_pass, observed_value=total, limit_value=limit_paise,
                severity=sev.get("cumulative_budget", "hard"),
                breach_ratio=round(cum_breach, 4),
            )
        )
        if not cum_pass:
            out.findings.append(
                FindingResult(
                    "CUMULATIVE_BUDGET_EXCEEDED", "CRITICAL",
                    f"Session total {total} paise across {len(session_payments)} payments "
                    f"exceeds the mandate budget {limit_paise} paise (breach {cum_breach:.1%}).",
                    "payment.amount_in_paise (session aggregate)",
                )
            )

    # merchant_drift (hard, step) — the agent moved between merchant domains
    # mid-session (redirect/hijack indicator). Marked at the step where the
    # new domain first appears; feeds divergence_point.
    domains_seen: list[tuple[int, str]] = []
    for t in trace:
        md = t.parameters.get("merchant_domain")
        if md:
            mdl = str(md).lower()  # audit SEC-13: case-insensitive drift compare
            if not domains_seen or domains_seen[-1][1] != mdl:
                domains_seen.append((t.step, mdl))
    if len({d for _, d in domains_seen}) > 1:
        drift_step = domains_seen[1][0]
        shown = " -> ".join(d for _, d in domains_seen[:5])
        out.constraint_checks.append(
            ConstraintCheckResult(
                constraint="merchant_drift", scope="step", step_no=drift_step,
                passed=False, observed_value=shown, limit_value="single merchant domain",
                severity=sev.get("merchant_drift", "hard"),
            )
        )
        out.findings.append(
            FindingResult(
                "MERCHANT_DOMAIN_DRIFT", "CRITICAL",
                f"Agent moved between merchant domains during the session: {shown}. "
                "Consistent with a redirect or page hijack between search and checkout.",
                f"trace.step:{drift_step}.parameters.merchant_domain",
            )
        )

    # repeated_action (soft) — identical action+parameters repeated
    # (retry-loop / flapping anomaly).
    repeat_min = int(policy["tolerances"].get("repeat_action_min", 3))
    if len(trace) >= repeat_min:
        counts: dict[tuple, int] = {}
        first_step: dict[tuple, int] = {}
        for t in trace:
            key = (t.action, json.dumps(t.parameters, sort_keys=True, default=str))
            counts[key] = counts.get(key, 0) + 1
            first_step.setdefault(key, t.step)
        hot = [(k, n) for k, n in counts.items() if n >= repeat_min]
        if hot:
            (action, _params_json), n = max(hot, key=lambda x: x[1])
            out.constraint_checks.append(
                ConstraintCheckResult(
                    constraint="repeated_action", scope="payment", step_no=None,
                    passed=False, observed_value=f"{action} x{n}",
                    limit_value=f"<= {repeat_min - 1} identical steps",
                    severity=sev.get("repeated_action", "soft"),
                )
            )
            out.findings.append(
                FindingResult(
                    "REPEATED_AGENT_ACTION", "MAJOR",
                    f"Identical action '{action}' with identical parameters repeated {n} times "
                    f"(first at step {first_step[(action, _params_json)]}) — retry-loop or flapping anomaly.",
                    f"trace.step:{first_step[(action, _params_json)]}.action",
                )
            )

    # post_checkout (soft) — agent activity after the FINAL click_checkout.
    checkout_steps = [t.step for t in trace if t.action == "click_checkout"]
    # EDG-B3: a captured payment with NO checkout step anywhere in the trace is
    # an evidence-quality red flag (visible MINOR finding; TIS-neutral).
    if not checkout_steps and payment.status.lower() == "captured":
        out.findings.append(
            FindingResult(
                "NO_CHECKOUT_STEP", "MINOR",
                "Payment is captured but the trace contains no click_checkout step; "
                "the declared-vs-settled cross-check is impossible and the trace may "
                "be incomplete or filtered.",
                "trace.agent_trace_logs",
            )
        )
    if checkout_steps:
        after = [t for t in trace if t.step > max(checkout_steps)]
        if after:
            out.constraint_checks.append(
                ConstraintCheckResult(
                    constraint="post_checkout", scope="step", step_no=after[0].step,
                    passed=False, observed_value=" -> ".join(t.action for t in after[:5]),
                    limit_value="no activity after final checkout",
                    severity=sev.get("post_checkout", "soft"),
                )
            )
            out.findings.append(
                FindingResult(
                    "POST_CHECKOUT_ACTIVITY", "MAJOR",
                    f"Agent performed {len(after)} action(s) after the final checkout "
                    f"({', '.join(t.action for t in after[:5])}) — unusual for a completed purchase.",
                    f"trace.step:{after[0].step}.action",
                )
            )

    # --- 4.2.2 step-level constraint projection (G3: divergence source) ----
    for t in trace:
        if t.action != "select_item":
            continue
        p = t.parameters
        listed_paise = p.get("listed_price_paise")
        if listed_paise is not None and int(listed_paise) > limit_paise + tol_paise:
            out.constraint_checks.append(
                ConstraintCheckResult(
                    constraint="budget", scope="step", step_no=t.step, passed=False,
                    observed_value=int(listed_paise), limit_value=limit_paise,
                    severity="hard",
                )
            )
        md = p.get("merchant_domain")
        # FINAL F2: case-insensitive — the payment-level merchant check is
        # case-insensitive (SEC-13); the step-level projection must match or
        # 'Amazon.In' hard-fails a step while the payment passes.
        if md is not None and str(md).lower() not in {str(m).lower() for m in mandate.allowed_merchants}:
            out.constraint_checks.append(
                ConstraintCheckResult(
                    constraint="merchant", scope="step", step_no=t.step, passed=False,
                    observed_value=md, limit_value=list(mandate.allowed_merchants),
                    severity="hard",
                )
            )
        ic = p.get("item_category")
        if ic is not None and ic not in mandate.allowed_categories:
            out.constraint_checks.append(
                ConstraintCheckResult(
                    constraint="category", scope="step", step_no=t.step, passed=False,
                    observed_value=ic, limit_value=list(mandate.allowed_categories),
                    severity="soft",
                )
            )

    hard_steps = [
        c.step_no for c in out.constraint_checks
        if c.scope == "step" and c.severity == "hard" and not c.passed and c.step_no is not None
    ]
    out.divergence_point = min(hard_steps) if hard_steps else None
    return out


def _select_item_ref(trace: list[TraceLog], key: str) -> str:
    t = _last(trace, "select_item")
    if t is not None:
        return f"trace.step:{t.step}.parameters.{key}"
    return f"trace.select_item.parameters.{key}"
