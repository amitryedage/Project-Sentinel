"""Stage 3 — Semantic alignment.

Design §4.3. The mock mode is an HONEST heuristic analyzer (G7): real pattern
and keyword logic that genuinely detects on the seeds — not canned verdicts
keyed by session id. The future LLM mode (Slice 3) plugs into the same
interface and returns the same shape.

The LLM/heuristic NEVER holds verdict authority — hard flags come from the
deterministic engine (P3).
"""

import re
from typing import Optional

from ..schemas.ingest import RazorpayPaymentEvent, TraceLog, UserMandate
from .contracts import FindingResult, SemanticOutput

ENGINE_ID = "heuristic-v1"

# Injection pattern battery (case-insensitive). Each hit is evidence, not a verdict.
INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("injected_system_notice", re.compile(r"(urgent|important|critical)[^.]{0,60}(system|admin|notice)", re.I)),
    ("auto_substitute", re.compile(r"auto-?substitute", re.I)),
    ("apply_coupon", re.compile(r"apply\s+(this\s+)?coupon", re.I)),
    ("ignore_instructions", re.compile(r"ignore\s+(previous|prior|all)\s+(instructions?|commands?)", re.I)),
    ("new_instruction", re.compile(r"new\s+instructions?", re.I)),  # FINAL F1: re.I for parity with the battery
]

STOPWORDS = {
    "a", "an", "the", "for", "under", "of", "to", "in", "on", "with", "and", "or",
    "buy", "purchase", "get", "order", "please", "me", "my", "rs", "inr", "replace", "replacement",
}  # 'rs'/'inr' are currency tokens, not product content (Phase 3 calibration)

FINDING_PENALTIES = {
    "PROMPT_INJECTION": 0.35,
    "PRODUCT_SUBSTITUTION": 0.30,
    "PRICE_MARKUP": 0.20,
    "SEMANTIC_DRIFT": 0.30,  # Phase 2: drift alone should warrant human review, not 'clear'
}


def _content_words(text: str) -> set[str]:
    tokens = re.findall(r"[a-z0-9]+", text.lower())
    return {t for t in tokens if not t.isdigit() and t not in STOPWORDS}


def _last_select(trace: list[TraceLog]) -> Optional[TraceLog]:
    for t in reversed(trace):
        if t.action == "select_item":
            return t
    return None


def _step_texts(t: TraceLog) -> list[str]:
    """All attacker-writable text in a step: result_summary + string parameter
    values (injection can hide in parameters, not just summaries — Phase 2)."""
    texts = [t.result_summary or ""]
    for v in (t.parameters or {}).values():
        if isinstance(v, str):
            texts.append(v)
        elif isinstance(v, (list, tuple)):
            texts.extend(x for x in v if isinstance(x, str))
        elif isinstance(v, dict):
            texts.extend(x for x in v.values() if isinstance(x, str))
    return texts


def detect_injections(trace: list[TraceLog]) -> list[tuple[int, list[str]]]:
    """Return [(step_no, [pattern_names]), ...] for steps with pattern hits in
    any writable text (summary or parameter values)."""
    hits = []
    for t in trace:
        names = [name for name, pat in INJECTION_PATTERNS
                 if any(pat.search(x) for x in _step_texts(t))]
        if names:
            hits.append((t.step, names))
    return hits


def analyze(
    mandate: UserMandate,
    trace: list[TraceLog],
    payment: RazorpayPaymentEvent,
    *,
    markup_tolerance_pct: float = 2.0,
    drift_max_overlap: float = 0.45,
) -> SemanticOutput:
    findings: list[FindingResult] = []
    raw: dict = {}

    # 1) PROMPT_INJECTION — pattern battery over every trace summary
    injection_hits = detect_injections(trace)
    if injection_hits:
        first_step, first_names = injection_hits[0]
        all_names = sorted({n for _, ns in injection_hits for n in ns})
        findings.append(
            FindingResult(
                "PROMPT_INJECTION", "CRITICAL",
                "Injected instruction pattern(s) detected in agent trace "
                f"(patterns: {', '.join(all_names)}). Agent appears to have acted on "
                "content originating from the merchant page, not the user mandate.",
                f"trace.step:{first_step}.result_summary",
            )
        )
    raw["injection_hits"] = [{"step": s, "patterns": ns} for s, ns in injection_hits]

    # 2) PRODUCT_SUBSTITUTION — zero shared content words between mandate and final item
    last_select = _last_select(trace)
    item_text = ""
    item_ref = "trace.select_item.parameters.item_name"
    if last_select is not None:
        item_text = str(last_select.parameters.get("item_name") or last_select.parameters.get("item_id") or "")
        item_ref = f"trace.step:{last_select.step}.parameters.item_name"
    mandate_words = _content_words(mandate.original_query)
    item_words = _content_words(item_text)
    raw["mandate_content_words"] = sorted(mandate_words)
    raw["item_words"] = sorted(item_words)
    if mandate_words and item_words and not (mandate_words & item_words):
        findings.append(
            FindingResult(
                "PRODUCT_SUBSTITUTION", "MAJOR",
                f"Final item '{item_text}' shares no content words with the requested "
                f"'{mandate.original_query}' — purchased product is unrelated to the mandate.",
                item_ref,
            )
        )
    elif mandate_words and item_words:
        # 2b) SEMANTIC_DRIFT (Phase 2) — partial overlap: the item relates to
        # the mandate but covers less than the configured fraction of its
        # content words (e.g. 'ergonomic office chair with lumbar support'
        # -> 'office chair'). Full substitution (ratio 0) is reported above;
        # the two findings are mutually exclusive.
        overlap_ratio = len(mandate_words & item_words) / len(mandate_words)
        raw["overlap_ratio"] = round(overlap_ratio, 4)
        if 0 < overlap_ratio < drift_max_overlap:
            findings.append(
                FindingResult(
                    "SEMANTIC_DRIFT", "MINOR",
                    f"Final item '{item_text}' only partially matches the mandate "
                    f"(content-word overlap {overlap_ratio:.0%} < {drift_max_overlap:.0%}) — "
                    f"possible scope or spec drift.",
                    item_ref,
                )
            )

    # 3) PRICE_MARKUP — settled amount materially above the item's listed price (int paise)
    listed_paise = last_select.parameters.get("listed_price_paise") if last_select else None
    diff_pct = 0.0
    if listed_paise:
        diff_pct = (payment.amount_in_paise - int(listed_paise)) / int(listed_paise) * 100.0
        if diff_pct > markup_tolerance_pct:
            findings.append(
                FindingResult(
                    "PRICE_MARKUP", "MAJOR",
                    f"Settled amount {payment.amount_in_paise} paise exceeds listed price "
                    f"{int(listed_paise)} paise by {diff_pct:.1%} (tolerance {markup_tolerance_pct}%).",
                    f"trace.step:{last_select.step}.parameters.listed_price_paise",
                )
            )
    raw["price_diff_pct"] = round(diff_pct, 4)

    # alignment score: 1 - min(1, Σ finding penalties)
    penalty_sum = min(1.0, sum(FINDING_PENALTIES[f.finding_type] for f in findings))
    raw["finding_penalties"] = {f.finding_type: FINDING_PENALTIES[f.finding_type] for f in findings}

    return SemanticOutput(
        alignment_score=round(1.0 - penalty_sum, 4),
        findings=findings,
        raw=raw,
        engine_mode="mock",
        engine_id=ENGINE_ID,
    )
