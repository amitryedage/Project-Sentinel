

from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

SUPPORTED_CURRENCIES = {"INR"}

# Identifier charset (blocks newlines/SQL-ish junk; EDG-A1)
SESSION_ID_PATTERN = r"^[A-Za-z0-9:_\-.]{8,64}$"
MONEY_FIELD_MAX = 10_000_000  # 1 crore INR cap per payment/budget
TRACE_PARAMS_JSON_MAX = 65_536  # serialized size cap for free-form params

# Money-bearing parameter keys the engines parse numerically. Validation lives at
# the API edge (audit SEC-04): a string/bool/nan/inf here used to 500 deep inside
# the engine instead of failing fast with a 422.
MONEY_FLOAT_KEYS = ("listed_price", "declared_total_inr")          # INR, int/float
MONEY_INT_KEYS = ("listed_price_paise", "declared_total_inr_paise")  # paise, int


def _check_money_params(v: dict) -> dict:
    for key in MONEY_FLOAT_KEYS:
        if key in v:
            x = v[key]
            if isinstance(x, bool) or not isinstance(x, (int, float)):
                raise ValueError(f"parameters.{key} must be a number (INR), got {type(x).__name__}")
            # Round-3: NaN/Inf only exist for floats — ints (arbitrary
            # precision JSON integers) must NOT be pushed through
            # math.isnan/isinf (int→float OverflowError → 500).
            if isinstance(x, float) and not math.isfinite(x):
                raise ValueError(f"parameters.{key} must be finite")
            if x < 0:
                raise ValueError(f"parameters.{key} must be >= 0")
    for key in MONEY_INT_KEYS:
        if key in v:
            x = v[key]
            if isinstance(x, bool) or not isinstance(x, int):
                raise ValueError(f"parameters.{key} must be an integer (paise), got {type(x).__name__}")
            if x < 0:
                raise ValueError(f"parameters.{key} must be >= 0")
    return v


def _check_json_size(obj, field_name: str, limit: int = TRACE_PARAMS_JSON_MAX) -> None:
    try:
        size = len(json.dumps(obj, default=str))
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} is not JSON-serializable")
    if size > limit:
        raise ValueError(f"{field_name} too large ({size} bytes > {limit})")


def inr_to_paise(amount_inr) -> int:
    """Canonical money conversion — the ONLY float→int boundary in the system.

    R2-round-3: int inputs (JSON integers can be arbitrary precision) convert
    EXACTLY by multiplication — float() would OverflowError on 10**400 → 500.
    Floats go through round() as before (callers have already validated
    finiteness for the money params that reach here)."""
    if isinstance(amount_inr, int) and not isinstance(amount_inr, bool):
        return amount_inr * 100
    return int(round(float(amount_inr) * 100))


# Money-bearing trace parameter keys → int-paise equivalents (G5/G1:
# chained payloads must be float-free, so normalization happens at ingest).
MONEY_PARAM_KEYS = {
    "listed_price": "listed_price_paise",
    "declared_total_inr": "declared_total_inr_paise",
}


def normalize_trace(trace: list[TraceLog]) -> list[TraceLog]:
    """Replace money params (INR floats) with int-paise params. Idempotent."""
    out = []
    for t in trace:
        params = dict(t.parameters)
        for src, dst in MONEY_PARAM_KEYS.items():
            if src in params and dst not in params:
                # inr_to_paise handles int (exact) vs float (round) — no float()
                # cast here (huge JSON ints would OverflowError).
                params[dst] = inr_to_paise(params.pop(src))
        out.append(TraceLog(step=t.step, action=t.action, parameters=params, result_summary=t.result_summary))
    return out


class UserMandate(BaseModel):
    original_query: str = Field(min_length=1, max_length=8192)
    budget_limit_inr: float = Field(gt=0, le=MONEY_FIELD_MAX)
    allowed_categories: list[str] = Field(default_factory=list, max_length=100)
    allowed_merchants: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("original_query")
    @classmethod
    def _query_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("original_query must not be blank")
        return v

    @field_validator("budget_limit_inr", mode="before")
    @classmethod
    def _budget_not_bool(cls, v: object) -> object:
        # R2-03: pydantic v2 coerces bool → float (true → 1.0) DURING
        # validation, so the check must run BEFORE coercion to see the raw
        # boolean. Every other money field in the system rejects bool
        # explicitly (R2-10: uniform strict money policy at the edge).
        if isinstance(v, bool):
            raise ValueError("budget_limit_inr must be a number (INR), not a boolean")
        return v

    @field_validator("allowed_categories", "allowed_merchants")
    @classmethod
    def _list_items_bounded(cls, v: list[str]) -> list[str]:
        for item in v:
            if not item or len(item) > 256:
                raise ValueError("list items must be non-empty and <= 256 chars")
        return v


class TraceLog(BaseModel):
    step: int = Field(ge=1, le=10_000)
    action: str = Field(min_length=1, max_length=64)  # DB column String(64)
    parameters: dict = Field(default_factory=dict)
    result_summary: str = Field(default="", max_length=10_000)

    @field_validator("parameters")
    @classmethod
    def _params_bounded(cls, v: dict) -> dict:
        _check_json_size(v, "parameters")
        return _check_money_params(v)


class RazorpayPaymentEvent(BaseModel):
    # Lengths aligned with DB columns (String(64/256/32/512)) so 422s happen
    # at the API edge, not as DB errors inside the app (EDG-A2).
    payment_id: str = Field(min_length=1, max_length=64)
    amount_in_paise: int = Field(gt=0, le=MONEY_FIELD_MAX * 100)
    currency: str = "INR"
    merchant_id: str = Field(min_length=1, max_length=64)
    merchant_name: str = Field(min_length=1, max_length=256)
    status: str = Field(min_length=1, max_length=32)
    method: str = Field(default="", max_length=32)
    signature: str = Field(min_length=1, max_length=512)  # G5: unsigned payload rejected

    @field_validator("currency")
    @classmethod
    def _currency_supported(cls, v: str) -> str:
        v = v.upper()
        if v not in SUPPORTED_CURRENCIES:
            raise ValueError(f"currency {v!r} not supported (supported: {sorted(SUPPORTED_CURRENCIES)})")
        return v


class InboundTelemetry(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    timestamp: Optional[datetime] = None  # agent-claimed (data, not trusted for ordering — G5)
    user_mandate: UserMandate
    # EDG-B2: a session with a captured payment MUST carry a trace; an empty
    # trace used to score 100 'clear' (no checks had anything to look at).
    agent_trace_logs: list[TraceLog] = Field(default_factory=list, min_length=1, max_length=1_000)
    razorpay_payment_event: RazorpayPaymentEvent

    @field_validator("agent_trace_logs")
    @classmethod
    def _steps_sequential(cls, logs: list[TraceLog]) -> list[TraceLog]:
        if not logs:
            return logs
        steps = [t.step for t in logs]
        if steps != list(range(1, len(logs) + 1)):
            raise ValueError(f"trace steps must be numbered 1..N consecutively; got {steps}")
        return logs

    @field_validator("timestamp")
    @classmethod
    def _claimed_ts_must_be_tz_aware(cls, v: Optional[datetime]) -> Optional[datetime]:
        # A claimed instant must be unambiguous (EDG-A3): tz-less timestamps
        # are rejected rather than silently re-based to server local time.
        if v is not None and (v.tzinfo is None or v.tzinfo.utcoffset(v) is None):
            raise ValueError("timestamp must include a UTC offset (tz-aware)")
        return v
