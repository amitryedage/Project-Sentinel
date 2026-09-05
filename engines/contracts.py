"""Engine contracts — typed in-memory results shared across stages."""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ConstraintCheckResult:
    constraint: str  # budget|merchant|category|time_window|trace_gateway
    scope: str  # payment|step
    step_no: Optional[int]  # set when scope == "step"
    passed: bool
    observed_value: Any  # int paise | domain str | None
    limit_value: Any
    severity: str  # hard|soft
    # breach ratio for budget (0.0 when n/a) — needed by scoring (G6 derivation)
    breach_ratio: float = 0.0


@dataclass
class FindingResult:
    finding_type: str  # taxonomy: design §6
    severity: str  # CRITICAL|MAJOR|MINOR
    description: str
    evidence_ref: str  # e.g. "trace.step:3.parameters.item_id"
    penalty: float = 0.0  # assigned by scoring (design §4.4)


@dataclass
class DeterministicOutput:
    constraint_checks: list[ConstraintCheckResult] = field(default_factory=list)
    findings: list[FindingResult] = field(default_factory=list)
    divergence_point: Optional[int] = None  # first step with a HARD violation (G3)


@dataclass
class SemanticOutput:
    alignment_score: float  # 0.0–1.0
    findings: list[FindingResult] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # full engine output (audit/replay)
    engine_mode: str = "mock"  # mock|llm
    engine_id: str = "heuristic-v1"


@dataclass
class ScoreOutput:
    s_det: float
    s_sem: float
    w_det: float
    w_sem: float
    tis: float  # 0.0–100.0
    override_applied: bool  # a hard failure forced the flag (G6)
    derivation: dict = field(default_factory=dict)  # the full math, visible in packet
    status: str = "clear"  # clear|review|flagged
