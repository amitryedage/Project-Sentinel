"""DB models for evaluation & evidence + policy/run metadata."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"), unique=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|clear|review|flagged|remediated
    divergence_point: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # first violating trace step
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    session: Mapped["Session"] = relationship(back_populates="incident")
    constraint_checks: Mapped[list["ConstraintCheck"]] = relationship(back_populates="incident")
    findings: Mapped[list["Finding"]] = relationship(back_populates="incident")
    semantic_result: Mapped[Optional["SemanticResult"]] = relationship(back_populates="incident")
    score: Mapped[Optional["Score"]] = relationship(back_populates="incident")
    packet: Mapped[Optional["EvidencePacket"]] = relationship(back_populates="incident")
    remediations: Mapped[list["Remediation"]] = relationship(back_populates="incident")


class ConstraintCheck(Base):
    __tablename__ = "constraint_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    constraint: Mapped[str] = mapped_column(String(32))  # budget|merchant|category|time_window|trace_gateway
    scope: Mapped[str] = mapped_column(String(16))  # payment|step
    step_no: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # set when scope=step
    passed: Mapped[bool] = mapped_column(Boolean)
    observed_value: Mapped[str] = mapped_column(String(512), default="")
    limit_value: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(8))  # hard|soft

    incident: Mapped["Incident"] = relationship(back_populates="constraint_checks")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    finding_type: Mapped[str] = mapped_column(String(48))  # see taxonomy: design §6
    severity: Mapped[str] = mapped_column(String(16))  # CRITICAL|MAJOR|MINOR
    description: Mapped[str] = mapped_column(Text)
    evidence_ref: Mapped[str] = mapped_column(String(256))
    penalty: Mapped[float] = mapped_column(Float, default=0.0)

    incident: Mapped["Incident"] = relationship(back_populates="findings")


class SemanticResult(Base):
    __tablename__ = "semantic_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), unique=True)
    alignment_score: Mapped[float] = mapped_column(Float)  # 0.0–1.0
    engine_mode: Mapped[str] = mapped_column(String(16))  # mock|llm
    engine_id: Mapped[str] = mapped_column(String(64))  # 'heuristic-v1' or model name
    raw: Mapped[dict] = mapped_column(JSON, default=dict)  # full engine output (audit/replay)

    incident: Mapped["Incident"] = relationship(back_populates="semantic_result")


class Score(Base):
    __tablename__ = "scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), unique=True)
    s_det: Mapped[float] = mapped_column(Float)
    s_sem: Mapped[float] = mapped_column(Float)
    w_det: Mapped[float] = mapped_column(Float)
    w_sem: Mapped[float] = mapped_column(Float)
    tis: Mapped[float] = mapped_column(Float)  # 0.0–100.0
    override_applied: Mapped[bool] = mapped_column(Boolean, default=False)  # hard failure forced flag
    derivation: Mapped[dict] = mapped_column(JSON, default=dict)  # the full math (G6)

    incident: Mapped["Incident"] = relationship(back_populates="score")


class EvidencePacket(Base):
    __tablename__ = "evidence_packets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), unique=True)
    packet: Mapped[dict] = mapped_column(JSON)  # Listing-4.1 shape + derivation + policy_version
    chain_head: Mapped[str] = mapped_column(String(64))
    packet_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    incident: Mapped["Incident"] = relationship(back_populates="packet")


class Remediation(Base):
    """Table only in Slice 1 — endpoints land in Slice 2 (P6 scope)."""

    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"))
    action: Mapped[str] = mapped_column(String(32))  # hold|refund|review|step_up
    status: Mapped[str] = mapped_column(String(16), default="proposed")  # proposed|approved|executed|rejected
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    razorpay_ref: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="remediations")


class WebhookEvent(Base):
    """Durable replay registry for verified Razorpay webhook event ids.

    Replaces a full ledger scan (audit R-02): replay protection becomes an
    O(1) lookup on a unique primary key instead of loading every
    ``gateway_event`` row on each delivery.
    """
    __tablename__ = "webhook_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    version: Mapped[str] = mapped_column(String(16), primary_key=True)
    policy: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    run_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"))
    run_seq: Mapped[int] = mapped_column(Integer)
    policy_version: Mapped[str] = mapped_column(String(16))
    engine_mode: Mapped[str] = mapped_column(String(16))  # mock|llm
    engine_id: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
