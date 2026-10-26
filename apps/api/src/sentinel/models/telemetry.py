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
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|clear|review|flagged|remediated

    mandate: Mapped[Optional["Mandate"]] = relationship(back_populates="session")
    trace_steps: Mapped[list["TraceStep"]] = relationship(
        back_populates="session", order_by="TraceStep.step"
    )
    payment_events: Mapped[list["PaymentEvent"]] = relationship(back_populates="session")
    ledger: Mapped[list["EvidenceLedger"]] = relationship(
        back_populates="session", order_by="EvidenceLedger.seq"
    )
    incident: Mapped[Optional["Incident"]] = relationship(back_populates="session")


class Mandate(Base):
    __tablename__ = "mandates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"), unique=True)
    original_query: Mapped[str] = mapped_column(Text)
    budget_limit_paise: Mapped[int] = mapped_column(Integer)  # int paise — no floats (G5)
    # R2-12: these JSON columns store LISTS (annotation corrected; runtime was
    # already safe — JSON round-trips lists fine).
    allowed_categories: Mapped[list] = mapped_column(JSON)
    allowed_merchants: Mapped[list] = mapped_column(JSON)
    # Amendment A1 (P2): who recorded the mandate. 'principal' = user's app at
    # delegation time (trusted); 'agent' = self-reported (lower confidence).
    mandate_source: Mapped[str] = mapped_column(String(16), default="principal")

    session: Mapped["Session"] = relationship(back_populates="mandate")


class TraceStep(Base):
    __tablename__ = "trace_steps"
    __table_args__ = (UniqueConstraint("session_id", "step"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"))
    step: Mapped[int] = mapped_column(Integer)  # causal order, 1..N
    action: Mapped[str] = mapped_column(String(64))
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)  # free-form, untrusted
    result_summary: Mapped[str] = mapped_column(Text, default="")

    session: Mapped["Session"] = relationship(back_populates="trace_steps")


class PaymentEvent(Base):
    __tablename__ = "payment_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"))
    payment_id: Mapped[str] = mapped_column(String(64), index=True)  # duplicate detection
    amount_in_paise: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(8), default="INR")
    merchant_id: Mapped[str] = mapped_column(String(64))
    merchant_name: Mapped[str] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32))  # created|authorized|captured|...
    method: Mapped[str] = mapped_column(String(32), default="")
    signature: Mapped[str] = mapped_column(String(512))  # required non-empty at ingest
    claimed_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)  # full gateway payload as received

    session: Mapped["Session"] = relationship(back_populates="payment_events")


class EvidenceLedger(Base):
    """Append-only, hash-chained case file (design §3.3).

    event_type: mandate | trace_step | payment_event | evaluation | remediation
    prev_hash = h_{i-1}, hash = h_i where
    h_i = sha256(h_{i-1} + ":" + canonicalize(payload)).
    """

    __tablename__ = "evidence_ledger"
    __table_args__ = (UniqueConstraint("session_id", "seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"))
    seq: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    session: Mapped["Session"] = relationship(back_populates="ledger")


# Imported for relationship resolution (type-only cycle broken by string refs).
from .incident import Incident  # noqa: E402,F401
