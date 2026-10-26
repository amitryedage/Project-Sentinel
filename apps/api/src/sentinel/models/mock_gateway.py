"""Durable mock gateway operations for serverless demo deployments."""
from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class MockGatewayOperation(Base):
    __tablename__ = "mock_gateway_operations"
    reference: Mapped[str] = mapped_column(String(64), primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(64), index=True)
    amount: Mapped[int] = mapped_column(Integer, default=0)
    payload: Mapped[dict] = mapped_column(JSON)
