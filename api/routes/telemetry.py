"""Telemetry ingestion endpoint (Stage 1) — design §8.

POST /api/v1/telemetry/ingest
- 201 on first ingest, 200 on idempotent re-ingest (A3)
- 409 when a concurrent ingest of the same session is in flight (EDG-201)
- 422 with field-level details on validation failure (FastAPI default)
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from ...database import get_db
from ...models import Session
from ...schemas.ingest import InboundTelemetry
from ...services.pipeline import ingest_and_evaluate

logger = logging.getLogger("sentinel.telemetry")

router = APIRouter(prefix="/api/v1/telemetry", tags=["telemetry"])


@router.post("/ingest", status_code=201)
def ingest(payload: InboundTelemetry, resp: Response, db: DbSession = Depends(get_db)):
    was_new = db.query(Session).filter_by(session_id=payload.session_id).first() is None
    try:
        result = ingest_and_evaluate(db, payload)
    except IntegrityError:
        # Concurrent first-ingest of the same session raced past the was_new
        # check (TOCTOU); the DB unique constraints won. Deterministic 409 so
        # callers can retry against the committed state.
        db.rollback()
        logger.warning("Concurrent ingest conflict for session %s",
                       payload.session_id.replace("\n", "\\n"))
        raise HTTPException(
            status_code=409,
            detail=f"session {payload.session_id} was committed concurrently; retry ingest")
    if not was_new:
        resp.status_code = 200
    result["reingest"] = not was_new
    return result
