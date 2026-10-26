import json
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.pool import NullPool

from app import app
from sentinel.config import get_settings
from sentinel.database import database_options
from sentinel.security import BodySizeLimitMiddleware, RateLimitMiddleware
from sentinel.services.database_mock_gateway import DatabaseMockGateway
from sentinel.services.razorpay_client import GatewayError

KEY = {"x-api-key": "test-operator-key"}
SEEDS = Path(__file__).parents[1] / "apps/api/src/sentinel/data/seeds"


def seed(name):
    payload = json.loads((SEEDS / name).read_text())
    suffix = uuid.uuid4().hex[:12]
    payload["session_id"] += suffix
    payload["razorpay_payment_event"]["payment_id"] += suffix
    return payload


def test_frontend_health_and_api_auth():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert "SENTINEL" in client.get("/").text
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/api/v1/incidents").status_code == 401
        assert client.get("/api/v1/incidents", headers={"x-api-key": "wrong"}).status_code == 401
        assert client.get("/api/v1/incidents", headers=KEY).status_code == 200


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+psycopg"])
def test_neon_url_and_pool_configuration(scheme):
    url, options = database_options(f"{scheme}://u:p@db-pooler.neon.tech/db?sslmode=require", serverless=True)
    assert url.drivername == "postgresql+psycopg"
    assert url.query["sslmode"] == "require"
    assert options["poolclass"] is NullPool
    assert options["connect_args"]["prepare_threshold"] is None


def test_serverless_rejects_sqlite():
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        database_options("sqlite:///unwanted.db", serverless=True)


def test_database_mock_survives_new_instance_and_refund_cap():
    payload = seed("scenario_002_budget_breach.json")
    with TestClient(app) as client:
        ingest = client.post("/api/v1/telemetry/ingest", json=payload, headers=KEY)
        assert ingest.status_code == 201, ingest.text
        incident_id = ingest.json()["incident_id"]
        assert client.get(f"/api/v1/incidents/{incident_id}", headers=KEY).status_code == 200
        evidence = client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=KEY).json()
        assert evidence["verify"]["ok"]
    payment_id = payload["razorpay_payment_event"]["payment_id"]
    amount = DatabaseMockGateway().get_payment(payment_id)["amount"]
    result = DatabaseMockGateway().create_refund(payment_id, amount, "test refund")
    assert DatabaseMockGateway().create_refund(payment_id, amount, "test refund") == result
    with pytest.raises(GatewayError):
        DatabaseMockGateway().create_refund(payment_id, 1, "second refund")


def test_chunked_body_limit():
    guarded = FastAPI()
    @guarded.post("/")
    async def echo(request: Request):
        return {"size": len(await request.body())}
    guarded.add_middleware(BodySizeLimitMiddleware, max_bytes=8)
    with TestClient(guarded) as client:
        assert client.post("/", content=b"12345678").json() == {"size": 8}
        assert client.post("/", content=b"123456789").status_code == 413
        assert client.post("/", content=iter([b"12345", b"67890"])).status_code == 413


def test_rate_limit():
    guarded = FastAPI()
    @guarded.get("/")
    def ok():
        return {"ok": True}
    guarded.add_middleware(RateLimitMiddleware, max_requests=1, window_s=60)
    with TestClient(guarded) as client:
        assert client.get("/").status_code == 200
        response = client.get("/")
        assert response.status_code == 429
        assert response.headers["retry-after"] == "60"


def test_fail_closed_without_api_key():
    settings = get_settings()
    original = settings.api_key
    settings.api_key = ""
    try:
        with pytest.raises(RuntimeError, match="API_KEY"):
            with TestClient(app):
                pass
    finally:
        settings.api_key = original


def test_schema_initialization_command(tmp_path):
    import os
    import sqlite3
    import subprocess
    import sys
    env = dict(os.environ, DATABASE_URL="sqlite:///" + str(tmp_path / "schema.db"), DATABASE_URL_UNPOOLED="")
    result = subprocess.run([sys.executable, "-m", "sentinel.tools.init_db"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(tmp_path / "schema.db") as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"sessions", "incidents", "mock_gateway_operations"} <= tables
