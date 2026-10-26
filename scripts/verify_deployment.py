"""Run HTTP and persistence checks against a configured PostgreSQL database.

Creates a uniquely named mock incident/refund for deployment verification.
No live payment requests are made. URLs and keys are never printed.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", default=".env.local")
    parser.add_argument("--initialize", action="store_true")
    args = parser.parse_args()
    env = dict(os.environ)
    for filename in [".env", ".env.local", args.env_file]:
        env.update({key: value for key, value in dotenv_values(ROOT / filename).items() if value is not None})
    env.update(VERCEL="1", AUTO_CREATE_SCHEMA="false", RAZORPAY_MOCK="1", SEMANTIC_MODE="mock", APP_ENV="production")
    if not env.get("API_KEY") or not env.get("SENTINEL_SIGNING_SECRET"):
        raise RuntimeError("Configure API_KEY and SENTINEL_SIGNING_SECRET first")
    if args.initialize:
        subprocess.run([sys.executable, "-m", "sentinel.tools.init_db"], cwd=ROOT, env=env, check=True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    log = tempfile.TemporaryFile()

    def start():
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(port)], cwd=ROOT, env=env, stdout=log, stderr=log)
        for _ in range(150):
            if process.poll() is not None:
                raise RuntimeError("API exited during startup")
            try:
                if httpx.get(base + "/health", timeout=1).status_code == 200:
                    return process
            except httpx.HTTPError:
                pass
            time.sleep(.2)
        process.terminate()
        process.wait(timeout=10)
        raise RuntimeError("API startup timed out")

    def stop(process):
        process.terminate()
        process.wait(timeout=15)

    process = start()
    try:
        with httpx.Client(base_url=base, headers={"x-api-key": env["API_KEY"]}, timeout=45) as client:
            def call(method, path, expected=200, **kwargs):
                response = client.request(method, path, **kwargs)
                assert response.status_code == expected, f"{method} {path}: HTTP {response.status_code}"
                return response.json()
            page = client.get("/")
            assert page.status_code == 200 and "SENTINEL" in page.text
            assert client.get("/api/v1/incidents", headers={"x-api-key": "invalid"}).status_code == 401
            assert call("GET", "/health")["gateway"] == "mock"
            print("PASS frontend HTTP 200, health HTTP 200, invalid API key HTTP 401")
            payload = json.loads((ROOT / "apps/api/src/sentinel/data/seeds/scenario_002_budget_breach.json").read_text())
            token = uuid.uuid4().hex[:16]
            payload["session_id"] = "deployment_check_" + token
            payload["razorpay_payment_event"]["payment_id"] = "pay_verify_" + token
            incident = call("POST", "/api/v1/telemetry/ingest", expected=201, json=payload)
            incident_id = incident["incident_id"]
            prefix = "/api/v1/incidents/" + incident_id
            assert call("GET", prefix)["status"] == "flagged"
            assert call("GET", prefix + "/evidence")["verify"]["ok"]
            assert call("GET", f"/api/v1/sessions/{payload['session_id']}/trace")["steps"]
            export = call("GET", prefix + "/export")
            assert export["tamper_evident_proof"]["timestamp_authority_signature"].startswith("sha256hmac:")
            print("PASS Neon-backed ingest HTTP 201, detail/trace/evidence/export HTTP 200; evidence chain verified")
            proposal = call("POST", prefix + "/remediation", expected=201, json={"action": "refund"})
            path = f"/api/v1/remediation/{proposal['remediation_id']}/approve"
            assert call("POST", path, json={"approved_by": "deployment-verification"})["status"] == "executed"
            print("PASS human-approved mock refund HTTP 200; payment state stored in PostgreSQL")
            stop(process)
            process = start()
            assert call("GET", prefix)["status"] == "remediated"
            assert call("GET", prefix + "/evidence")["verify"]["ok"]
            second = call("POST", prefix + "/remediation", expected=201, json={"action": "refund"})
            path = f"/api/v1/remediation/{second['remediation_id']}/approve"
            call("POST", path, expected=502, json={"approved_by": "deployment-verification"})
            print("PASS restart persistence and duplicate-refund cap (HTTP 502 rejection)")
            print("VERIFIED incident:", incident_id, "session:", payload["session_id"])
    except Exception:
        import re
        log.seek(0)
        diagnostic = log.read().decode(errors="replace")
        diagnostic = re.sub(r"postgres(?:ql)?(?:\+psycopg)?://[^\s]+", "[redacted database URL]", diagnostic)
        print("\n".join(diagnostic.splitlines()[-35:]))
        raise
    finally:
        if process.poll() is None:
            stop(process)
        log.close()


if __name__ == "__main__":
    main()
