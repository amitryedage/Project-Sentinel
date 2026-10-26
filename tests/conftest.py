import os
import tempfile
from pathlib import Path

# Tests never use the production database pulled by Neon.
os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(tempfile.mkdtemp(prefix="sentinel-tests-")) / "test.db")
os.environ["DATABASE_URL_UNPOOLED"] = ""
os.environ["API_KEY"] = "test-operator-key"
os.environ["VERCEL"] = "0"
os.environ["AUTO_CREATE_SCHEMA"] = "true"
os.environ["RAZORPAY_MOCK"] = "true"
os.environ["SEMANTIC_MODE"] = "mock"
os.environ["SENTINEL_SIGNING_SECRET"] = "test-signing-key"
