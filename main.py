

import logging
import math
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .api.routes import export as export_routes
from .api.routes import incidents as incidents_routes
from .api.routes import remediation as remediation_routes
from .api.routes import telemetry as telemetry_routes
from .api.routes import webhook as webhook_routes
from .config import get_settings
from .database import init_db
from .security import BodySizeLimitMiddleware, RateLimitMiddleware, verify_api_key
from .services.razorpay_client import get_gateway

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("sentinel.main")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-closed (SEC-A1): never serve the authenticated API without a key.
    if not settings.api_key:
        raise RuntimeError(
            "Refusing to start: api_key (env API_KEY) must be set to a non-empty value"
        )
   
    if settings.app_env != "dev" and not settings.sentinel_signing_secret:
        logger.warning(
            "SENTINEL_SIGNING_SECRET not set — dispute export signatures fall back "
            "to the API key; configure an out-of-band signing secret in production"
        )
    init_db()
    logger.info("Sentinel started (gateway=%s, semantic=%s, db=%s)",
                get_gateway().mode, settings.semantic_mode,
                settings.database_url.split("@")[-1])
    yield



_dev_docs = settings.app_env == "dev"

app = FastAPI(
    title="Project Sentinel",
    description="Agentic Payment Incident & Evidence Intelligence",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs" if _dev_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _dev_docs else None,
)



# Global 500: log the traceback server-side, never leak internals .

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})



def _json_safe(obj):
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return "<non-finite>"
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    # Exception objects (pydantic v2 error ctx) or any other unserializable
    # value: keep only the type name — never internal detail.
    return f"<{type(obj).__name__}>"


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422, content={"detail": _json_safe(exc.errors())}
    )


app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=settings.rate_limit_max_requests,
    window_s=settings.rate_limit_window_s,
    exempt_paths=("/health",),
)



app.include_router(telemetry_routes.router, dependencies=[Depends(verify_api_key)])
app.include_router(export_routes.router, dependencies=[Depends(verify_api_key)])
app.include_router(incidents_routes.router, dependencies=[Depends(verify_api_key)])
app.include_router(remediation_routes.router, dependencies=[Depends(verify_api_key)])


app.include_router(webhook_routes.router)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "sentinel",
        "gateway": get_gateway().mode,
        "semantic_mode": settings.semantic_mode,
        "webhook_enabled": bool(settings.razorpay_webhook_secret),
    }
