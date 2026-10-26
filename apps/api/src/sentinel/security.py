"""API authentication and bounded ASGI request guards."""
import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException
from starlette.responses import JSONResponse

from .config import get_settings


def _s(value) -> str:
    return str(value).replace("\r", "\\r").replace("\n", "\\n")[:2000]


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = get_settings().api_key
    if not expected:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid API key")


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                return await JSONResponse({"detail": "Request body too large"}, 413)(scope, receive, send)
            chunks.append(message)
            if not message.get("more_body", False):
                break
        index = 0

        async def replay():
            nonlocal index
            if index < len(chunks):
                message = chunks[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay, send)


class RateLimitMiddleware:
    """Per-instance backstop; configure Vercel Firewall for global rate limits."""
    def __init__(self, app, max_requests: int, window_s: int, exempt_paths=()):
        self.app = app
        self.max_requests, self.window_s = max_requests, window_s
        self.exempt_paths = set(exempt_paths)
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in self.exempt_paths:
            return await self.app(scope, receive, send)
        client = (scope.get("client") or ("unknown",))[0]
        now = time.monotonic()
        with self.lock:
            if len(self.requests) >= 10000:
                self.requests = defaultdict(deque, {
                    key: values for key, values in self.requests.items()
                    if values and values[-1] > now - self.window_s
                })
            if client not in self.requests and len(self.requests) >= 10000:
                limited = True
            else:
                requests = self.requests[client]
                while requests and requests[0] <= now - self.window_s:
                    requests.popleft()
                limited = len(requests) >= self.max_requests
                if not limited:
                    requests.append(now)
        if limited:
            return await JSONResponse({"detail": "Rate limit exceeded"}, 429,
                                      headers={"Retry-After": str(self.window_s)})(scope, receive, send)
        await self.app(scope, receive, send)
