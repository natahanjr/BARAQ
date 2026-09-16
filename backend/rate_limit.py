"""BARAQ Rate Limiting Middleware — protects API from abuse.

Usage:
    Add to FastAPI app:
        from backend.rate_limit import RateLimitMiddleware
        app.add_middleware(RateLimitMiddleware)

    Configure via .env:
        RATE_LIMIT_PER_MINUTE=60
        RATE_LIMIT_BURST=10
"""

from __future__ import annotations

import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter using sliding window."""

    def __init__(self, app, per_minute: int = 60, burst: int = 10):
        super().__init__(app)
        self.per_minute = per_minute
        self.burst = burst
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._cleanup_interval = 60
        self._last_cleanup = time.time()

    def _get_client_id(self, request: Request) -> str:
        """Identify client by API key or IP."""
        api_key = request.headers.get("X-Agent-Key") or request.headers.get("Authorization")
        if api_key:
            return f"key:{api_key[:16]}"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        return f"ip:{request.client.host if request.client else 'unknown'}"

    def _cleanup(self) -> None:
        """Remove old entries periodically."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - 120
        for client_id in list(self._requests.keys()):
            self._requests[client_id] = [
                ts for ts in self._requests[client_id] if ts > cutoff
            ]
            if not self._requests[client_id]:
                del self._requests[client_id]

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and docs
        if request.url.path in ("/api/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        self._cleanup()
        client_id = self._get_client_id(request)
        now = time.time()
        window_start = now - 60

        # Clean old entries for this client
        self._requests[client_id] = [
            ts for ts in self._requests[client_id] if ts > window_start
        ]

        # Check burst limit
        recent = len(self._requests[client_id])
        if recent >= self.burst:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Maximum {self.burst} requests per minute. Try again later.",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"},
            )

        # Record this request
        self._requests[client_id].append(now)

        # Add rate limit headers
        response = await call_next(request)
        remaining = max(0, self.burst - len(self._requests[client_id]))
        response.headers["X-RateLimit-Limit"] = str(self.burst)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(now + 60))

        return response
