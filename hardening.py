"""
健壮性层：熔断器、重连管理器、结构化错误、超时控制。

提供：
    CircuitBreaker          — 逐维度滑动窗口熔断器
    ReconnectManager        — 指数退避重连管理器
    StructuredError         — 结构化错误响应
"""
    CircuitBreakerRegistry  — Registry managing breakers across all dimensions
    ReconnectManager        — Exponential backoff tracking per machine
    StructuredHTTPException — Uniform JSON error envelope for HTTP responses
    GlobalErrorHandler      — FastAPI middleware catching all exceptions
    RequestTimeoutMiddleware — Per-request timeout with graceful degradation
"""

import asyncio
import logging
import time
import uuid
from collections import defaultdict
from typing import Optional, Callable, Awaitable

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("agentdock.hardening")

# ──────────────────────────────────────────────
# Structured Error Envelope
# ──────────────────────────────────────────────

#: Maps error code strings to HTTP status codes.
ERROR_CODES = {
    "unauthorized": 401,
    "not-found": 404,
    "rate-limited": 429,
    "rpc-timeout": 504,
    "rpc-error": 502,
    "circuit-open": 503,
    "machine-not-connected": 503,
    "no-available-machine": 503,
    "invalid-params": 400,
    "internal-error": 500,
    "pairing-failed": 401,
    "session-not-found": 404,
    "machine-not-found": 404,
    "pairing-request-not-found-or-expired": 404,
    "pairing-not-authorized": 401,
    "signature-mismatch": 401,
    "invalid-auth-params": 400,
    "invalid-base64": 400,
    "sessionId-required": 400,
}


def structured_error(
    code: str,
    message: str,
    detail: str = None,
    request_id: str = None,
) -> dict:
    """Build a structured error response matching the wire protocol's error format.

    Returns a dict of the form::

        {"error": {"code": str, "message": str, "detail": str | None,
                   "requestId": str | None}}
    """
    return {
        "error": {
            "code": code,
            "message": message,
            "detail": detail,
            "requestId": request_id,
        }
    }


class StructuredHTTPException(HTTPException):
    """HTTP exception carrying a structured error payload.

    Attributes:
        error_code: Machine-readable error code string.
        error_message: Human-readable message.
        error_detail: Optional additional detail.
        request_id: Optional request identifier for tracing.
    """

    def __init__(
        self,
        code: str,
        message: str,
        detail: str = None,
        status_code: int = None,
        request_id: str = None,
    ):
        self.error_code = code
        self.error_message = message
        self.error_detail = detail
        self.request_id = request_id
        status_code = status_code or ERROR_CODES.get(code, 500)
        payload = structured_error(code, message, detail, request_id)
        super().__init__(status_code=status_code, detail=payload)


# ──────────────────────────────────────────────
# Sliding-window Circuit Breaker
# ──────────────────────────────────────────────


class CircuitBreaker:
    """Per-dimension sliding-window circuit breaker.

    State machine::

        CLOSED (normal) -> OPEN (failing) -> HALF_OPEN (probing) -> CLOSED or OPEN

    Four dimensions are tracked independently:
        - **pairing**: Too many failed pairing attempts per client IP.
        - **session**: Session operations failing.
        - **rpc**: RPC calls to a machine timing out.
        - **auth**: Authentication failures.

    Args:
        dimension: Dimension name for logging/tracking.
        key: Optional sub-key (e.g. machine ID, client IP).
        failure_threshold: Failures within the window to trip open.
        recovery_timeout: Seconds before transitioning from OPEN to HALF_OPEN.
        half_open_max_requests: Allowed probes in HALF_OPEN before re-opening.
        window_seconds: Sliding-window duration for failure counting.
    """

    def __init__(
        self,
        dimension: str,
        key: str = "",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_requests: int = 3,
        window_seconds: float = 60.0,
    ):
        self.dimension = dimension
        self.key = key
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_requests = half_open_max_requests
        self.window_seconds = window_seconds

        self._state = "CLOSED"           # CLOSED | OPEN | HALF_OPEN
        self._failures: list[float] = []  # Timestamps of failures in current window
        self._total_failures = 0
        self._last_failure_time = 0.0
        self._open_since = 0.0
        self._half_open_used = 0

    @property
    def name(self) -> str:
        """Human-readable name for this breaker (e.g. ``cb:rpc:machine_abc:check-path``)."""
        return (
            f"cb:{self.dimension}:{self.key}"
            if self.key
            else f"cb:{self.dimension}"
        )

    def _prune_window(self):
        """Remove failures outside the sliding time window."""
        cutoff = time.time() - self.window_seconds
        self._failures = [t for t in self._failures if t > cutoff]

    def record_success(self):
        """Record a success — reset the failure count and close the breaker."""
        self._state = "CLOSED"
        self._failures.clear()
        self._half_open_used = 0

    def record_failure(self) -> bool:
        """Record a failure and check if the threshold is exceeded.

        Returns:
            ``True`` if the breaker just tripped from CLOSED to OPEN.
        """
        now = time.time()
        self._failures.append(now)
        self._total_failures += 1
        self._last_failure_time = now
        self._prune_window()

        if len(self._failures) >= self.failure_threshold and self._state == "CLOSED":
            self._state = "OPEN"
            self._open_since = now
            logger.warning(
                f"{self.name} -> OPEN ({len(self._failures)} failures "
                f"in {self.window_seconds}s)"
            )
            return True
        return False

    def allow_request(self) -> bool:
        """Check whether a request should be allowed through the breaker.

        In CLOSED state all requests pass.
        In OPEN state requests are rejected until the recovery timeout elapses,
        at which point we transition to HALF_OPEN.
        In HALF_OPEN a limited number of probe requests are allowed.
        """
        now = time.time()

        if self._state == "CLOSED":
            self._prune_window()
            return True

        if self._state == "OPEN":
            if now - self._open_since >= self.recovery_timeout:
                self._state = "HALF_OPEN"
                self._half_open_used = 0
                logger.info(f"{self.name} -> HALF_OPEN (probing)")
                return True
            return False

        if self._state == "HALF_OPEN":
            if self._half_open_used < self.half_open_max_requests:
                self._half_open_used += 1
                return True
            return False

        return True  # Fallback for unknown states

    @property
    def state(self) -> str:
        """Current breaker state: ``CLOSED``, ``OPEN``, or ``HALF_OPEN``."""
        return self._state

    def reset(self):
        """Fully reset the breaker to CLOSED with no recorded failures."""
        self._state = "CLOSED"
        self._failures.clear()
        self._total_failures = 0
        self._open_since = 0.0
        self._half_open_used = 0

    def stats(self) -> dict:
        """Return a snapshot of current breaker statistics."""
        now = time.time()
        self._prune_window()
        return {
            "dimension": self.dimension,
            "key": self.key,
            "state": self._state,
            "failuresInWindow": len(self._failures),
            "totalFailures": self._total_failures,
            "lastFailure": self._last_failure_time,
            "openSince": self._open_since,
            "openDuration": (now - self._open_since) if self._open_since else 0,
            "threshold": self.failure_threshold,
            "recoveryTimeout": self.recovery_timeout,
        }


class CircuitBreakerRegistry:
    """Manages circuit breakers across all dimensions.

    Provides a uniform interface for ``allow``, ``succeed``, ``fail``,
    ``all_stats``, and ``reset_all`` operations.
    """

    def __init__(self):
        self._breakers: dict[str, CircuitBreaker] = {}

    def _key(self, dimension: str, key: str = "") -> str:
        return f"{dimension}:{key}" if key else dimension

    def get(
        self,
        dimension: str,
        key: str = "",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> CircuitBreaker:
        """Get or create a circuit breaker for the given dimension and key."""
        k = self._key(dimension, key)
        if k not in self._breakers:
            self._breakers[k] = CircuitBreaker(
                dimension=dimension,
                key=key,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        return self._breakers[k]

    def allow(self, dimension: str, key: str = "") -> bool:
        """Check if a request should be allowed for the given dimension."""
        return self.get(dimension, key).allow_request()

    def succeed(self, dimension: str, key: str = ""):
        """Record a success for the given dimension."""
        self.get(dimension, key).record_success()

    def fail(self, dimension: str, key: str = "") -> bool:
        """Record a failure for the given dimension.

        Returns:
            ``True`` if the breaker tripped open.
        """
        return self.get(dimension, key).record_failure()

    def all_stats(self) -> dict:
        """Return stats for all registered breakers, keyed by breaker name."""
        return {k: b.stats() for k, b in self._breakers.items()}

    def reset_all(self):
        """Reset every registered breaker to its initial state."""
        for b in self._breakers.values():
            b.reset()


# ──────────────────────────────────────────────
# Reconnection Manager (exponential backoff)
# ──────────────────────────────────────────────


class ReconnectManager:
    """Tracks machine reconnection state with exponential backoff.

    Backoff progression: 5s, 10s, 20s, 40s, 80s, 160s (capped at *max_delay*).

    Args:
        base_delay: Initial backoff delay in seconds.
        max_delay: Maximum backoff delay cap.
        max_retries: Maximum reconnection attempts before giving up.
    """

    def __init__(
        self,
        base_delay: float = 5.0,
        max_delay: float = 300.0,
        max_retries: int = 20,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self._machines: dict[str, dict] = {}

    def on_disconnect(self, machine_id: str, reason: str = "normal") -> dict:
        """Start or advance reconnection tracking for a machine.

        Computes the next attempt time using exponential backoff.

        Args:
            machine_id: The machine that disconnected.
            reason: Reason for disconnection.

        Returns:
            The updated entry dict for this machine.
        """
        entry = self._machines.get(machine_id, {
            "machine_id": machine_id,
            "attempts": 0,
            "last_attempt": 0.0,
            "next_attempt": 0.0,
            "state": "disconnected",
            "reason": reason,
        })
        entry["attempts"] += 1
        entry["last_attempt"] = time.time()
        entry["state"] = "disconnected"
        entry["reason"] = reason

        # Exponential backoff: base * 2^attempts, capped at max_delay
        delay = min(
            self.base_delay * (2 ** min(entry["attempts"] - 1, 10)),
            self.max_delay,
        )
        entry["next_attempt"] = entry["last_attempt"] + delay
        self._machines[machine_id] = entry
        logger.info(
            f"Reconnect [{machine_id}]: attempt #{entry['attempts']}, "
            f"next in {delay:.0f}s"
        )
        return entry

    def on_connect(self, machine_id: str):
        """Reset reconnection state when a machine successfully connects."""
        entry = self._machines.pop(machine_id, None)
        if entry:
            logger.info(
                f"Reconnect [{machine_id}]: reconnected after "
                f"{entry['attempts']} attempts"
            )

    def should_retry(self, machine_id: str) -> bool:
        """Check whether a machine should be retried given its backoff state."""
        entry = self._machines.get(machine_id)
        if not entry:
            return True  # Not tracked = first connect or already reconnected
        if entry["attempts"] >= self.max_retries:
            return False
        if time.time() >= entry["next_attempt"]:
            return True
        return False

    def get_state(self, machine_id: str) -> dict:
        """Get the current reconnection state for a machine."""
        entry = self._machines.get(machine_id, {
            "machine_id": machine_id,
            "attempts": 0,
            "state": "connected" if machine_id not in self._machines else "disconnected",
        })
        entry["state"] = (
            "connected" if machine_id not in self._machines else "disconnected"
        )
        return entry


# ──────────────────────────────────────────────
# Global exception handler
# ──────────────────────────────────────────────


class GlobalErrorHandler(BaseHTTPMiddleware):
    """Catch all unhandled exceptions and return structured error responses.

    Handles ``StructuredHTTPException``, standard FastAPI ``HTTPException``,
    and generic ``Exception`` in that priority order.
    """

    def __init__(self, app, debug: bool = False):
        super().__init__(app)
        self.debug = debug

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex[:16]
        try:
            response = await call_next(request)
            return response
        except StructuredHTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.detail,
            )
        except HTTPException as exc:
            # Convert standard FastAPI HTTPException to structured format
            detail = exc.detail
            if isinstance(detail, dict) and "error" in detail:
                payload = detail
            else:
                payload = structured_error(
                    code=_status_to_code(exc.status_code),
                    message=str(detail) if detail else "http-error",
                    request_id=request_id,
                )
            return JSONResponse(
                status_code=exc.status_code,
                content=payload,
            )
        except Exception as exc:
            logger.exception(
                f"Unhandled exception [request {request_id}]: {exc}"
            )
            payload = structured_error(
                code="internal-error",
                message="Internal server error",
                detail=str(exc) if self.debug else None,
                request_id=request_id,
            )
            return JSONResponse(status_code=500, content=payload)


def _status_to_code(status: int) -> str:
    """Map an HTTP status code to the closest error code string."""
    mapping = {
        400: "invalid-params",
        401: "unauthorized",
        403: "forbidden",
        404: "not-found",
        429: "rate-limited",
        502: "bad-gateway",
        503: "service-unavailable",
        504: "gateway-timeout",
    }
    return mapping.get(status, "internal-error")


# ──────────────────────────────────────────────
# Request timeout middleware
# ──────────────────────────────────────────────


class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Add per-request timeout with graceful degradation to 504 responses.

    Long-running paths (e.g. ``/v1/tasks``) get an extended timeout.
    """

    def __init__(
        self,
        app,
        default_timeout: float = 30.0,
        long_timeout_paths: list[str] = None,
    ):
        super().__init__(app)
        self.default_timeout = default_timeout
        self.long_timeout_paths = long_timeout_paths or ["/v1/tasks"]
        self.long_timeout = 120.0

    def _get_timeout(self, path: str) -> float:
        """Determine the appropriate timeout for a request path."""
        for p in self.long_timeout_paths:
            if path.startswith(p):
                return self.long_timeout
        return self.default_timeout

    async def dispatch(self, request: Request, call_next):
        timeout = self._get_timeout(request.url.path)
        try:
            response = await asyncio.wait_for(
                call_next(request), timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
            logger.warning(
                f"Request timeout [{request.method} {request.url.path}]"
            )
            return JSONResponse(
                status_code=504,
                content=structured_error(
                    code="gateway-timeout",
                    message="Request timed out",
                    request_id=uuid.uuid4().hex[:16],
                ),
            )


# ──────────────────────────────────────────────
# Helper: run with circuit breaker guard
# ──────────────────────────────────────────────


async def circuit_breaker_call(
    cb_registry: CircuitBreakerRegistry,
    dimension: str,
    key: str,
    coro_factory: Callable[[], Awaitable],
    timeout: float = 30.0,
    fallback: Optional[Callable[[], Awaitable]] = None,
) -> dict:
    """Execute an operation guarded by a circuit breaker.

    Checks the breaker before calling the coroutine. Records success or
    failure on the breaker. If the breaker is OPEN and a *fallback* is
    provided, returns the fallback result instead.

    Args:
        cb_registry: The circuit breaker registry.
        dimension: Dimension to check (e.g. ``"rpc"``).
        key: Sub-key (e.g. ``"machine_id:method_name"``).
        coro_factory: Async callable producing the actual operation result.
        timeout: Maximum seconds to wait for the operation.
        fallback: Optional async callable producing a degraded result.

    Returns:
        The operation result dict, or fallback result, or error dict.
    """
    cb = cb_registry.get(dimension, key)

    if not cb.allow_request():
        logger.warning(
            f"Circuit OPEN [{dimension}:{key}] — blocking request"
        )
        if fallback:
            return await fallback()
        return {
            "ok": False,
            "error": "circuit-open",
            "detail": f"Circuit breaker OPEN for {dimension}:{key}",
        }

    try:
        result = await asyncio.wait_for(coro_factory(), timeout=timeout)
        cb.record_success()
        return result
    except asyncio.TimeoutError:
        cb.record_failure()
        logger.warning(
            f"Circuit timeout [{dimension}:{key}] — failure recorded"
        )
        if fallback:
            return await fallback()
        return {
            "ok": False,
            "error": "rpc-timeout",
            "detail": f"Operation timed out ({timeout}s)",
        }
    except Exception as exc:
        cb.record_failure()
        logger.warning(f"Circuit error [{dimension}:{key}]: {exc}")
        if fallback:
            return await fallback()
        return {"ok": False, "error": "rpc-error", "detail": str(exc)}
