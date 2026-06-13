"""
AgentDock 协议服务端 — FastAPI + python-socketio。

实现 AgentDock 协议完整功能：
  - HTTP：配对、认证、机器管理、会话 CRUD、统计
  - Socket.IO (/v1/updates)：Web UI 与客户端之间的实时信令

提供 Web 管理界面和 RESTful API。
"""

"""

import asyncio
import hashlib
import json
import logging
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional, Any

import socketio
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel, Field

from config import settings
from storage import Storage
import crypto as agentdock_crypto
from scheduler import TaskEngine, parse_cron
from hardening import (
    CircuitBreakerRegistry,
    ReconnectManager,
    structured_error,
    StructuredHTTPException,
    GlobalErrorHandler,
    RequestTimeoutMiddleware,
    circuit_breaker_call,
)

logger = logging.getLogger("agentdock")

# ─── Globals ────────────────────────────────────────

#: SQLite storage layer
storage = Storage()
#: Socket.IO async server (mounted as ASGI alongside FastAPI)
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    ping_interval=25,
    ping_timeout=60,
)

#: Connected daemons: ``sid -> {machine_id, token, client_type, connected_at}``
connected_daemons: dict[str, dict] = {}
#: Machine socket tracking: ``machine_id -> set[sid]``
machine_sids: dict[str, set] = {}
#: Session ownership: ``session_id -> machine_id``
session_owners: dict[str, str] = {}
#: RPC method registrations per machine: ``machine_id -> set[method_name]``
machine_rpc_methods: dict[str, set] = {}

# Hardening layer instances
cb_registry = CircuitBreakerRegistry()
reconnect_mgr = ReconnectManager()

#: Pending RPC calls keyed by call_id, each holding an asyncio Future
pending_rpcs: dict[str, asyncio.Future] = {}
#: Auth challenge cache: ``challenge_id -> {nonce, created_at}``
auth_challenges: dict[str, dict] = {}


# ─── Helpers ────────────────────────────────────────


def generate_token() -> str:
    """Generate a random auth token with ``ad_`` prefix."""
    return "ad_" + secrets.token_hex(32)


def generate_pin() -> str:
    """Generate a random numeric PIN of the configured length.

    Uses ``secrets.randbelow`` for cryptographic randomness.
    """
    return str(secrets.randbelow(10 ** settings.pairing_pin_length)).zfill(
        settings.pairing_pin_length
    )


def derive_web_url(server_url: str) -> str:
    """Derive the Web UI URL from the server URL.

    If ``settings.web_url`` is set, returns it directly.
    Otherwise attempts to infer the UI URL by replacing ``-api`` subdomains
    or mapping local network addresses to the dev server port (5173).

    Args:
        server_url: The server's base URL (e.g. ``http://192.168.1.5:8080``).

    Returns:
        The Web UI base URL string.
    """
    if settings.web_url:
        return settings.web_url.rstrip("/")
    try:
        from urllib.parse import urlparse
        parsed = urlparse(server_url)
        hostname = parsed.hostname or ""
        # Detect whether we're on a local/private network
        is_local = (
            hostname in ("localhost", "127.0.0.1", "::1", "[::1]")
            or hostname.startswith("10.")
            or hostname.startswith("192.168.")
            or any(hostname.startswith(f"172.{i}.") for i in range(16, 32))
        )
        if is_local and parsed.scheme == "http":
            # Dev-mode: assume Web UI runs on port 5173
            return f"{parsed.scheme}://{parsed.hostname}:5173"
        else:
            # Production: strip ``-api`` subdomain
            new_host = hostname.replace("-api.", ".")
            return f"{parsed.scheme}://{new_host}"
    except Exception:
        return server_url


def generate_pairing_url(public_key_b64: str, server_url: str) -> str:
    """Generate a pairing QR-code URL.

    Args:
        public_key_b64: The device's base64-encoded public key.
        server_url: The server's base URL.

    Returns:
        A fully qualified URL for the Web UI pairing page.
    """
    web_url = derive_web_url(server_url)
    return f"{web_url}/pair?key={public_key_b64}"


async def get_current_machine(request: Request) -> Optional[dict]:
    """Extract the authenticated machine from the ``Authorization`` header.

    Looks for a ``Bearer <token>`` header and validates the token against storage.

    Returns:
        The token record dict, or ``None`` if no valid token is found.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") and not auth.startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1]
    return await storage.validate_token(token)


async def require_auth(request: Request):
    """FastAPI dependency that requires a valid auth token.

    Raises:
        HTTPException 401: If the token is missing or invalid.
    """
    machine = await get_current_machine(request)
    if machine is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return machine


# ─── Socket.IO Auth ─────────────────────────────────


@sio.event
async def connect(sid: str, environ: dict, auth: dict):
    """Socket.IO connect handler — validates authentication.

    For machine-scoped / session-scoped connections the token is validated
    against storage.  Protocol version is also checked for compatibility.

    On success the client is added to the appropriate Socket.IO room
    (``user-scoped``, ``machine-scoped``, or ``session-scoped``).
    """
    logger.info(f"socket connect: sid={sid}, auth={auth}")

    client_type = auth.get("clientType", "user-scoped")
    token = auth.get("token", "")
    machine_id = auth.get("machineId", "")
    protocol_version = auth.get("protocolVersion", 0)

    # Reject if protocol version doesn't match
    if protocol_version and int(protocol_version) != settings.protocol_version:
        logger.warning(
            f"protocol version mismatch: {protocol_version} != "
            f"{settings.protocol_version}"
        )
        raise socketio.ConnectionRefusedError("upgrade-required")

    # Validate token for machine-scoped / session-scoped connections
    if client_type in ("machine-scoped", "session-scoped"):
        tok_data = await storage.validate_token(token)
        if tok_data is None:
            logger.warning(f"invalid token for sid={sid}")
            raise socketio.ConnectionRefusedError("auth-invalid-token")

        connected_daemons[sid] = {
            "machine_id": machine_id or tok_data.get("machine_id", ""),
            "token": token,
            "client_type": client_type,
            "connected_at": time.time(),
            "protocol_version": protocol_version,
        }

        if machine_id:
            if machine_id not in machine_sids:
                machine_sids[machine_id] = set()
            machine_sids[machine_id].add(sid)

    # Clear reconnection tracking on successful reconnect
    if machine_id:
        reconnect_mgr.on_connect(machine_id)
        await sio.emit(
            "machine-status-update",
            {
                "machineId": machine_id,
                "status": "online",
                "timestamp": time.time(),
            },
            room="user-scoped",
        )

    await sio.enter_room(sid, client_type)
    return {"ok": True}


@sio.event
async def disconnect(sid: str):
    """Socket.IO disconnect handler — cleanup tracking state.

    Removes the client from ``connected_daemons``, updates machine status,
    and broadcasts an offline notification to Web UI subscribers.
    """
    logger.info(f"socket disconnect: sid={sid}")
    info = connected_daemons.pop(sid, None)
    if info:
        machine_id = info.get("machine_id", "")
        if machine_id and machine_id in machine_sids:
            machine_sids[machine_id].discard(sid)
            if not machine_sids[machine_id]:
                del machine_sids[machine_id]
                # Mark machine in DB and broadcast to Web UI
                await storage.disconnect_machine(machine_id)
                reconnect_info = reconnect_mgr.on_disconnect(
                    machine_id, "normal"
                )
                await sio.emit(
                    "machine-status-update",
                    {
                        "machineId": machine_id,
                        "status": "offline",
                        "reconnect": reconnect_info,
                        "timestamp": time.time(),
                    },
                    room="user-scoped",
                )


# ─── Socket.IO Events ───────────────────────────────


@sio.on("machine-register")
async def on_machine_register(sid: str, data: dict):
    """Register daemon machine metadata.

    Called by the daemon on initial connect to register its hostname,
    platform, architecture, and available agent types.

    Returns:
        Dict with ``ok``, optional ``latestVersion``, and ``labsSettings``.
    """
    info = connected_daemons.get(sid)
    if not info:
        return {"ok": False, "error": "not-authenticated"}

    machine_id = data.get("id") or info.get("machine_id", "")
    if not machine_id:
        machine_id = f"m_{uuid.uuid4().hex[:12]}"

    hostname = data.get("hostname", "")
    platform = data.get("platform", "linux")
    arch = data.get("arch", "")
    available_agents = data.get("availableAgents", [])

    await storage.register_machine(
        machine_id=machine_id,
        hostname=hostname,
        platform=platform,
        arch=arch,
        available_agents=available_agents,
    )

    info["machine_id"] = machine_id
    if machine_id not in machine_sids:
        machine_sids[machine_id] = set()
    machine_sids[machine_id].add(sid)

    logger.info(f"machine registered: {machine_id} ({hostname})")

    return {
        "ok": True,
        "latestVersion": None,  # Future: check for upgrades
        "labsSettings": {"historySessionSync": False},
    }


@sio.on("machine-heartbeat")
async def on_machine_heartbeat(sid: str, data: dict):
    """Handle daemon heartbeat — updates the machine's last-heartbeat timestamp.

    Returns:
        Dict with ``ok`` status.
    """
    info = connected_daemons.get(sid)
    if not info:
        return {"ok": False, "error": "not-authenticated"}
    machine_id = info.get("machine_id", "")
    if machine_id:
        await storage.heartbeat_machine(machine_id)
    return {"ok": True}


@sio.on("session-create")
async def on_session_create(sid: str, data: dict):
    """Create a new session, called by the daemon when starting an agent session.

    If the session was pre-reserved via the ``spawn-session`` HTTP endpoint,
    the daemon should include ``sessionId`` matching the reserved ID.
    Otherwise a new UUID is generated.

    Returns:
        Dict with ``ok`` and ``sessionId``.
    """
    info = connected_daemons.get(sid)
    if not info:
        return {"ok": False, "error": "not-authenticated"}

    machine_id = info.get("machine_id", "")
    session_id = data.get("sessionId", "")
    tag = data.get("tag", "")
    metadata = data.get("metadata", {})
    wrapped_dek = data.get("dataEncryptionKey")
    source = data.get("source", "managed")
    claude_session_id = data.get("claudeSessionId")
    project_path = data.get("projectPath")

    # Generate an ID if not pre-reserved
    if not session_id:
        session_id = f"s_{uuid.uuid4().hex[:16]}"

    # If the session was already created via HTTP, just update the DEK
    existing = await storage.get_session(session_id)
    if existing:
        logger.info(f"session already exists (pre-reserved): {session_id}")
        if wrapped_dek and not existing.get("wrapped_dek"):
            await storage.provision_session_dek(session_id, wrapped_dek)
        await sio.enter_room(sid, f"session:{session_id}")
        return {"ok": True, "sessionId": session_id}

    # Full creation
    session = await storage.create_session(
        session_id=session_id,
        machine_id=machine_id,
        tag=tag,
        metadata=metadata,
        wrapped_dek=wrapped_dek,
        source=source,
        claude_session_id=claude_session_id,
        project_path=project_path,
    )
    session_owners[session_id] = machine_id
    await sio.enter_room(sid, f"session:{session_id}")

    # Notify Web UI subscribers
    await sio.emit(
        "session-create",
        {
            "sessionId": session_id,
            "machineId": machine_id,
            "tag": tag,
            "metadata": metadata,
            "createdAt": time.time(),
        },
        room="user-scoped",
    )

    logger.info(f"session created: {session_id} for {machine_id}")
    return {"ok": True, "sessionId": session_id}


@sio.on("session-alive")
async def on_session_alive(sid: str, data: dict):
    """Session heartbeat — updates the session's updated_at timestamp.

    Returns:
        Dict with ``ok`` status, or error if the session doesn't exist.
    """
    session_id = data.get("sessionId", "")
    session = await storage.get_session(session_id)
    if not session:
        return {"ok": False, "error": "session-not-found"}

    await storage._conn.execute(
        "UPDATE sessions SET updated_at=? WHERE id=?",
        (time.time(), session_id),
    )
    await storage._conn.commit()
    return {"ok": True}


@sio.on("session-end")
async def on_session_end(sid: str, data: dict):
    """End a session — marks it as ended in the database.

    Accepts an optional ``summary`` dict attached to the metadata.
    """
    session_id = data.get("sessionId", "")
    summary = data.get("summary")
    await storage.end_session(session_id, summary)
    session_owners.pop(session_id, None)
    logger.info(f"session ended: {session_id}")
    return {"ok": True}


@sio.on("message")
async def on_message(sid: str, data: dict, ack_callback=None):
    """Receive an encrypted session envelope, store it, and relay to Web UI.

    Args:
        sid: Source socket ID.
        data: Dict with ``sessionId``, ``localId``, ``content``, and
            optional ``skipBroadcast``.
        ack_callback: Optional Socket.IO acknowledgment callback.

    Returns:
        Dict with ``ok`` and the assigned ``seq`` number.
    """
    session_id = data.get("sessionId", "")
    local_id = data.get("localId", "")
    content = data.get("content", {})
    skip_broadcast = data.get("skipBroadcast", False)

    if not session_id or not content:
        return {"ok": False, "error": "invalid-message"}

    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    stored = await storage.store_message(
        session_id=session_id,
        message_id=message_id,
        content=content,
        local_id=local_id,
    )

    # Broadcast to Web UI subscribers in the session room
    if not skip_broadcast:
        await sio.emit(
            "message",
            {
                "sessionId": session_id,
                "message": stored,
            },
            room=f"session:{session_id}",
            skip_sid=sid,
        )

    return {"ok": True, "seq": stored["seq"]}


@sio.on("rpc-register")
async def on_rpc_register(sid: str, data: dict):
    """Register an RPC method that this machine can handle.

    The daemon calls this for each method it supports
    (e.g. ``get-machine-info``, ``check-path``).
    """
    info = connected_daemons.get(sid)
    if not info:
        return {"ok": False, "error": "not-authenticated"}
    machine_id = info.get("machine_id", "")
    method = data.get("method", "")
    if not method:
        return {"ok": False, "error": "method-required"}
    if machine_id not in machine_rpc_methods:
        machine_rpc_methods[machine_id] = set()
    machine_rpc_methods[machine_id].add(method)
    return {"ok": True}


@sio.on("rpc-unregister")
async def on_rpc_unregister(sid: str, data: dict):
    """Unregister a previously registered RPC method."""
    info = connected_daemons.get(sid)
    if not info:
        return {"ok": False, "error": "not-authenticated"}
    machine_id = info.get("machine_id", "")
    method = data.get("method", "")
    if machine_id in machine_rpc_methods and method:
        machine_rpc_methods[machine_id].discard(method)
    return {"ok": True}


@sio.on("rpc-call")
async def on_rpc_call(sid: str, data: dict):
    """Handle a daemon's RPC response.

    Matches the response's ``call_id`` against pending RPC futures
    and resolves them so the waiting caller can receive the result.
    """
    call_id = data.get("id", "")
    if call_id and call_id in pending_rpcs:
        future = pending_rpcs.pop(call_id)
        if not future.done():
            future.set_result(data)
        return {"ok": True}
    return {"ok": False, "error": "no-pending-call"}


@sio.on("provision-session-dek")
async def on_provision_session_dek(sid: str, data: dict):
    """Provision a wrapped session data encryption key (DEK)."""
    session_id = data.get("sessionId", "")
    wrapped_dek = data.get("dataEncryptionKey", "")
    if not session_id or not wrapped_dek:
        return {"ok": False, "error": "invalid-params"}
    await storage.provision_session_dek(session_id, wrapped_dek)
    return {"ok": True}


@sio.on("update-metadata")
async def on_update_metadata(sid: str, data: dict):
    """Update session metadata from the daemon."""
    session_id = data.get("sessionId", "")
    metadata = data.get("metadata", {})
    ok = await storage.update_session_metadata(session_id, metadata)
    return {"ok": ok}


@sio.on("update-state")
async def on_update_state(sid: str, data: dict):
    """Update session state (placeholder — not implemented)."""
    return {"ok": True}


@sio.on("get-messages")
async def on_get_messages(sid: str, data: dict):
    """Retrieve paginated messages for a session."""
    session_id = data.get("sessionId", "")
    from_seq = data.get("fromSeq")
    limit = data.get("limit", 50)
    result = await storage.get_messages(session_id, from_seq, limit)
    return result


@sio.on("batch-message")
async def on_batch_message(sid: str, data: dict):
    """Receive and store a batch of messages for a session.

    Returns:
        Dict with ``ok`` and a list of assigned sequence numbers (``seqs``).
    """
    session_id = data.get("sessionId", "")
    messages = data.get("messages", [])
    results = []
    for msg in messages:
        stored = await storage.store_message(
            session_id=session_id,
            message_id=f"msg_{uuid.uuid4().hex[:16]}",
            content=msg.get("content", {}),
            local_id=msg.get("localId"),
        )
        results.append(stored["seq"])
    return {"ok": True, "seqs": results}


@sio.on("rename-session")
async def on_rename_session(sid: str, data: dict):
    """Rename a session by updating its tag."""
    session_id = data.get("sessionId", "")
    new_tag = data.get("tag", "")
    if session_id:
        await storage._conn.execute(
            "UPDATE sessions SET tag=? WHERE id=?", (new_tag, session_id)
        )
        await storage._conn.commit()
    return {"ok": True}


@sio.on("client-visibility")
async def on_client_visibility(sid: str, data: dict):
    """Update client visibility state (e.g. Web UI tab focus).

    Placeholder — no action taken.
    """
    return {"ok": True}


@sio.on("list-sessions")
async def on_list_sessions(sid: str, data: dict):
    """List sessions, optionally filtered by machine ID or status."""
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "") or (data or {}).get(
        "machineId", ""
    )
    status_filter = (data or {}).get("status")
    sessions = await storage.list_sessions(machine_id, status_filter)
    return {"ok": True, "sessions": sessions}


# ─── HTTP Routes ────────────────────────────────────

app = FastAPI(title="AgentDock Server", version="0.1.0")

# CORS — allow all origins by default (configurable via settings)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend files (SPA served from ``static/`` directory)
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
(STATIC_DIR / "css").mkdir(exist_ok=True)
(STATIC_DIR / "js").mkdir(exist_ok=True)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/app")
    @app.get("/app/{path:path}")
    async def serve_spa(path: str = ""):
        """Serve the Single Page Application for ``/app/*`` routes (SPA catch-all)."""
        spa_path = STATIC_DIR / "index.html"
        if spa_path.exists():
            return HTMLResponse(spa_path.read_text())
        return HTMLResponse("<h1>Frontend not built yet</h1>", status_code=404)

# Hardening middleware — global error handler and request timeout
app.add_middleware(GlobalErrorHandler, debug=True)
app.add_middleware(RequestTimeoutMiddleware)

# FastAPI exception handlers (structured error format)


@app.exception_handler(HTTPException)
async def fastapi_http_exception_handler(request, exc):
    """Convert all ``HTTPException`` to the structured error format."""
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail:
        payload = detail
    else:
        code = (
            "not-found" if exc.status_code == 404 else
            "unauthorized" if exc.status_code == 401 else
            "invalid-params" if exc.status_code == 400 else
            "rate-limited" if exc.status_code == 429 else
            "http-error"
        )
        payload = structured_error(
            code,
            str(detail) if detail else "http-error",
            request_id=uuid.uuid4().hex[:16],
        )
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Return structured 404 errors."""
    if (
        hasattr(exc, 'detail')
        and isinstance(exc.detail, dict)
        and 'error' in exc.detail
    ):
        return JSONResponse(status_code=404, content=exc.detail)
    return JSONResponse(
        status_code=404,
        content=structured_error(
            "not-found",
            f"Route not found: {request.url.path}",
            request_id=uuid.uuid4().hex[:16],
        ),
    )


@app.exception_handler(Exception)
async def fastapi_generic_exception_handler(request, exc):
    """Catch-all exception handler — logs and returns 500."""
    logger.exception(f"Unhandled: {exc}")
    return JSONResponse(
        status_code=500,
        content=structured_error(
            "internal-error",
            "Internal server error",
            detail=str(exc),
            request_id=uuid.uuid4().hex[:16],
        ),
    )

# Mount Socket.IO ASGI app on the configured socket path
sio_asgi_app = socketio.ASGIApp(
    sio,
    other_asgi_app=app,
    socketio_path=settings.socket_path.lstrip('/'),
)


# ─── REST API ───────────────────────────────────────
# Pydantic models for request validation


class PairingRequestIn(BaseModel):
    """POST /v1/pairing/request body."""
    publicKey: str
    pin: Optional[str] = None
    label: Optional[str] = None
    type: Optional[str] = None


class PairingRespondIn(BaseModel):
    """POST /v1/pairing/respond body."""
    publicKey: str
    encryptedPayload: str


class AuthRequestIn(BaseModel):
    """POST /v1/auth body — supports both key-based and challenge-response flow."""
    challenge: Optional[str] = None
    nonce: Optional[str] = None          # Alias for challenge (wire protocol)
    publicKey: Optional[str] = None
    signature: Optional[str] = None
    key: Optional[str] = None

    def get_challenge(self) -> Optional[str]:
        """Return the challenge value regardless of which field was used."""
        return self.nonce or self.challenge


class PairingExchangeIn(BaseModel):
    """POST /v1/pairing/exchange body."""
    daemonPublicKey: str
    devicePublicKey: str


class PairingDeliverIn(BaseModel):
    """POST /v1/pairing/deliver body."""
    publicKey: str
    encryptedPayload: str


class AnswerQuestionIn(BaseModel):
    """POST /v1/sessions/{id}/answer body."""
    requestId: str
    text: str


class PermissionIn(BaseModel):
    """POST /v1/sessions/{id}/permission body."""
    requestId: str
    action: str = "approve"
    reason: Optional[str] = None


class SwitchModeIn(BaseModel):
    """POST /v1/sessions/{id}/switch-mode body."""
    mode: str = "default"


class SpawnSessionIn(BaseModel):
    """POST /v1/sessions/create or /v1/sessions/{id}/spawn body."""
    agentType: str = "claude"
    cwd: str = ""
    prompt: Optional[str] = None
    permissionMode: str = "default"
    model: Optional[str] = None
    machineId: Optional[str] = None
    env: Optional[dict] = None
    baseUrl: Optional[str] = None
    appendSystemPrompt: Optional[str] = None
    allowedTools: Optional[list[str]] = None
    disallowedTools: Optional[list[str]] = None
    maxTurns: Optional[int] = None
    resumeSessionId: Optional[str] = None
    serverSessionId: Optional[str] = None
    source: str = "managed"
    background: bool = False


class CheckPathIn(BaseModel):
    """POST /v1/check-path body."""
    cwd: str = "/"
    machineId: Optional[str] = None


class ClientMessageIn(BaseModel):
    """POST /v1/messages/send body."""
    sessionId: str
    content: dict
    localId: Optional[str] = None
    skipBroadcast: bool = False


class RpcCallIn(BaseModel):
    """POST /v1/rpc/call body."""
    machineId: str
    method: str
    params: dict = {}


# ─── Pairing Endpoints ────────────────────────────────


@app.post("/v1/pairing/request")
async def pairing_request(body: PairingRequestIn, request: Request):
    """CLI initiates a pairing request.

    Creates or updates a pairing request with a PIN for the user to enter
    on the Web UI.  Circuit breaker guards against brute force per client IP.

    Returns:
        Dict with ``pin``, ``pairingUrl``, and ``ttl``.
    """
    # Per-IP rate limiting via circuit breaker
    client_ip = request.client.host if request.client else "unknown"
    pair_cb = cb_registry.get(
        "pairing", client_ip,
        failure_threshold=10,
        recovery_timeout=60.0,
    )
    if not pair_cb.allow_request():
        raise StructuredHTTPException(
            "rate-limited",
            "Too many pairing attempts. Try again later.",
            status_code=429,
        )

    public_key = body.publicKey
    pairing_type = body.type or "join"
    label = body.label
    pin = body.pin or generate_pin()

    # Reuse existing pending request if available
    existing = await storage.get_pairing_request(public_key)
    if (
        existing
        and existing["state"] == "pending"
        and existing["expires_at"] > time.time()
    ):
        pin = existing["pin"]
    else:
        await storage.create_pairing_request(public_key, pin, label, pairing_type)

    server_url = str(request.base_url).rstrip("/")
    pairing_url = generate_pairing_url(public_key, server_url)

    return {
        "pin": pin,
        "pairingUrl": pairing_url,
        "ttl": settings.pairing_pin_ttl,
    }


@app.post("/v1/pairing/respond")
async def pairing_respond(body: PairingRespondIn):
    """Web UI confirms a pairing with an encrypted payload.

    Transitions the pairing from ``pending`` to ``authorized`` and returns
    an auth token.

    Returns:
        Dict with ``ok`` and ``token``.

    Raises:
        404: If the pairing request is not found or expired.
    """
    token = await storage.respond_pairing(body.publicKey, body.encryptedPayload)
    if token is None:
        raise HTTPException(
            status_code=404, detail="pairing-request-not-found-or-expired"
        )
    return {"ok": True, "token": token}


@app.get("/v1/pairing/status/{public_key}")
async def pairing_status(public_key: str):
    """CLI polls for pairing status.

    Returns the current state of the pairing request:
    ``pending``, ``exchange``, ``authorized``, or ``expired``.
    """
    await storage.expire_stale_pairings()
    req = await storage.get_pairing_request(public_key)
    if not req:
        return {"state": "expired", "publicKey": public_key}

    state = req["state"]
    if state == "pending":
        return {"state": "pending", "publicKey": public_key}
    elif state == "expired":
        return {"state": "expired", "publicKey": public_key}
    elif state == "exchange":
        return {
            "state": "exchange",
            "publicKey": public_key,
            "devicePublicKey": req.get("device_public_key", ""),
        }
    elif state == "authorized":
        return {
            "state": "authorized",
            "publicKey": public_key,
            "encryptedPayload": req.get("encrypted_payload", ""),
            "token": req.get("token", ""),
        }
    return {"state": "expired", "publicKey": public_key}


# ─── Auth Endpoints ──────────────────────────────────


@app.post("/v1/auth")
async def auth_handler(body: AuthRequestIn):
    """Auth endpoint — supports two modes:

    1. **Key-based token exchange**: Present the public key after pairing.
       Returns the previously authorized token.
    2. **Ed25519 challenge-response**: Verify a signed challenge nonce.
       Returns a new token and machine ID.

    Raises:
        400: Invalid parameters.
        401: Pairing not authorized or signature mismatch.
    """
    key = body.key
    public_key = body.publicKey
    challenge_b64 = body.get_challenge()
    signature_b64 = body.signature

    import base64

    if key:
        # Key-based flow — return existing authorized token
        req = await storage.get_pairing_request(key)
        if not req or req["state"] != "authorized":
            raise HTTPException(status_code=401, detail="pairing-not-authorized")

        token = req.get("token", "")
        if not token:
            token = generate_token()
            machine_id = f"m_{uuid.uuid4().hex[:12]}"
            await storage.create_auth_token(
                token, machine_id=machine_id, public_key=key
            )
            await storage.authorize_pairing(key, token)

        return {"token": token, "serverUrl": ""}

    elif challenge_b64 and public_key and signature_b64:
        # Ed25519 challenge-response flow
        try:
            challenge = base64.b64decode(challenge_b64)
            pubkey = base64.b64decode(public_key)
            sig = base64.b64decode(signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid-base64")

        valid = agentdock_crypto.verify_challenge(challenge, pubkey, sig)
        if not valid:
            raise HTTPException(status_code=401, detail="signature-mismatch")

        token = generate_token()
        machine_id = f"m_{uuid.uuid4().hex[:12]}"
        await storage.create_auth_token(token, machine_id=machine_id)
        return {"token": token, "serverUrl": ""}

    else:
        raise HTTPException(status_code=400, detail="invalid-auth-params")


@app.post("/v1/auth/challenge")
async def auth_challenge():
    """Issue a random Ed25519 challenge nonce for the CLI to sign.

    Returns:
        Dict with ``nonce`` (base64) and ``challengeId``.
    """
    import base64
    nonce = secrets.token_bytes(32)
    nonce_id = f"ch_{uuid.uuid4().hex[:16]}"
    auth_challenges[nonce_id] = {
        "nonce": nonce,
        "created_at": time.time(),
    }
    logger.info(f"auth challenge issued: {nonce_id}")
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "challengeId": nonce_id,
    }


@app.post("/v1/auth/verify")
async def auth_verify(body: AuthRequestIn):
    """Verify an Ed25519 signature against a previously issued challenge.

    On success returns an auth token with expiration.

    Body: ``{ publicKey, nonce, signature, challengeId? }``

    Raises:
        400: Invalid base64 or missing parameters.
        401: Signature verification failed.
    """
    import base64

    public_key_b64 = body.publicKey
    nonce_b64 = body.get_challenge()
    signature_b64 = body.signature
    challenge_id = body.key or ""

    if not all([public_key_b64, nonce_b64, signature_b64]):
        raise StructuredHTTPException(
            "invalid-params",
            "publicKey, nonce, and signature are required",
            status_code=400,
        )

    try:
        challenge = base64.b64decode(nonce_b64)
        pubkey = base64.b64decode(public_key_b64)
        sig = base64.b64decode(signature_b64)
    except Exception:
        raise StructuredHTTPException(
            "invalid-base64", "Invalid base64 encoding", status_code=400
        )

    # Verify the Ed25519 signature
    valid = agentdock_crypto.verify_challenge(challenge, pubkey, sig)
    if not valid:
        cb_registry.fail("auth", "challenge-response")
        raise StructuredHTTPException(
            "signature-mismatch",
            "Signature verification failed",
            status_code=401,
        )

    cb_registry.succeed("auth", "challenge-response")

    # Check if this public key was already paired
    existing = await storage.get_machine_by_public_key(public_key_b64)
    if existing:
        token = generate_token()
        await storage.create_auth_token(
            token, machine_id=existing["id"], public_key=public_key_b64
        )
        expires_at = time.time() + settings.token_ttl
    else:
        token = generate_token()
        machine_id = f"m_{uuid.uuid4().hex[:12]}"
        token_info = await storage.create_auth_token(
            token, machine_id=machine_id, public_key=public_key_b64
        )
        expires_at = token_info["expires_at"]

    logger.info(f"auth verify success: publicKey={public_key_b64[:16]}...")
    return {
        "token": token,
        "expiresAt": int(expires_at),
        "machineId": existing["id"] if existing else machine_id,
    }


# ─── Pairing Exchange / Delivery ────────────────────


@app.post("/v1/pairing/exchange")
async def pairing_exchange(body: PairingExchangeIn):
    """Exchange public keys during the invite flow.

    Transitions the pairing state from ``pending`` to ``exchange``.
    """
    daemon_key = body.daemonPublicKey
    device_key = body.devicePublicKey
    req = await storage.get_pairing_request(daemon_key)
    if not req:
        raise HTTPException(status_code=404, detail="pairing-request-not-found")

    await storage._conn.execute(
        "UPDATE pairing_requests SET state='exchange', device_public_key=? "
        "WHERE public_key=?",
        (device_key, daemon_key),
    )
    await storage._conn.commit()
    return {"ok": True}


@app.post("/v1/pairing/deliver", dependencies=[Depends(require_auth)])
async def pairing_deliver(body: PairingDeliverIn):
    """Deliver the encrypted master secret to a newly paired device."""
    await storage._conn.execute(
        "UPDATE pairing_requests SET encrypted_payload=?, state='authorized' "
        "WHERE public_key=?",
        (body.encryptedPayload, body.publicKey),
    )
    await storage._conn.commit()
    return {"ok": True}


# ─── Machine Endpoints ───────────────────────────────


@app.get("/v1/machines", dependencies=[Depends(require_auth)])
async def list_machines():
    """List all registered machines in wire-protocol camelCase."""
    raw = await storage.list_machines()
    machines = []
    for m in raw:
        machines.append({
            "id": m["id"],
            "hostname": m["hostname"],
            "platform": m["platform"],
            "arch": m.get("arch", ""),
            "displayName": m.get("display_name", ""),
            "daemonVersion": m.get("daemon_version", ""),
            "active": bool(m.get("active", 0)),
            "activeAt": m.get("active_at", 0),
            "createdAt": m["created_at"],
            "availableAgents": m.get("available_agents", []),
            "supportedMethods": m.get("supported_methods", []),
            "lastHeartbeat": m.get("last_heartbeat", 0),
            "disconnectReason": m.get("disconnect_reason"),
        })
    return {"machines": machines}


@app.get("/v1/machines/{machine_id}", dependencies=[Depends(require_auth)])
async def get_machine(machine_id: str):
    """Get details for a single machine by ID."""
    m = await storage.get_machine(machine_id)
    if not m:
        raise HTTPException(status_code=404, detail="machine-not-found")
    return {
        "machine": {
            "id": m["id"],
            "hostname": m["hostname"],
            "platform": m["platform"],
            "arch": m.get("arch", ""),
            "displayName": m.get("display_name", ""),
            "daemonVersion": m.get("daemon_version", ""),
            "active": bool(m.get("active", 0)),
            "activeAt": m.get("active_at", 0),
            "createdAt": m["created_at"],
            "availableAgents": m.get("available_agents", []),
            "supportedMethods": m.get("supported_methods", []),
            "lastHeartbeat": m.get("last_heartbeat", 0),
            "disconnectReason": m.get("disconnect_reason"),
        }
    }


@app.get("/v1/machines/{machine_id}/info", dependencies=[Depends(require_auth)])
async def get_machine_info(machine_id: str):
    """Get machine info via RPC (``get-machine-info``).

    Requires the machine to be connected.
    """
    if machine_id not in machine_sids or not machine_sids[machine_id]:
        raise HTTPException(status_code=503, detail="machine-not-connected")
    result = await dispatch_rpc_to_daemon(
        machine_id, "get-machine-info", {}, timeout=15.0
    )
    return result


@app.get(
    "/v1/machines/{machine_id}/checkpoints",
    dependencies=[Depends(require_auth)],
)
async def list_checkpoints(machine_id: str):
    """List session checkpoints on a machine via RPC."""
    if machine_id not in machine_sids or not machine_sids[machine_id]:
        raise HTTPException(status_code=503, detail="machine-not-connected")
    result = await dispatch_rpc_to_daemon(
        machine_id, "checkpoint-list", {}, timeout=30.0
    )
    return result


# ─── Session Endpoints ────────────────────────────────


@app.get("/v1/sessions", dependencies=[Depends(require_auth)])
async def list_all_sessions(machine_id: str = None, status: str = None):
    """List all sessions, optionally filtered by machine_id and/or status.

    Returns wire-protocol camelCase fields.
    """
    raw = await storage.list_sessions(machine_id, status)
    sessions = []
    for s in raw:
        sessions.append({
            "id": s["id"],
            "machineId": s["machine_id"],
            "tag": s["tag"],
            "status": s["status"],
            "metadata": s.get("metadata", {}),
            "wrappedDek": s.get("wrapped_dek"),
            "source": s.get("source", "managed"),
            "claudeSessionId": s.get("claude_session_id"),
            "projectPath": s.get("project_path"),
            "createdAt": s["created_at"],
            "updatedAt": s["updated_at"],
            "endedAt": s.get("ended_at"),
        })
    return {"sessions": sessions}


@app.get("/v1/sessions/{session_id}", dependencies=[Depends(require_auth)])
async def get_session(session_id: str):
    """Get session details, including the wrapped DEK for client-side decryption."""
    session = await storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="session-not-found")
    return {
        "session": {
            "id": session["id"],
            "machineId": session["machine_id"],
            "tag": session["tag"],
            "status": session["status"],
            "metadata": session.get("metadata", {}),
            "wrappedDek": session.get("wrapped_dek"),
            "source": session.get("source", "managed"),
            "claudeSessionId": session.get("claude_session_id"),
            "projectPath": session.get("project_path"),
            "createdAt": session["created_at"],
            "updatedAt": session["updated_at"],
            "endedAt": session.get("ended_at"),
        }
    }


@app.get(
    "/v1/sessions/{session_id}/dek",
    dependencies=[Depends(require_auth)],
)
async def get_session_dek(session_id: str):
    """Get the wrapped data encryption key for a session (client-side decryption)."""
    session = await storage.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="session-not-found")
    return {
        "sessionId": session_id,
        "dataEncryptionKey": session.get("wrapped_dek"),
    }


# ─── Session-scoped RPC endpoints ──────────────────


@app.post("/v1/sessions/create", dependencies=[Depends(require_auth)])
async def create_session(body: SpawnSessionIn):
    """One-step session creation: reserves a session ID, finds a machine,
    and spawns the daemon session.

    Returns:
        Dict with ``ok``, ``sessionId``, ``machineId``, and ``daemonResult``.
    """
    session_id = f"s_{uuid.uuid4().hex[:16]}"
    params = body.dict(exclude_none=True)
    params["serverSessionId"] = session_id
    machine_id = params.pop("machineId", "") or ""
    agent_type = params.get("agentType", "claude")

    # Find a connected machine that supports this agent type
    if not machine_id:
        machines = await storage.list_machines()
        for m in machines:
            m_id = m.get("id", "")
            if m_id in machine_sids and machine_sids[m_id]:
                agents = m.get("available_agents", [])
                if not agents or agent_type in agents:
                    machine_id = m_id
                    break

    if not machine_id:
        raise StructuredHTTPException(
            "no-available-machine",
            "No connected machine available",
            status_code=503,
        )

    session_owners[session_id] = machine_id

    try:
        result = await dispatch_rpc_to_daemon(
            machine_id, "spawn-session", params, timeout=60.0
        )
        return {
            "ok": True,
            "sessionId": session_id,
            "machineId": machine_id,
            "daemonResult": result,
        }
    except Exception as e:
        raise StructuredHTTPException(
            "rpc-error", f"Spawn failed: {e}", status_code=502
        )


@app.post("/v1/sessions/{session_id}/spawn", dependencies=[Depends(require_auth)])
async def spawn_session_v2(session_id: str, body: SpawnSessionIn):
    """Spawn a new session with a specific session ID (Pydantic-validated).

    Matches ``SpawnSessionParams`` from ``wire/rpc.d.ts``.
    """
    params = body.dict(exclude_none=True)
    params["serverSessionId"] = session_id
    machine_id = params.pop("machineId", "") or ""
    agent_type = params.get("agentType", "claude")

    if not machine_id:
        machines = await storage.list_machines()
        for m in machines:
            m_id = m.get("id", "")
            if m_id in machine_sids and machine_sids[m_id]:
                agents = m.get("available_agents", [])
                if not agents or agent_type in agents:
                    machine_id = m_id
                    break

    if not machine_id:
        raise HTTPException(status_code=503, detail="no-available-machine")

    session_owners[session_id] = machine_id
    result = await dispatch_rpc_to_daemon(
        machine_id, "spawn-session", params, timeout=60.0
    )
    return {
        "ok": True,
        "sessionId": session_id,
        "machineId": machine_id,
        "daemonResult": result,
    }


@app.post(
    "/v1/sessions/{session_id}/abort",
    dependencies=[Depends(require_auth)],
)
async def session_abort(session_id: str):
    """Web UI aborts the current turn in a session."""
    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        raise HTTPException(status_code=404, detail="session-not-found")
    result = await dispatch_rpc_to_daemon(
        machine_id, "abort", {"sessionId": session_id}, timeout=15.0,
    )
    return result


@app.post(
    "/v1/sessions/{session_id}/stop",
    dependencies=[Depends(require_auth)],
)
async def session_stop(session_id: str):
    """Web UI stops a session completely."""
    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        raise HTTPException(status_code=404, detail="session-not-found")
    result = await dispatch_rpc_to_daemon(
        machine_id, "stop-session", {"sessionId": session_id}, timeout=30.0,
    )
    await storage.end_session(session_id)
    session_owners.pop(session_id, None)
    return result


@app.post(
    "/v1/sessions/{session_id}/answer",
    dependencies=[Depends(require_auth)],
)
async def session_answer_question_v2(session_id: str, body: AnswerQuestionIn):
    """Web UI answers a question posed by the agent in the session."""
    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        raise HTTPException(status_code=404, detail="session-not-found")
    result = await dispatch_rpc_to_daemon(
        machine_id, "answer-question",
        {"sessionId": session_id, "requestId": body.requestId, "text": body.text},
        timeout=30.0,
    )
    return result


@app.post(
    "/v1/sessions/{session_id}/permission",
    dependencies=[Depends(require_auth)],
)
async def session_permission_v2(session_id: str, body: PermissionIn):
    """Web UI approves or denies a permission request from the agent."""
    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        raise HTTPException(status_code=404, detail="session-not-found")
    method = "deny-permission" if body.action == "deny" else "approve-permission"
    params = {
        "sessionId": session_id,
        "requestId": body.requestId,
        "action": body.action,
    }
    if body.reason:
        params["reason"] = body.reason
    result = await dispatch_rpc_to_daemon(machine_id, method, params, timeout=30.0)
    return result


@app.post(
    "/v1/sessions/{session_id}/switch-mode",
    dependencies=[Depends(require_auth)],
)
async def session_switch_mode_v2(session_id: str, body: SwitchModeIn):
    """Web UI switches the permission mode for a session."""
    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        raise HTTPException(status_code=404, detail="session-not-found")
    result = await dispatch_rpc_to_daemon(
        machine_id, "switch-mode",
        {"sessionId": session_id, "mode": body.mode},
        timeout=15.0,
    )
    return result


# ─── Message Endpoints ────────────────────────────────


@app.get(
    "/v1/messages/{session_id}",
    dependencies=[Depends(require_auth)],
)
async def get_messages(session_id: str, from_seq: int = None, limit: int = 50):
    """Get paginated messages for a session."""
    result = await storage.get_messages(session_id, from_seq, limit)
    return result


@app.post("/v1/messages/send", dependencies=[Depends(require_auth)])
async def send_client_message(body: ClientMessageIn):
    """Web UI sends an encrypted message to a session via REST.

    The message is persisted and forwarded to the daemon via Socket.IO.
    """
    session_id = body.sessionId
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    stored = await storage.store_message(
        session_id=session_id,
        message_id=message_id,
        content=body.content,
        local_id=body.localId,
    )

    # Route to daemon
    machine_id = session_owners.get(session_id, "")
    if machine_id and machine_id in machine_sids:
        sids = machine_sids.get(machine_id, set())
        for sid in sids:
            await sio.emit(
                "message",
                {"sessionId": session_id, "message": stored},
                to=sid,
            )

    return {"ok": True, "seq": stored["seq"]}


# ─── Health / Root ────────────────────────────────────


@app.get("/v1/health")
async def health():
    """Health check — returns protocol version and connected machine count."""
    connected = await storage.count_connected_machines()
    return {
        "ok": True,
        "protocolVersion": settings.protocol_version,
        "connectedMachines": connected,
    }


@app.get("/")
async def root():
    """Root endpoint — returns service metadata."""
    return {"service": "AgentDock Server", "version": "0.1.0"}


@app.get("/v1/pairing/request")
async def pairing_request_get(publicKey: str, request: Request):
    """GET version of pairing request for simpler clients."""
    return await pairing_request(PairingRequestIn(publicKey=publicKey), request)


@app.get("/v1/pairing/find-by-pin/{pin}")
async def pairing_find_by_pin(pin: str):
    """Find a pending pairing request by PIN.

    Used by the Web UI to look up a pairing request during the pairing flow.
    """
    req = await storage.get_pairing_by_pin(pin)
    if not req:
        raise StructuredHTTPException(
            "not-found",
            f"No pending pairing request for PIN {pin}",
            status_code=404,
        )
    return {
        "publicKey": req["public_key"],
        "state": req["state"],
        "label": req.get("label", ""),
        "createdAt": req["created_at"],
        "expiresAt": req["expires_at"],
    }


# ─── RPC dispatch: Web UI -> Daemon ──────────────────


async def dispatch_rpc_to_daemon(
    machine_id: str,
    method: str,
    params: dict = None,
    timeout: float = 30.0,
) -> dict:
    """Send an RPC request to a connected daemon with circuit breaker guard.

    Sends the RPC to all connected Socket.IO sessions for the machine.
    Waits for a response via the ``pending_rpcs`` future mechanism.

    Args:
        machine_id: Target machine ID.
        method: RPC method name.
        params: Optional parameters dict.
        timeout: Maximum wait time in seconds.

    Returns:
        The response dict from the daemon.

    Raises:
        StructuredHTTPException 503: Machine not connected.
        StructuredHTTPException 504: RPC timed out.
    """
    sids = machine_sids.get(machine_id, set())
    if not sids:
        raise StructuredHTTPException(
            "machine-not-connected",
            f"Machine {machine_id} not connected",
            status_code=503,
        )

    async def _do_rpc():
        call_id = f"rpc_{uuid.uuid4().hex[:16]}"
        future = asyncio.get_event_loop().create_future()
        pending_rpcs[call_id] = future

        # Send to all connected Socket.IO sessions for this machine
        for sid in sids:
            await sio.emit(
                "rpc-request",
                {"id": call_id, "method": method, "params": params or {}},
                to=sid,
            )

        try:
            result = await asyncio.wait_for(future, timeout)
            return result
        except asyncio.TimeoutError:
            pending_rpcs.pop(call_id, None)
            raise StructuredHTTPException(
                "rpc-timeout",
                f"RPC {method} timed out ({timeout}s)",
                status_code=504,
            )

    return await circuit_breaker_call(
        cb_registry,
        "rpc",
        f"{machine_id}:{method}",
        _do_rpc,
        timeout=timeout + 5,
        fallback=lambda: {
            "ok": False,
            "error": "circuit-open",
            "detail": f"RPC {method} circuit open for {machine_id}",
        },
    )


# ─── RPC endpoints for Web UI ──────────────────────


@app.post("/v1/rpc/call", dependencies=[Depends(require_auth)])
async def web_rpc_call(body: RpcCallIn):
    """Web UI calls a machine-scoped RPC on a daemon.

    Body includes ``machineId``, ``method``, and optional ``params``.
    """
    result = await dispatch_rpc_to_daemon(
        body.machineId, body.method, body.params
    )
    return result


@app.post("/v1/check-path", dependencies=[Depends(require_auth)])
async def check_path(body: CheckPathIn):
    """Check if a directory path exists on a machine via RPC."""
    machine_id = body.machineId or ""
    if not machine_id:
        machines = await storage.list_machines()
        for m in machines:
            if m.get("active"):
                machine_id = m["id"]
                break
    if not machine_id or machine_id not in machine_sids:
        raise HTTPException(status_code=503, detail="no-connected-machine")
    result = await dispatch_rpc_to_daemon(
        machine_id, "check-path", {"cwd": body.cwd}, timeout=15.0
    )
    return result


# ─── Additional Socket Events ─────────────────────────


@sio.on("ephemeral")
async def on_ephemeral(sid: str, data: dict):
    """Handle ephemeral (transient) messages — relay to Web UI without storage."""
    session_id = data.get("sessionId", "")
    if session_id:
        await sio.emit(
            "ephemeral", data,
            room=f"session:{session_id}",
            skip_sid=sid,
        )
    return {"ok": True}


@sio.on("usage-report")
async def on_usage_report(sid: str, data: dict):
    """Handle usage / telemetry reports from daemon (e.g. turn-end tokens)."""
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "")
    session_id = data.get("sessionId", "")
    event_type = data.get("eventType", "usage-report")
    payload = data.get("payload", {})
    await storage.record_usage(session_id, machine_id, event_type, payload)
    return {"ok": True}


@sio.on("telemetry-report")
async def on_telemetry_report(sid: str, data: dict):
    """Handle telemetry reports."""
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "")
    session_id = data.get("sessionId", "")
    payload = data.get("payload", {})
    await storage.record_usage(session_id, machine_id, "telemetry", payload)
    return {"ok": True}


@sio.on("get-known-claude-sessions")
async def on_get_known_claude_sessions(sid: str, data: dict):
    """History sync: return known Claude CLI sessions for a machine."""
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "")
    if not machine_id:
        return {"ok": False, "error": "not-authenticated"}
    sessions = await storage.get_known_claude_sessions(machine_id)
    return {"ok": True, "sessions": sessions}


@sio.on("register-history-sessions")
async def on_register_history_sessions(sid: str, data: dict):
    """History sync: register discovered Claude CLI sessions."""
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "")
    if not machine_id:
        return {"ok": False, "error": "not-authenticated"}
    sessions = data.get("sessions", [])
    ids = []
    for sess in sessions:
        sid_ = await storage.register_history_session(
            machine_id,
            sess.get("claudeSessionId"),
            sess,
        )
        ids.append(sid_)
    return {"ok": True, "historySessionIds": ids}


@sio.on("update-sync-status")
async def on_update_sync_status(sid: str, data: dict):
    """Update history sync status (placeholder)."""
    return {"ok": True}


@sio.on("permission-resolved")
async def on_permission_resolved(sid: str, data: dict):
    """Relay a permission resolution event from daemon to Web UI.

    The daemon sends this after the Web UI approves or denies a permission.
    """
    session_id = data.get("sessionId", "")
    if session_id:
        await sio.emit(
            "permission-resolved", data,
            room=f"session:{session_id}",
            skip_sid=sid,
        )
    return {"ok": True}


@sio.on("core-update")
async def on_core_update(sid: str, data: dict):
    """Relay a ``CoreUpdateContainer`` event (wire/sync.d.ts).

    Handles sub-types:
      - ``new-message``: Store and broadcast to subscribers.
      - ``update-session``: Update session metadata.
      - ``update-machine``: Refresh heartbeat.
      - ``session-reset``: End the session.
    """
    body = data.get("body", {})
    body_t = body.get("t", "")
    info = connected_daemons.get(sid)
    machine_id = (info or {}).get("machine_id", "")

    if body_t == "new-message":
        sid_ = body.get("sid", "")
        msg = body.get("message", {})
        if sid_ and msg:
            message_id = msg.get("id", f"msg_{uuid.uuid4().hex[:16]}")
            stored = await storage.store_message(
                session_id=sid_,
                message_id=message_id,
                content=msg.get("content", {}),
                local_id=msg.get("localId"),
            )
            await sio.emit(
                "message",
                {"sessionId": sid_, "message": stored},
                room=f"session:{sid_}",
                skip_sid=sid,
            )

    elif body_t == "update-session":
        session_id = body.get("id", "")
        if session_id:
            existing = await storage.get_session(session_id)
            if existing:
                meta = existing.get("metadata", {})
                if isinstance(meta, str):
                    meta = json.loads(meta)
                if body.get("tag"):
                    meta["tag"] = body["tag"]
                if body.get("source"):
                    meta["source"] = body["source"]
                await storage.update_session_metadata(session_id, meta)
                # Promote from history to managed on resume
                if (
                    body.get("source") == "managed"
                    and existing.get("status") == "ended"
                ):
                    await storage._conn.execute(
                        "UPDATE sessions SET status='active', updated_at=? WHERE id=?",
                        (time.time(), session_id),
                    )
                    await storage._conn.commit()

    elif body_t == "update-machine" and machine_id:
        await storage.heartbeat_machine(machine_id)

    elif body_t == "session-reset":
        sid_ = body.get("sessionId", "")
        if sid_:
            await storage.end_session(sid_, {"summary": "reset"})

    # Broadcast update to all user-scoped clients
    await sio.emit("core-update", data, room="user-scoped", skip_sid=sid)
    return {"ok": True}


@sio.on("user-input")
async def on_user_input(sid: str, data: dict):
    """Web UI sends user input to a session (answer-question relay).

    This is the Socket.IO equivalent of the REST ``/answer`` endpoint.
    """
    session_id = data.get("sessionId", "")
    request_id = data.get("requestId", "")
    text = data.get("text", "")

    if not session_id:
        return {"ok": False, "error": "sessionId-required"}

    machine_id = session_owners.get(session_id, "")
    if not machine_id:
        session = await storage.get_session(session_id)
        if session:
            machine_id = session.get("machine_id", "")
    if not machine_id:
        return {"ok": False, "error": "session-not-found"}

    method = "answer-question"
    params = {
        "sessionId": session_id,
        "requestId": request_id,
        "text": text,
    }

    call_id = f"rpc_{uuid.uuid4().hex[:16]}"
    future = asyncio.get_event_loop().create_future()
    pending_rpcs[call_id] = future

    sids = machine_sids.get(machine_id, set())
    for msid in sids:
        await sio.emit(
            "rpc-request",
            {"id": call_id, "method": method, "params": params},
            to=msid,
        )

    try:
        result = await asyncio.wait_for(future, timeout=30.0)
        return result
    except asyncio.TimeoutError:
        pending_rpcs.pop(call_id, None)
        return {"ok": False, "error": "rpc-timeout"}


# ─── Hardening endpoints ──────────────────────────────


@app.get("/v1/circuit-breakers", dependencies=[Depends(require_auth)])
async def get_circuit_breaker_stats():
    """Get circuit breaker status across all dimensions."""
    return {"circuitBreakers": cb_registry.all_stats()}


@app.post("/v1/circuit-breakers/reset", dependencies=[Depends(require_auth)])
async def reset_circuit_breakers():
    """Reset all circuit breakers."""
    cb_registry.reset_all()
    return {"ok": True}


@app.get("/v1/reconnect/state", dependencies=[Depends(require_auth)])
async def get_reconnect_state(machine_id: str = None):
    """Get reconnection state for all machines or a specific one."""
    if machine_id:
        return {"machine": reconnect_mgr.get_state(machine_id)}
    return {"machines": {}}


# ─── History Sync (wire/sync.d.ts) ──────────────────


@app.post("/v1/backfill-history-session", dependencies=[Depends(require_auth)])
async def backfill_history_session(body: dict):
    """Backfill a history session imported by the daemon scanner."""
    machine_id = body.get("machineId", "")
    claude_session_id = body.get("claudeSessionId", "")
    if not machine_id or not claude_session_id:
        raise HTTPException(
            status_code=400,
            detail="machineId-and-claudeSessionId-required",
        )
    hid = await storage.register_history_session(
        machine_id, claude_session_id, body
    )
    return {"ok": True, "historySessionId": hid}


@app.get("/v1/history-sessions", dependencies=[Depends(require_auth)])
async def list_history_sessions(machine_id: str = None):
    """List known history sessions for a machine."""
    if not machine_id:
        return {"sessions": []}
    sessions = await storage.get_known_claude_sessions(machine_id)
    return {"sessions": sessions}


@app.post(
    "/v1/history-sessions/{history_id}/promote",
    dependencies=[Depends(require_auth)],
)
async def promote_history_session(history_id: str):
    """Promote a history session to managed (placeholder)."""
    return {"ok": True}


# ─── Task Engine ──────────────────────────────────────


async def _dispatch_spawn_for_scheduler(machine_id: str, params: dict) -> dict:
    """Dispatch a spawn-session RPC from the scheduler."""
    return await dispatch_rpc_to_daemon(
        machine_id, "spawn-session", params, timeout=60.0
    )


task_engine = TaskEngine(
    storage, dispatch_spawn_fn=_dispatch_spawn_for_scheduler
)


# ─── Stats endpoints (wire/stats.d.ts) ──────────────


@app.get("/v1/stats/overview", dependencies=[Depends(require_auth)])
async def stats_overview():
    """Get StatsOverview matching ``wire/stats.d.ts``."""
    return await storage.get_stats_overview()


@app.get("/v1/stats/claude", dependencies=[Depends(require_auth)])
async def stats_claude(machine_id: str = None):
    """Get ClaudeStatsData for all machines or a specific one."""
    return await storage.get_claude_stats_data(machine_id)


@app.get("/v1/stats/tokens/trend", dependencies=[Depends(require_auth)])
async def stats_token_trend(days: int = 30):
    """Get token usage trend over the last N days."""
    data = await storage.get_claude_stats_data()
    trends = []
    for dm in data.get("dailyModelTokens", []):
        total = sum(dm["tokensByModel"].values())
        trends.append({
            "date": dm["date"],
            "totalTokens": total,
            "inputTokens": 0,
            "outputTokens": total,
            "byModel": dm["tokensByModel"],
        })
    return {"trends": trends[-days:]}


@app.get("/v1/stats/projects", dependencies=[Depends(require_auth)])
async def stats_projects():
    """Get project summaries from session metadata."""
    return {"projects": await storage.get_project_summaries()}


@app.get("/v1/stats", dependencies=[Depends(require_auth)])
async def get_stats(machine_id: str = None):
    """Get quick usage statistics, optionally filtered by machine."""
    if machine_id:
        return await storage.get_machine_stats(machine_id)
    machines = await storage.list_machines()
    total_sessions = 0
    active_sessions = 0
    for m in machines:
        stats = await storage.get_machine_stats(m["id"])
        total_sessions += stats["totalSessions"]
        active_sessions += stats["activeSessions"]
    return {
        "totalSessions": total_sessions,
        "activeSessions": active_sessions,
        "onlineMachines": sum(1 for m in machines if m.get("active")),
        "totalMachines": len(machines),
    }


# ─── Scheduled Tasks CRUD (wire/scheduledTasks.d.ts) ─


@app.post("/v1/tasks", dependencies=[Depends(require_auth)])
async def create_task(body: dict):
    """Create a new scheduled task with a cron expression."""
    try:
        parse_cron(body.get("schedule", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    task = await task_engine.create_task(
        name=body["name"],
        schedule=body["schedule"],
        spawn_params=body.get("spawnParams", {}),
        enabled=body.get("enabled", True),
        machine_id=body.get("machineId", ""),
    )
    return {"task": task}


@app.get("/v1/tasks", dependencies=[Depends(require_auth)])
async def list_tasks():
    """List all scheduled tasks."""
    tasks = await task_engine.list_tasks()
    return {"tasks": tasks}


@app.get("/v1/tasks/{task_id}", dependencies=[Depends(require_auth)])
async def get_task(task_id: str):
    """Get a scheduled task by ID."""
    task = await task_engine.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task-not-found")
    return {"task": task}


@app.patch("/v1/tasks/{task_id}", dependencies=[Depends(require_auth)])
async def update_task(task_id: str, body: dict):
    """Update a scheduled task (partial update)."""
    if "schedule" in body:
        try:
            parse_cron(body["schedule"])
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    task = await task_engine.update_task(task_id, body)
    if not task:
        raise HTTPException(status_code=404, detail="task-not-found")
    return {"task": task}


@app.delete("/v1/tasks/{task_id}", dependencies=[Depends(require_auth)])
async def delete_task(task_id: str):
    """Delete a scheduled task."""
    deleted = await task_engine.delete_task(task_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="task-not-found")
    return {"ok": True}


@app.post("/v1/tasks/{task_id}/run", dependencies=[Depends(require_auth)])
async def run_task_manual(task_id: str):
    """Manually trigger a task execution."""
    task = await task_engine.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="task-not-found")
    exec_record = await task_engine.create_execution(task_id, "manual")
    asyncio.create_task(task_engine._execute_task(task))
    return {"execution": exec_record}


@app.get(
    "/v1/tasks/{task_id}/executions",
    dependencies=[Depends(require_auth)],
)
async def get_task_executions(task_id: str, limit: int = 20):
    """Get execution history for a task."""
    executions = await task_engine.get_executions(task_id, limit)
    return {"executions": executions}


# ─── Application Lifespan ────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initializes storage, scheduler, and cleanup.

    On startup:
      - Connects to SQLite and creates tables.
      - Initialises the task engine tables.
      - Starts the scheduler if cron tasks exist.

    On shutdown:
      - Stops the scheduler.
      - Closes the database connection.
    """
    await storage.connect()
    await task_engine.init_db()

    # Start the scheduler if there are already cron tasks defined
    tasks = await task_engine.list_tasks()
    if tasks:
        await task_engine.start()

    logger.info(
        f"AgentDock server starting on {settings.host}:{settings.port}"
    )
    yield

    await task_engine.stop()
    await storage.close()
    logger.info("AgentDock server stopped")


# Override the default lifespan with our custom one
app.router.lifespan_context = lifespan
