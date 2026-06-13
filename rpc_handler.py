"""
RPC 路由分发 — 处理 Web UI 与客户端之间的双向 RPC 调用。

实现规范的 RPC 方法路由，支持：
  - 会话作用域 vs 机器作用域路由
  - 超时控制与错误处理
  - 方法注册与发现
"""

Method categories:
    Session-scoped:
        answer-question, approve-permission, deny-permission,
        abort, stop-session
    Machine-scoped:
        start-invite, get-machine-info, get-agent-settings,
        set-agent-settings, get-labs-settings, set-labs-settings,
        check-path, backfill-history-session, trigger-upgrade,
        checkpoint-list, checkpoint-diff, checkpoint-rollback,
        refresh-enterprise-models
    Server-initiated:
        spawn-session, list-sessions, get-messages, get-stats,
        shutdown-daemon
"""

import asyncio
import logging
import time
import uuid
from typing import Optional

from fastapi import HTTPException

logger = logging.getLogger("agentdock.rpc")


# ─── Session-scoped RPC methods ────────────────────
# These require an active session context (sessionId). The daemon routes
# the request to the specific agent session.

SESSION_RPC_METHODS = frozenset({
    "answer-question",
    "approve-permission",
    "deny-permission",
    "abort",
    "stop-session",
    "switch-mode",
})

# ─── Machine-scoped RPC methods ────────────────────
# These apply to the daemon machine itself, not a specific session.

MACHINE_RPC_METHODS = frozenset({
    "start-invite",
    "get-machine-info",
    "get-agent-settings",
    "set-agent-settings",
    "get-labs-settings",
    "set-labs-settings",
    "check-path",
    "backfill-history-session",
    "trigger-upgrade",
    "checkpoint-list",
    "checkpoint-diff",
    "checkpoint-rollback",
    "refresh-enterprise-models",
})

# ─── Server-initiated RPC methods ──────────────────
# These are called by the server via HTTP, not registered by the daemon.

SERVER_RPC_METHODS = frozenset({
    "spawn-session",
    "list-sessions",
    "get-messages",
    "get-stats",
    "get-team-stats",
    "shutdown-daemon",
})

# Union of all methods the daemon must register
DAEMON_REQUIRED_METHODS = SESSION_RPC_METHODS | MACHINE_RPC_METHODS


class RpcDispatcher:
    """Routes RPC calls between Web UI and Daemon via Socket.IO.

    Architecture::

        Web UI ──HTTP──┬── Server ──socket.io 'rpc-request'──┬── Daemon
        Daemon ──socket.io 'rpc-call'──┬── Server ──HTTP──┬── Web UI

    Each outgoing RPC gets a unique ``call_id`` stored in ``_pending_rpcs``.
    The daemon responds via ``rpc-call`` with the matching ``call_id``.
    """

    def __init__(self, sio, storage, machine_sids, session_owners,
                 connected_daemons, machine_rpc_methods):
        #: python-socketio AsyncServer instance
        self.sio = sio
        #: Storage layer for DB lookups
        self.storage = storage
        #: Mapping of machine_id -> set of connected SIO session IDs
        self.machine_sids = machine_sids
        #: Mapping of session_id -> owning machine_id
        self.session_owners = session_owners
        #: Mapping of sid -> connection metadata
        self.connected_daemons = connected_daemons
        #: Mapping of machine_id -> set of registered RPC method names
        self.machine_rpc_methods = machine_rpc_methods
        #: Pending RPC calls keyed by call_id, each holding an asyncio Future
        self._pending_rpcs: dict[str, asyncio.Future] = {}

    # ─── Dispatch: machine-scoped ─────────────────

    async def call_machine(self, machine_id: str, method: str,
                            params: dict = None, timeout: float = 30.0) -> dict:
        """Send an RPC to a specific daemon *machine_id* and wait for a response.

        Args:
            machine_id: Target daemon machine identifier.
            method: RPC method name.
            params: Optional parameters dict.
            timeout: Maximum seconds to wait for a response.

        Returns:
            The response dict from the daemon.

        Raises:
            HTTPException 503: Machine is not connected.
            HTTPException 504: RPC timed out.
        """
        sids = self.machine_sids.get(machine_id, set())
        if not sids:
            raise HTTPException(status_code=503, detail="machine-not-connected")

        # Generate a unique call ID so the daemon's response can be matched
        call_id = f"rpc_{uuid.uuid4().hex[:16]}"
        future = asyncio.get_event_loop().create_future()
        self._pending_rpcs[call_id] = future

        payload = {
            "id": call_id,
            "method": method,
            "params": params or {},
        }

        logger.info(
            f"RPC dispatch: {method} -> machine={machine_id[:12]} "
            f"call_id={call_id[:12]}"
        )

        # Send the RPC request to all of the machine's socket connections
        for sid in sids:
            await self.sio.emit("rpc-request", payload, to=sid)

        try:
            result = await asyncio.wait_for(future, timeout)
            self._pending_rpcs.pop(call_id, None)
            return result
        except asyncio.TimeoutError:
            self._pending_rpcs.pop(call_id, None)
            logger.warning(
                f"RPC timeout: {method} on {machine_id[:12]} ({timeout}s)"
            )
            raise HTTPException(
                status_code=504, detail=f"rpc-timeout:{method}"
            )

    # ─── Dispatch: session-scoped ─────────────────

    async def call_session(self, session_id: str, method: str,
                            params: dict = None, timeout: float = 30.0) -> dict:
        """Send a session-scoped RPC to the machine owning *session_id*.

        Looks up the owning machine from ``session_owners`` cache, then
        falls back to the database.

        Args:
            session_id: Target session identifier.
            method: RPC method name.
            params: Optional parameters (augmented with ``sessionId``).
            timeout: Maximum seconds to wait.

        Returns:
            The response dict from the daemon.

        Raises:
            HTTPException 404: Session not found or has no owning machine.
        """
        machine_id = self.session_owners.get(session_id)
        if not machine_id:
            # Fall back to DB lookup
            session = await self.storage.get_session(session_id)
            if not session:
                raise HTTPException(status_code=404, detail="session-not-found")
            machine_id = session.get("machine_id", "")
            if not machine_id:
                raise HTTPException(
                    status_code=404, detail="session-no-machine"
                )

        # Augment params with session context so the daemon knows which session
        full_params = dict(params or {})
        full_params["sessionId"] = session_id

        return await self.call_machine(
            machine_id, method, full_params, timeout
        )

    # ─── Handle daemon RPC response ───────────────

    def handle_rpc_result(self, data: dict) -> bool:
        """Called when a daemon sends ``rpc-call``. Routes the result to the
        pending caller via the stored Future.

        Args:
            data: Response dict containing at least ``id``.

        Returns:
            ``True`` if a matching pending call was found and resolved.
        """
        call_id = data.get("id", "")
        if call_id in self._pending_rpcs:
            future = self._pending_rpcs.pop(call_id)
            if not future.done():
                future.set_result(data)
                return True
        return False

    # ─── Cancel stale pending RPCs ────────────────

    def reap_stale_rpcs(self, max_age: float = 60.0):
        """Cancel and remove pending RPCs older than *max_age* seconds.

        Prevents memory leaks from RPCs whose daemon never responded.
        """
        now = time.time()
        stale = [
            cid for cid, f in self._pending_rpcs.items()
            if f.done() or (
                hasattr(f, '_created_at')
                and now - f._created_at > max_age
            )
        ]
        for cid in stale:
            f = self._pending_rpcs.pop(cid, None)
            if f and not f.done():
                f.set_exception(TimeoutError("rpc-reaped"))

    # ─── Find available machine for agent type ────

    async def find_machine_for_agent(
        self,
        agent_type: str = "claude",
        preferred_machine_id: str = "",
    ) -> str:
        """Find a connected machine that supports the given *agent_type*.

        If *preferred_machine_id* is set and connected, returns it.
        Otherwise iterates all registered machines.

        Raises:
            HTTPException 503: No suitable machine is available.
        """
        if preferred_machine_id and preferred_machine_id in self.machine_sids:
            return preferred_machine_id

        machines = await self.storage.list_machines()
        for m in machines:
            m_id = m.get("id", "")
            if m_id in self.machine_sids and self.machine_sids[m_id]:
                agents = m.get("available_agents", [])
                if not agents or agent_type in agents:
                    return m_id

        raise HTTPException(status_code=503, detail="no-available-machine")

    # ─── Spawn session helper ─────────────────────

    async def spawn_session(
        self,
        params: dict,
        session_id_override: str = "",
    ) -> dict:
        """Spawn a new agent session via RPC.

        Workflow:
          1. Finds a machine that can handle the agent type.
          2. Reserves a session ID and stores ownership.
          3. Sends ``spawn-session`` RPC to the daemon.
          4. Returns the reserved session ID so the caller can listen for
             ``session-create``.

        Args:
            params: Spawn parameters including ``agentType``, ``machineId``, etc.
            session_id_override: Optional pre-determined session ID.

        Returns:
            Dict with ``ok``, ``sessionId``, ``daemonResult``, ``machineId``.
        """
        agent_type = params.get("agentType", "claude")
        machine_id = params.get("machineId", "")

        # Find the right machine for this agent type
        machine_id = await self.find_machine_for_agent(agent_type, machine_id)

        # Reserve a session ID — don't create the DB record yet (the daemon
        # does it via the ``session-create`` Socket.IO event).
        # Just store the ownership mapping so ``on_session_create`` knows
        # which machine owns it.
        server_session_id = session_id_override or f"s_{uuid.uuid4().hex[:16]}"
        params["serverSessionId"] = server_session_id
        self.session_owners[server_session_id] = machine_id

        # Send spawn-session RPC to the daemon
        result = await self.call_machine(
            machine_id, "spawn-session", params, timeout=60.0
        )

        return {
            "ok": True,
            "sessionId": server_session_id,
            "daemonResult": result,
            "machineId": machine_id,
        }

    # ─── Session-scoped RPC helpers ───────────────

    async def answer_question(self, session_id: str, request_id: str, text: str):
        """Answer a question posed by the agent in the given session.

        Delegates to the ``answer-question`` RPC method.
        """
        return await self.call_session(
            session_id, "answer-question",
            {"requestId": request_id, "text": text},
        )

    async def approve_permission(
        self,
        session_id: str,
        request_id: str,
        action: str = "approve",
        reason: str = "",
    ):
        """Approve a permission request from the agent."""
        params = {"requestId": request_id, "action": action}
        if reason:
            params["reason"] = reason
        return await self.call_session(
            session_id, "approve-permission", params,
        )

    async def deny_permission(
        self,
        session_id: str,
        request_id: str,
        reason: str = "",
    ):
        """Deny a permission request from the agent."""
        params = {"requestId": request_id, "action": "deny"}
        if reason:
            params["reason"] = reason
        return await self.call_session(
            session_id, "deny-permission", params,
        )

    async def abort_session(self, session_id: str):
        """Abort the current operation in a session."""
        return await self.call_session(session_id, "abort")

    async def stop_session(self, session_id: str):
        """Stop a session completely and clean up its DB record."""
        result = await self.call_session(session_id, "stop-session")
        await self.storage.end_session(session_id)
        self.session_owners.pop(session_id, None)
        return result

    # ─── Machine-scoped RPC helpers ───────────────

    async def get_machine_info(self, machine_id: str):
        """Get detailed machine info from the daemon."""
        return await self.call_machine(machine_id, "get-machine-info")

    async def get_agent_settings(self, machine_id: str):
        """Get the daemon's current agent settings."""
        return await self.call_machine(machine_id, "get-agent-settings")

    async def set_agent_settings(self, machine_id: str, settings: dict):
        """Update the daemon's agent settings."""
        return await self.call_machine(
            machine_id, "set-agent-settings", {"settings": settings}
        )

    async def check_path(self, machine_id: str, cwd: str):
        """Check if a directory path exists on the daemon machine."""
        return await self.call_machine(
            machine_id, "check-path", {"cwd": cwd}
        )

    async def trigger_upgrade(self, machine_id: str):
        """Trigger a daemon upgrade."""
        return await self.call_machine(machine_id, "trigger-upgrade")

    async def switch_mode(self, machine_id: str, session_id: str, mode: str):
        """Switch the permission mode for an active session."""
        return await self.call_machine(
            machine_id, "switch-mode",
            {"sessionId": session_id, "mode": mode},
        )

    async def get_session_stats(
        self,
        machine_id: str,
        session_id: str = None,
    ):
        """Get usage statistics from the daemon, optionally for a specific session."""
        params = {}
        if session_id:
            params["sessionId"] = session_id
        return await self.call_machine(machine_id, "get-stats", params)
