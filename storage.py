"""
SQLite 存储层 — 持久化管理。

数据表：
    pairing_requests   — 配对状态机 (pending -> exchange -> authorized)
    devices            — 已配对设备
    auth_tokens        — 认证令牌
    sessions           — AI Agent 会话记录
    scheduled_tasks    — 定时任务
    usage_stats        — 用量统计
"""
    messages           — Encrypted session envelopes (end-to-end encrypted)
    auth_tokens        — Issued authentication tokens
    stats_events       — Telemetry and usage events
    history_sessions   — Discovered Claude CLI history sessions
"""

import json
import secrets
import time
import uuid
import os
from collections import defaultdict
from datetime import datetime
from typing import Optional
import aiosqlite

from config import settings


class Storage:
    """SQLite-backed persistence layer for all server data.

    Wraps ``aiosqlite`` with async method-based access.  All tables are
    created on first connect via ``_create_tables()``.
    """

    def __init__(self, db_path: str = None):
        #: Path to the SQLite database file
        self.db_path = db_path or settings.db_path
        #: Underlying aiosqlite connection (None until :meth:`connect` is called)
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        """Open the SQLite database and create tables if they don't exist."""
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        """Close the SQLite connection."""
        if self._conn:
            await self._conn.close()

    async def _create_tables(self):
        """Create all required tables and indexes if they don't already exist."""
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS pairing_requests (
                public_key TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'pending',
                pin TEXT,
                label TEXT,
                pairing_type TEXT DEFAULT 'join',
                device_public_key TEXT,
                encrypted_payload TEXT,
                token TEXT,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS machines (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT 'linux',
                arch TEXT DEFAULT '',
                display_name TEXT DEFAULT '',
                daemon_version TEXT DEFAULT '',
                active INTEGER NOT NULL DEFAULT 0,
                active_at REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                available_agents TEXT DEFAULT '[]',
                agent_versions TEXT DEFAULT '{}',
                supported_methods TEXT DEFAULT '[]',
                disconnect_reason TEXT DEFAULT NULL,
                last_heartbeat REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                machine_id TEXT NOT NULL,
                tag TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                metadata TEXT DEFAULT '{}',
                wrapped_dek TEXT DEFAULT NULL,
                source TEXT DEFAULT 'managed',
                claude_session_id TEXT DEFAULT NULL,
                project_path TEXT DEFAULT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                ended_at REAL DEFAULT NULL,
                FOREIGN KEY (machine_id) REFERENCES machines(id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                local_id TEXT,
                content_type TEXT NOT NULL DEFAULT 'encrypted',
                content_data TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (session_id, seq)
            );

            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                machine_id TEXT,
                public_key TEXT,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, seq);
            CREATE INDEX IF NOT EXISTS idx_sessions_machine ON sessions(machine_id);
            CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS stats_events (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                machine_id TEXT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS history_sessions (
                id TEXT PRIMARY KEY,
                machine_id TEXT NOT NULL,
                claude_session_id TEXT,
                source TEXT NOT NULL DEFAULT 'scanner',
                session_data TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_stats_session ON stats_events(session_id);
        """)
        await self._conn.commit()

    # ─── Pairing ─────────────────────────────────────

    async def create_pairing_request(
        self,
        public_key: str,
        pin: str,
        label: Optional[str] = None,
        pairing_type: str = "join",
    ) -> dict:
        """Create a new pairing request or replace an existing one for *public_key*.

        Args:
            public_key: Base64-encoded public key of the requesting device.
            pin: Human-readable PIN for the pairing flow.
            label: Optional human-readable device label.
            pairing_type: ``"join"`` (new device) or ``"invite"``.

        Returns:
            The row dict as stored.
        """
        now = time.time()
        row = {
            "public_key": public_key,
            "state": "pending",
            "pin": pin,
            "label": label or "",
            "pairing_type": pairing_type,
            "created_at": now,
            "expires_at": now + settings.pairing_pin_ttl,
        }
        await self._conn.execute(
            """INSERT OR REPLACE INTO pairing_requests
               (public_key, state, pin, label, pairing_type, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (row["public_key"], row["state"], row["pin"], row["label"],
             row["pairing_type"], row["created_at"], row["expires_at"]),
        )
        await self._conn.commit()
        return row

    async def get_pairing_by_pin(self, pin: str) -> Optional[dict]:
        """Find a non-expired pairing request by its *pin*.

        Returns the most recent match, or ``None``.
        """
        now = time.time()
        cursor = await self._conn.execute(
            "SELECT * FROM pairing_requests WHERE pin = ? AND expires_at > ? "
            "ORDER BY created_at DESC",
            (pin, now),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_pairing_request(self, public_key: str) -> Optional[dict]:
        """Get a pairing request by its *public_key*.

        Returns the row dict, or ``None``.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM pairing_requests WHERE public_key = ?",
            (public_key,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def respond_pairing(
        self,
        public_key: str,
        encrypted_payload: str,
    ) -> Optional[str]:
        """Transition a pending pairing to authorized with an *encrypted_payload*.

        This is called by the Web UI after the user confirms pairing.

        Args:
            public_key: The device's public key.
            encrypted_payload: Encrypted confirmation payload.

        Returns:
            The generated auth token string, or ``None`` if the request
            wasn't found or was expired.
        """
        now = time.time()
        cursor = await self._conn.execute(
            "SELECT * FROM pairing_requests WHERE public_key = ? AND state = 'pending'",
            (public_key,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        row = dict(row)
        if now > row["expires_at"]:
            await self._set_pairing_state(public_key, "expired")
            return None

        # Generate machine ID and token atomically
        token = "ad_" + secrets.token_hex(32)
        machine_id = f"m_{uuid.uuid4().hex[:12]}"
        await self.create_auth_token(
            token, machine_id=machine_id, public_key=public_key
        )
        await self._conn.execute(
            "UPDATE pairing_requests SET state='authorized', "
            "encrypted_payload=?, token=? WHERE public_key=?",
            (encrypted_payload, token, public_key),
        )
        await self._conn.commit()
        return token

    async def authorize_pairing(self, public_key: str, token: str) -> bool:
        """Authorize a pairing by setting its state to ``authorized`` with a *token*."""
        await self._conn.execute(
            "UPDATE pairing_requests SET state = 'authorized', token = ? "
            "WHERE public_key = ?",
            (token, public_key),
        )
        await self._conn.commit()
        return True

    async def expire_pairing(self, public_key: str):
        """Mark a pairing request as expired."""
        await self._set_pairing_state(public_key, "expired")

    async def expire_stale_pairings(self):
        """Bulk-expire all pending pairing requests past their TTL."""
        now = time.time()
        await self._conn.execute(
            "UPDATE pairing_requests SET state = 'expired' "
            "WHERE state = 'pending' AND expires_at < ?",
            (now,),
        )
        await self._conn.commit()

    async def _set_pairing_state(self, public_key: str, state: str):
        """Update the state column of a single pairing request."""
        await self._conn.execute(
            "UPDATE pairing_requests SET state = ? WHERE public_key = ?",
            (state, public_key),
        )
        await self._conn.commit()

    # ─── Machines ────────────────────────────────────

    async def register_machine(
        self,
        machine_id: str,
        hostname: str = "",
        platform: str = "linux",
        arch: str = "",
        available_agents: list = None,
    ) -> dict:
        """Register or re-register a daemon machine.

        If the machine already exists its metadata is updated; otherwise a
        new row is inserted.

        Returns:
            The current machine record.
        """
        now = time.time()
        agents_json = json.dumps(available_agents or [])
        existing = await self.get_machine(machine_id)
        if existing:
            await self._conn.execute(
                """UPDATE machines SET hostname=?, platform=?, arch=?, active=1,
                   active_at=?, last_heartbeat=?, available_agents=?
                   WHERE id=?""",
                (hostname, platform, arch, now, now, agents_json, machine_id),
            )
        else:
            await self._conn.execute(
                """INSERT INTO machines
                   (id, hostname, platform, arch, active, active_at,
                    created_at, last_heartbeat, available_agents)
                   VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                (machine_id, hostname, platform, arch,
                 now, now, now, agents_json),
            )
        await self._conn.commit()
        return await self.get_machine(machine_id)

    async def get_machine(self, machine_id: str) -> Optional[dict]:
        """Get a machine record by *machine_id*.

        JSON fields (``available_agents``, ``agent_versions``,
        ``supported_methods``) are automatically deserialized.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM machines WHERE id = ?", (machine_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        d = dict(row)
        # Deserialize JSON-encoded fields
        for field in ("available_agents", "agent_versions", "supported_methods"):
            if isinstance(d.get(field), str):
                d[field] = json.loads(d[field])
        return d

    async def get_machine_by_public_key(self, public_key_b64: str) -> Optional[dict]:
        """Find a machine by its paired public key through the auth_tokens table."""
        cursor = await self._conn.execute(
            "SELECT * FROM auth_tokens WHERE public_key=? "
            "ORDER BY created_at DESC LIMIT 1",
            (public_key_b64,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        d = dict(row)
        machine_id = d.get("machine_id", "")
        if machine_id:
            return await self.get_machine(machine_id)
        return None

    async def heartbeat_machine(self, machine_id: str):
        """Update a machine's ``last_heartbeat`` and ``active_at`` timestamps."""
        now = time.time()
        await self._conn.execute(
            "UPDATE machines SET active=1, active_at=?, last_heartbeat=? WHERE id=?",
            (now, now, machine_id),
        )
        await self._conn.commit()

    async def count_connected_machines(self) -> int:
        """Return the number of machines currently marked active."""
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM machines WHERE active=1"
        )
        row = await cursor.fetchone()
        return row[0] if row else 0

    async def disconnect_machine(self, machine_id: str, reason: str = "normal"):
        """Mark a machine as disconnected and record the *reason*."""
        await self._conn.execute(
            "UPDATE machines SET active=0, disconnect_reason=? WHERE id=?",
            (reason, machine_id),
        )
        await self._conn.commit()

    async def list_machines(self) -> list[dict]:
        """List all registered machines, newest first.

        JSON fields are automatically deserialized.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM machines ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for field in ("available_agents", "agent_versions", "supported_methods"):
                if isinstance(d.get(field), str):
                    d[field] = json.loads(d[field])
            result.append(d)
        return result

    # ─── Sessions ────────────────────────────────────

    async def create_session(
        self,
        session_id: str,
        machine_id: str,
        tag: str = "",
        metadata: dict = None,
        wrapped_dek: str = None,
        source: str = "managed",
        claude_session_id: str = None,
        project_path: str = None,
    ) -> dict:
        """Create a new session record.

        Args:
            session_id: Unique session identifier.
            machine_id: Owning machine identifier.
            tag: Optional human-readable tag.
            metadata: Optional metadata dict (e.g., ``cwd``, ``summary``).
            wrapped_dek: Base64-encoded wrapped DEK for E2E encryption.
            source: Session origin (``"managed"``, ``"scanner"``, etc.).
            claude_session_id: Corresponding Claude CLI session ID.
            project_path: Project root path on the machine.

        Returns:
            The created session record.
        """
        now = time.time()
        await self._conn.execute(
            """INSERT INTO sessions
               (id, machine_id, tag, status, metadata, wrapped_dek, source,
                claude_session_id, project_path, created_at, updated_at)
               VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, machine_id, tag, json.dumps(metadata or {}),
             wrapped_dek, source, claude_session_id, project_path, now, now),
        )
        await self._conn.commit()
        return await self.get_session(session_id)

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Get a session by its ID.

        The ``metadata`` JSON field is deserialized automatically.
        """
        cursor = await self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        d = dict(row)
        if isinstance(d.get("metadata"), str):
            d["metadata"] = json.loads(d["metadata"])
        return d

    async def update_session_metadata(
        self,
        session_id: str,
        metadata: dict,
        expected_version: int = None,
    ) -> bool:
        """Update a session's metadata.

        Note: Optimistic concurrency via *expected_version* is currently
        not implemented (simplified for now).

        Returns:
            ``False`` if the session doesn't exist.
        """
        existing = await self.get_session(session_id)
        if existing is None:
            return False
        await self._conn.execute(
            "UPDATE sessions SET metadata=?, updated_at=? WHERE id=?",
            (json.dumps(metadata), time.time(), session_id),
        )
        await self._conn.commit()
        return True

    async def end_session(self, session_id: str, summary: dict = None):
        """Mark a session as ended and optionally attach a *summary*."""
        now = time.time()
        meta = None
        existing = await self.get_session(session_id)
        if existing and summary:
            meta = existing["metadata"]
            meta["summary"] = summary
        await self._conn.execute(
            "UPDATE sessions SET status='ended', ended_at=?, updated_at=?, "
            "metadata=? WHERE id=?",
            (now, now, json.dumps(meta or existing.get("metadata", {})),
             session_id),
        )
        await self._conn.commit()

    async def list_sessions(
        self,
        machine_id: str = None,
        status: str = None,
    ) -> list[dict]:
        """List sessions, optionally filtered by *machine_id* and/or *status*.

        Results are ordered newest first.
        """
        query = "SELECT * FROM sessions"
        params = []
        conds = []
        if machine_id:
            conds.append("machine_id = ?")
            params.append(machine_id)
        if status:
            conds.append("status = ?")
            params.append(status)
        if conds:
            query += " WHERE " + " AND ".join(conds)
        query += " ORDER BY created_at DESC"
        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            if isinstance(d.get("metadata"), str):
                d["metadata"] = json.loads(d["metadata"])
            result.append(d)
        return result

    async def provision_session_dek(self, session_id: str, wrapped_dek: str):
        """Store the wrapped DEK for a session (set after session creation)."""
        await self._conn.execute(
            "UPDATE sessions SET wrapped_dek=? WHERE id=?",
            (wrapped_dek, session_id),
        )
        await self._conn.commit()

    # ─── Messages ────────────────────────────────────

    async def store_message(
        self,
        session_id: str,
        message_id: str,
        content: dict,
        local_id: str = None,
    ) -> dict:
        """Persist an encrypted message envelope for a session.

        Each message gets an auto-incrementing ``seq`` number scoped to
        the session.

        Args:
            session_id: Owning session.
            message_id: Client-provided message ID.
            content: Dict with ``t`` (type) and ``c`` (ciphertext) keys.
            local_id: Optional client-local identifier.

        Returns:
            The stored message record dict.
        """
        now = time.time()
        # Compute the next sequence number for this session
        cursor = await self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE session_id = ?",
            (session_id,),
        )
        seq = (await cursor.fetchone())[0]

        await self._conn.execute(
            """INSERT INTO messages
               (id, session_id, seq, local_id, content_type, content_data,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (message_id, session_id, seq, local_id,
             content.get("t", "encrypted"),
             content.get("c", ""), now, now),
        )
        await self._conn.commit()

        return {
            "id": message_id,
            "seq": seq,
            "localId": local_id,
            "content": content,
            "createdAt": now,
            "updatedAt": now,
        }

    async def get_messages(
        self,
        session_id: str,
        from_seq: int = None,
        limit: int = 50,
    ) -> dict:
        """Retrieve paginated messages for a session starting from *from_seq*.

        Returns a dict with ``messages``, ``total`` count, and ``hasMore`` flag.
        An extra record is fetched (``limit + 1``) to detect the ``has_more`` boundary.
        """
        if from_seq is None:
            from_seq = 0
        cursor = await self._conn.execute(
            """SELECT * FROM messages
               WHERE session_id = ? AND seq > ?
               ORDER BY seq ASC LIMIT ?""",
            (session_id, from_seq, limit + 1),
        )
        rows = await cursor.fetchall()
        has_more = len(rows) > limit
        messages = []
        for row in rows[:limit]:
            d = dict(row)
            messages.append({
                "id": d["id"],
                "seq": d["seq"],
                "localId": d["local_id"],
                "content": {"t": d["content_type"], "c": d["content_data"]},
                "createdAt": d["created_at"],
                "updatedAt": d["updated_at"],
            })

        # Total message count for the session
        cursor2 = await self._conn.execute(
            "SELECT COUNT(*) FROM messages WHERE session_id = ?",
            (session_id,),
        )
        total = (await cursor2.fetchone())[0]

        return {
            "messages": messages,
            "total": total,
            "hasMore": has_more,
        }

    # ─── Auth Tokens ─────────────────────────────────

    async def create_auth_token(
        self,
        token: str,
        machine_id: str = None,
        public_key: str = None,
        ttl: int = None,
    ) -> dict:
        """Create a new auth token with an optional *ttl* (default: from settings).

        Returns:
            The token record dict.
        """
        ttl = ttl or settings.token_ttl
        now = time.time()
        await self._conn.execute(
            "INSERT INTO auth_tokens (token, machine_id, public_key, "
            "created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token, machine_id, public_key, now, now + ttl),
        )
        await self._conn.commit()
        return {
            "token": token,
            "machine_id": machine_id,
            "created_at": now,
            "expires_at": now + ttl,
        }

    async def validate_token(self, token: str) -> Optional[dict]:
        """Check if a token is valid (exists and not expired).

        Returns the token record or ``None``.
        """
        now = time.time()
        cursor = await self._conn.execute(
            "SELECT * FROM auth_tokens WHERE token = ? AND expires_at > ?",
            (token, now),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def revoke_token(self, token: str):
        """Delete a token, effectively revoking it."""
        await self._conn.execute(
            "DELETE FROM auth_tokens WHERE token = ?", (token,)
        )
        await self._conn.commit()

    async def clean_expired_tokens(self):
        """Purge all tokens past their expiration time."""
        await self._conn.execute(
            "DELETE FROM auth_tokens WHERE expires_at < ?",
            (time.time(),),
        )
        await self._conn.commit()

    # ─── Stats / Usage ───────────────────────────────

    async def record_usage(
        self,
        session_id: str,
        machine_id: str,
        event_type: str,
        payload: dict = None,
    ):
        """Record a telemetry / usage event.

        Args:
            session_id: Session this event belongs to.
            machine_id: Machine that generated the event.
            event_type: Event category (e.g. ``"turn-end"``, ``"telemetry"``).
            payload: Event-specific data (e.g. token counts).
        """
        event_id = f"evt_{uuid.uuid4().hex[:16]}"
        now = time.time()
        await self._conn.execute(
            """INSERT INTO stats_events
               (id, session_id, machine_id, event_type, payload, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event_id, session_id, machine_id, event_type,
             json.dumps(payload or {}), now),
        )
        await self._conn.commit()

    async def get_session_stats(self, session_id: str) -> dict:
        """Aggregate token usage statistics for a session from its ``turn-end`` events.

        Returns:
            Dict with ``inputTokens``, ``outputTokens``, ``cacheReadTokens``,
            and ``cacheWriteTokens`` totals.
        """
        cursor = await self._conn.execute(
            "SELECT event_type, payload, created_at FROM stats_events "
            "WHERE session_id=? ORDER BY created_at",
            (session_id,),
        )
        rows = await cursor.fetchall()
        input_tokens = 0
        output_tokens = 0
        cache_read = 0
        cache_write = 0
        for row in rows:
            d = dict(row)
            if d["event_type"] == "turn-end":
                pl = json.loads(d["payload"])
                usage = pl.get("usage", {})
                input_tokens += usage.get("inputTokens", 0)
                output_tokens += usage.get("outputTokens", 0)
                cache_read += usage.get("cacheReadTokens", 0)
                cache_write += usage.get("cacheWriteTokens", 0)
        return {
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "cacheReadTokens": cache_read,
            "cacheWriteTokens": cache_write,
        }

    async def get_machine_stats(self, machine_id: str) -> dict:
        """Get total and active session counts for a machine."""
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE machine_id=?",
            (machine_id,),
        )
        total_sessions = (await cursor.fetchone())[0]
        cursor2 = await self._conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE machine_id=? AND status='active'",
            (machine_id,),
        )
        active_sessions = (await cursor2.fetchone())[0]
        return {
            "totalSessions": total_sessions,
            "activeSessions": active_sessions,
        }

    async def record_turn_usage(
        self,
        session_id: str,
        machine_id: str,
        usage: dict,
        model: str = None,
    ):
        """Convenience method to record a ``turn-end`` usage event."""
        payload = {"usage": usage}
        if model:
            payload["model"] = model
        await self.record_usage(session_id, machine_id, "turn-end", payload)

    # ─── Stats Aggregation (matching wire/stats.d.ts) ──

    async def get_claude_stats_data(self, machine_id: str = None) -> dict:
        """Build a ``ClaudeStatsData`` dict from recorded usage events.

        Aggregates sessions, messages, daily activity, model-level token
        usage, and longest session info.
        ``stats.d.ts``.

        Args:
            machine_id: Optional filter — omit for all machines.

        Returns:
            Dict with ``version``, ``totalSessions``, ``totalMessages``,
            ``dailyActivity``, ``dailyModelTokens``, ``modelUsage``,
            ``longestSession``, ``firstSessionDate``, ``hourCounts``.
        """
        sessions = await self.list_sessions(machine_id, None)
        total_sessions = len(sessions)
        total_messages = 0
        daily_activity: dict[str, dict] = {}
        daily_model_tokens: dict[str, dict] = {}
        model_usage: dict[str, dict] = {}
        hour_counts = defaultdict(int)
        longest_session_info = None
        first_session_date = None

        for s in sessions:
            sid = s["id"]
            msg_cursor = await self._conn.execute(
                "SELECT COUNT(*) FROM messages WHERE session_id=?", (sid,)
            )
            msg_count = (await msg_cursor.fetchone())[0]
            total_messages += msg_count

            # Per-day session activity
            created_dt = datetime.fromtimestamp(s["created_at"])
            day_str = created_dt.strftime("%Y-%m-%d")
            if day_str not in daily_activity:
                daily_activity[day_str] = {
                    "date": day_str,
                    "messageCount": 0,
                    "sessionCount": 0,
                    "toolCallCount": 0,
                }
            daily_activity[day_str]["sessionCount"] += 1
            daily_activity[day_str]["messageCount"] += msg_count

            # Per-hour activity histogram
            hour_key = created_dt.strftime("%H:00")
            hour_counts[hour_key] += 1

            if first_session_date is None or s["created_at"] < first_session_date:
                first_session_date = s["created_at"]

            # Track longest session by wall-clock duration
            if s.get("ended_at") and s["ended_at"] > s["created_at"]:
                duration = s["ended_at"] - s["created_at"]
                if (longest_session_info is None
                        or duration > longest_session_info.get("duration", 0)):
                    longest_session_info = {
                        "sessionId": sid,
                        "duration": duration,
                        "messageCount": msg_count,
                        "timestamp": datetime.fromtimestamp(
                            s["created_at"]
                        ).isoformat(),
                    }

        # Aggregate token usage from stats_events
        cursor = await self._conn.execute(
            "SELECT event_type, payload, created_at FROM stats_events"
            + (" WHERE machine_id=?" if machine_id else ""),
            (machine_id,) if machine_id else (),
        )
        rows = await cursor.fetchall()
        for row in rows:
            d = dict(row)
            if d["event_type"] == "turn-end":
                pl = json.loads(d["payload"])
                usage = pl.get("usage", {})
                model = pl.get("model", "unknown")
                if model not in model_usage:
                    model_usage[model] = {
                        "inputTokens": 0,
                        "outputTokens": 0,
                        "cacheReadInputTokens": 0,
                        "cacheCreationInputTokens": 0,
                    }
                mu = model_usage[model]
                mu["inputTokens"] += usage.get("inputTokens", 0)
                mu["outputTokens"] += usage.get("outputTokens", 0)
                mu["cacheReadInputTokens"] += usage.get(
                    "cacheReadInputTokens", 0
                )
                mu["cacheCreationInputTokens"] += usage.get(
                    "cacheCreationInputTokens", 0
                )

                # Per-day model-level token counts
                ts = d["created_at"]
                day_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                if day_str not in daily_model_tokens:
                    daily_model_tokens[day_str] = {
                        "date": day_str,
                        "tokensByModel": {},
                    }
                tokens_total = (
                    usage.get("inputTokens", 0)
                    + usage.get("outputTokens", 0)
                )
                dm = daily_model_tokens[day_str]
                dm["tokensByModel"][model] = (
                    dm["tokensByModel"].get(model, 0) + tokens_total
                )

        return {
            "version": 1,
            "totalSessions": total_sessions,
            "totalMessages": total_messages,
            "dailyActivity": sorted(
                daily_activity.values(), key=lambda x: x["date"]
            ),
            "dailyModelTokens": sorted(
                daily_model_tokens.values(), key=lambda x: x["date"]
            ),
            "modelUsage": model_usage,
            "longestSession": longest_session_info,
            "firstSessionDate": (
                datetime.fromtimestamp(first_session_date).isoformat()
                if first_session_date else None
            ),
            "hourCounts": dict(hour_counts),
        }

    async def get_project_summaries(self) -> list[dict]:
        """Build project summaries from session metadata paths.

        Returns:
            List of dicts with ``projectPath``, ``sessionCount``,
            ``subagentSessionCount``, ``totalTokens``.
        """
        sessions = await self.list_sessions()
        projects = {}
        for s in sessions:
            meta = s.get("metadata", {})
            if isinstance(meta, str):
                meta = json.loads(meta)
            project_path = (
                meta.get("cwd", "/") if isinstance(meta, dict) else "/"
            )
            if project_path not in projects:
                projects[project_path] = {
                    "projectPath": project_path,
                    "sessionCount": 0,
                    "subagentSessionCount": 0,
                    "totalTokens": 0,
                }
            projects[project_path]["sessionCount"] += 1
        return list(projects.values())

    async def get_stats_overview(self) -> dict:
        """Build the full StatsOverview matching wire/stats.d.ts ``StatsOverviewSchema``.

        Combines Claude stats, project summaries, and cost estimates into a
        single response.
        """
        claude_stats = await self.get_claude_stats_data()
        projects = await self.get_project_summaries()
        return {
            "stats": claude_stats,
            "projects": projects,
            "costEstimates": {},
            "totalEstimatedCost": 0,
            "agentType": "claude",
            "agentTypeUsage": [
                {
                    "agentType": "claude",
                    "totalSessions": claude_stats["totalSessions"],
                    "totalMessages": claude_stats["totalMessages"],
                    "totalTokens": sum(
                        m["inputTokens"] + m["outputTokens"]
                        for m in claude_stats["modelUsage"].values()
                    ),
                    "projects": projects,
                    "stats": claude_stats,
                },
            ],
        }

    # ─── History Sync ────────────────────────────────

    async def get_known_claude_sessions(self, machine_id: str) -> list[dict]:
        """Get all known Claude CLI history sessions for a *machine_id*."""
        cursor = await self._conn.execute(
            "SELECT * FROM history_sessions WHERE machine_id=? "
            "ORDER BY created_at DESC",
            (machine_id,),
        )
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            if isinstance(d.get("session_data"), str):
                d["session_data"] = json.loads(d["session_data"])
            results.append(d)
        return results

    async def register_history_session(
        self,
        machine_id: str,
        claude_session_id: str,
        session_data: dict = None,
    ):
        """Register a discovered Claude CLI history session.

        Returns:
            The generated history session ID.
        """
        now = time.time()
        session_id = f"h_{uuid.uuid4().hex[:16]}"
        await self._conn.execute(
            """INSERT OR REPLACE INTO history_sessions
               (id, machine_id, claude_session_id, source, session_data,
                status, created_at)
               VALUES (?, ?, ?, 'scanner', ?, 'pending', ?)""",
            (session_id, machine_id, claude_session_id,
             json.dumps(session_data or {}), now),
        )
        await self._conn.commit()
        return session_id
