"""
定时任务引擎 — 基于 Cron 的计划任务管理。

支持：
  - 创建/更新/删除定时任务
  - Cron 表达式调度
  - 任务状态跟踪
  - 历史记录查询
"""
    - ScheduledTaskSummary, TaskExecution
    - RetryPolicy, MissedRunPolicy, ScheduledSpawnParams
    - Auto-disable via circuit breaker (consecutive failures)

Storage:
    scheduled_tasks  — Task definitions (schedule, spawn params, state)
    task_executions  — Execution history (success/fail/skip)
"""

import asyncio
import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from storage import Storage

logger = logging.getLogger("agentdock.scheduler")

# ─── Cron expression parser (subset) ───────────────
# Supported: *, N, N-M, N/K, comma-separated combinations

_DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}


def _parse_cron_field(field: str, lo: int, hi: int) -> set[int]:
    """Parse a single cron field (*minute*, *hour*, *dom*, *month*, *dow*).

    Supports ``*``, exact values, ranges (``N-M``), steps (``*/K``, ``N-M/K``),
    and comma-separated combinations.

    Returns:
        A set of matching integer values within ``[lo, hi]``.
    """
    result: set[int] = set()
    for part in field.split(","):
        part = part.strip().lower()
        if part == "*":
            return set(range(lo, hi + 1))
        if "/" in part:
            base, step = part.split("/", 1)
            step = int(step)
            base_lo, base_hi = lo, hi
            if base != "*":
                if "-" in base:
                    base_lo, base_hi = (int(x) for x in base.split("-", 1))
                else:
                    base_lo = int(base)
                    base_hi = hi
            result.update(range(base_lo, base_hi + 1, step))
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            result.update(range(a, b + 1))
        else:
            result.add(int(part))
    return result


def parse_cron(
    expr: str,
) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    """Parse a 5-field cron expression.

    Args:
        expr: Standard cron expression like ``"*/5 * * * *"``.

    Returns:
        Tuple of ``(minutes, hours, dom, months, dow)`` as sets of matching values.

    Raises:
        ValueError: If the expression doesn't have exactly 5 fields.
    """
    fields = expr.strip().split()
    if len(fields) != 5:
        raise ValueError(f"Invalid cron expression: {expr!r}")
    return (
        _parse_cron_field(fields[0], 0, 59),
        _parse_cron_field(fields[1], 0, 23),
        _parse_cron_field(fields[2], 1, 31),
        _parse_cron_field(fields[3], 1, 12),
        _parse_cron_field(fields[4], 0, 6),
    )


def cron_matches(expr: str, dt: datetime) -> bool:
    """Check whether a cron expression matches the given datetime.

    All five dimensions must match for the expression to match.
    """
    minutes, hours, dom, months, dow = parse_cron(expr)
    if dt.minute not in minutes:
        return False
    if dt.hour not in hours:
        return False
    if dt.day not in dom:
        return False
    if dt.month not in months:
        return False
    if dt.weekday() not in dow:
        return False
    return True


def next_cron_match(expr: str, after: float) -> Optional[float]:
    """Find the next timestamp matching a cron expression after *after*.

    Searches forward minute-by-minute up to ~1 year.

    Args:
        expr: Cron expression string.
        after: Unix timestamp to search from.

    Returns:
        The next matching Unix timestamp, or ``None`` if no match is found
        within the search horizon.
    """
    import calendar

    dt = (
        datetime.fromtimestamp(after, tz=timezone.utc)
        .replace(second=0, microsecond=0)
    )
    # Search up to ~1 year of minutes
    for _ in range(525600):
        if dt.timestamp() > after and cron_matches(expr, dt):
            return dt.timestamp()
        # Advance by one minute, handling all boundary conditions
        if dt.minute < 59:
            dt = dt.replace(minute=dt.minute + 1)
        else:
            # Roll to the next hour
            dt = dt.replace(
                minute=0,
                hour=dt.hour + 1 if dt.hour < 23 else 0,
            )
            if dt.hour == 0:
                # Roll to the next day
                _, days_in_month = calendar.monthrange(dt.year, dt.month)
                if dt.day < days_in_month:
                    dt = dt.replace(day=dt.day + 1)
                else:
                    dt = dt.replace(day=1, month=dt.month + 1 if dt.month < 12 else 1)
                    if dt.month == 1:
                        dt = dt.replace(year=dt.year + 1)
    return None


# ─── Task Engine ────────────────────────────────────


class TaskEngine:
    """Scheduled task engine that runs cron checks, spawns agent sessions,
    and tracks execution history.

    Args:
        storage: The :class:`Storage` instance for persistence.
        dispatch_spawn_fn: Async callable ``(machine_id, spawn_params) -> dict``
            used to actually trigger session spawns on daemon machines.
    """

    def __init__(self, storage: Storage, dispatch_spawn_fn=None):
        self.storage = storage
        self.dispatch_spawn = dispatch_spawn_fn
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def init_db(self):
        """Create ``scheduled_tasks`` and ``task_executions`` tables if needed."""
        storage = self.storage
        await storage._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                schedule TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                machine_id TEXT,
                spawn_params TEXT NOT NULL DEFAULT '{}',
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                disabled_reason TEXT,
                last_run_at REAL,
                last_execution_status TEXT,
                last_execution_summary TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS task_executions (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES scheduled_tasks(id),
                session_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                trigger TEXT NOT NULL DEFAULT 'scheduled',
                scheduled_at REAL NOT NULL,
                started_at REAL,
                completed_at REAL,
                error TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                summary TEXT,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_task_exec_task
                ON task_executions(task_id, created_at);
        """)

    # ─── CRUD ────────────────────────────────────────

    async def create_task(
        self,
        name: str,
        schedule: str,
        spawn_params: dict,
        enabled: bool = True,
        machine_id: str = "",
    ) -> dict:
        """Create a new scheduled task definition.

        Returns:
            The created task dict.
        """
        now = time.time()
        task_id = f"t_{uuid.uuid4().hex[:16]}"
        await self.storage._conn.execute(
            """INSERT INTO scheduled_tasks
               (id, name, schedule, enabled, machine_id, spawn_params,
                consecutive_failures, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)""",
            (task_id, name, schedule, 1 if enabled else 0, machine_id or None,
             json.dumps(spawn_params), now, now),
        )
        await self.storage._conn.commit()
        return await self.get_task(task_id)

    async def update_task(self, task_id: str, updates: dict) -> Optional[dict]:
        """Update fields on an existing task.

        Supported fields: ``name``, ``schedule``, ``machine_id``, ``enabled``,
        ``disabled_reason``, ``spawn_params``, ``consecutive_failures``.

        Returns:
            The updated task dict, or ``None`` if the task doesn't exist.
        """
        existing = await self.get_task(task_id)
        if not existing:
            return None
        now = time.time()
        sets = ["updated_at=?"]
        params = [now]
        for field, col in [
            ("name", "name"),
            ("schedule", "schedule"),
            ("machine_id", "machine_id"),
            ("enabled", "enabled"),
            ("disabled_reason", "disabled_reason"),
        ]:
            if field in updates:
                val = updates[field]
                if field == "enabled":
                    val = 1 if val else 0
                sets.append(f"{col}=?")
                params.append(val)
        if "spawn_params" in updates:
            sets.append("spawn_params=?")
            params.append(json.dumps(updates["spawn_params"]))
        if "consecutive_failures" in updates:
            sets.append("consecutive_failures=?")
            params.append(updates["consecutive_failures"])
        params.append(task_id)
        await self.storage._conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(sets)} WHERE id=?",
            params,
        )
        await self.storage._conn.commit()
        return await self.get_task(task_id)

    async def get_task(self, task_id: str) -> Optional[dict]:
        """Get a scheduled task by its ID.

        Returns a camelCase dict with ``spawnParams`` deserialized.
        """
        cur = await self.storage._conn.execute(
            "SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)
        )
        row = await cur.fetchone()
        if row is None:
            return None
        return self._row_to_task(dict(row))

    async def list_tasks(self) -> list[dict]:
        """List all scheduled tasks, newest first."""
        cur = await self.storage._conn.execute(
            "SELECT * FROM scheduled_tasks ORDER BY created_at DESC"
        )
        rows = await cur.fetchall()
        return [self._row_to_task(dict(r)) for r in rows]

    async def delete_task(self, task_id: str) -> bool:
        """Delete a scheduled task by ID.

        Returns:
            ``True`` if a row was actually deleted.
        """
        cur = await self.storage._conn.execute(
            "DELETE FROM scheduled_tasks WHERE id=?", (task_id,)
        )
        await self.storage._conn.commit()
        return cur.rowcount > 0

    def _row_to_task(self, row: dict) -> dict:
        """Convert a raw DB row to the camelCase API representation.

        Deserializes JSON fields and computes the ``nextRunAt`` time.
        """
        if isinstance(row.get("spawn_params"), str):
            row["spawn_params"] = json.loads(row["spawn_params"])
        now = time.time()
        next_run = self._compute_next_run(
            row["schedule"], row.get("last_run_at") or now - 1
        )
        return {
            "id": row["id"],
            "name": row["name"],
            "schedule": row["schedule"],
            "enabled": bool(row["enabled"]),
            "machineId": row.get("machine_id"),
            "spawnParams": row["spawn_params"],
            "consecutiveFailures": row.get("consecutive_failures", 0),
            "disabledReason": row.get("disabled_reason"),
            "lastRunAt": row.get("last_run_at"),
            "lastExecution": (
                {
                    "status": row.get("last_execution_status", "pending"),
                    "summary": row.get("last_execution_summary"),
                }
                if row.get("last_execution_status")
                else None
            ),
            "nextRunAt": next_run,
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    # ─── Executions ──────────────────────────────────

    async def create_execution(
        self,
        task_id: str,
        trigger: str = "scheduled",
        session_id: str = "",
    ) -> dict:
        """Create a new task execution record.

        Args:
            task_id: The parent task ID.
            trigger: How this execution was triggered (``"scheduled"`` or ``"manual"``).
            session_id: Optional ID of the spawned session.

        Returns:
            The execution record dict.
        """
        now = time.time()
        exec_id = f"e_{uuid.uuid4().hex[:16]}"
        await self.storage._conn.execute(
            """INSERT INTO task_executions
               (id, task_id, session_id, status, trigger, scheduled_at, created_at)
               VALUES (?, ?, ?, 'pending', ?, ?, ?)""",
            (exec_id, task_id, session_id or None, trigger, now, now),
        )
        await self.storage._conn.commit()
        return {
            "id": exec_id,
            "taskId": task_id,
            "sessionId": session_id or None,
            "status": "pending",
            "trigger": trigger,
            "scheduledAt": now,
            "startedAt": None,
            "completedAt": None,
            "error": None,
            "retryCount": 0,
            "summary": None,
            "createdAt": now,
        }

    async def update_execution(self, exec_id: str, updates: dict):
        """Update fields on an existing execution record."""
        sets = []
        params = []
        for field, col in [
            ("status", "status"),
            ("session_id", "session_id"),
            ("started_at", "started_at"),
            ("completed_at", "completed_at"),
            ("error", "error"),
            ("retry_count", "retry_count"),
            ("summary", "summary"),
        ]:
            if field in updates:
                sets.append(f"{col}=?")
                params.append(updates[field])
        if not sets:
            return
        params.append(exec_id)
        await self.storage._conn.execute(
            f"UPDATE task_executions SET {', '.join(sets)} WHERE id=?",
            params,
        )
        await self.storage._conn.commit()

    async def get_executions(self, task_id: str, limit: int = 20) -> list[dict]:
        """Get recent execution history for a task."""
        cur = await self.storage._conn.execute(
            """SELECT * FROM task_executions WHERE task_id=?
               ORDER BY created_at DESC LIMIT ?""",
            (task_id, limit),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ─── Cron scheduling ─────────────────────────────

    def _compute_next_run(self, schedule: str, after: float) -> Optional[float]:
        """Compute the next cron match after a given timestamp."""
        return next_cron_match(schedule, after)

    async def check_and_run(self):
        """Check all enabled tasks and trigger any that are due.

        Tasks that have failed 5+ consecutive times are auto-disabled
        via circuit breaker logic.
        """
        tasks = await self.list_tasks()
        now = time.time()
        for task in tasks:
            if not task.get("enabled"):
                continue
            if task.get("disabledReason"):
                continue
            if task.get("consecutiveFailures", 0) >= 5:
                await self.update_task(task["id"], {
                    "disabled_reason": "circuit-breaker",
                    "enabled": False,
                })
                logger.warning(
                    f"Task {task['id']} auto-disabled (circuit breaker)"
                )
                continue

            last_run = task.get("lastRunAt") or (now - 86400)
            next_run = self._compute_next_run(task["schedule"], last_run)
            if next_run is not None and next_run <= now:
                await self._execute_task(task)

    async def _execute_task(self, task: dict):
        """Execute a single task: spawn a session or record a skipped run.

        Creates an execution record, attempts to dispatch the spawn,
        and updates the task's summary and failure count.
        """
        task_id = task["id"]
        machine_id = task.get("machineId") or ""
        spawn_params = task.get("spawnParams", {})

        exec_record = await self.create_execution(task_id, "scheduled")

        try:
            if self.dispatch_spawn and machine_id:
                result = await self.dispatch_spawn(machine_id, {
                    **spawn_params,
                    "source": "scheduled",
                    "sessionId": exec_record["id"],
                })
                session_id = result.get("sessionId", "")
                await self.update_execution(exec_record["id"], {
                    "status": "running",
                    "started_at": time.time(),
                    "session_id": session_id,
                })
            else:
                # No machine assigned — mark as skipped
                await self.update_execution(exec_record["id"], {
                    "status": "skipped",
                    "completed_at": time.time(),
                    "summary": "no available machine",
                })
                return

        except Exception as exc:
            error_msg = str(exc)
            logger.error(f"Task {task_id} failed: {error_msg}")
            await self.update_execution(exec_record["id"], {
                "status": "failed",
                "completed_at": time.time(),
                "error": error_msg,
            })
            failures = task.get("consecutiveFailures", 0) + 1
            await self.update_task(task_id, {"consecutive_failures": failures})

        # Update the task's last-run summary regardless of outcome
        await self.storage._conn.execute(
            """UPDATE scheduled_tasks
               SET last_run_at=?, last_execution_status=?,
                   last_execution_summary=?, updated_at=?
               WHERE id=?""",
            (time.time(), None, None, time.time(), task_id),
        )
        await self.storage._conn.commit()

    # ─── Background loop ────────────────────────────

    async def start(self, interval_seconds: int = 60):
        """Start the background scheduler loop.

        Runs ``check_and_run()`` every *interval_seconds*.

        Args:
            interval_seconds: Seconds between checks.
        """
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(
            self._run_loop(interval_seconds)
        )
        logger.info(f"Scheduler started (interval={interval_seconds}s)")

    async def stop(self):
        """Stop the background scheduler loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Scheduler stopped")

    async def _run_loop(self, interval: int):
        """Background loop body — check and sleep."""
        while self._running:
            try:
                await self.check_and_run()
            except Exception as e:
                logger.error(f"Scheduler check error: {e}")
            await asyncio.sleep(interval)
