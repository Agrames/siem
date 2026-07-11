"""Async Postgres access: one connection pool, plus insert/query helpers."""
from __future__ import annotations

from psycopg.rows import dict_row
from psycopg.types.json import Json
from psycopg_pool import AsyncConnectionPool

from . import config
from .models import Alert, Event

_pool: AsyncConnectionPool | None = None


async def init_pool() -> None:
    global _pool
    if _pool is None:
        _pool = AsyncConnectionPool(config.DATABASE_URL, min_size=1, max_size=5, open=False)
        await _pool.open()


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def _int(x) -> int | None:
    return int(x) if x is not None else None


async def insert_event(ev: Event) -> int:
    async with _pool.connection() as conn:
        cur = await conn.execute(
            """INSERT INTO events
               (ts, received_at, host, app, pid, facility, severity, source_ip, message, raw)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (ev.ts, ev.received_at, ev.host, ev.app, ev.pid,
             _int(ev.facility), _int(ev.severity), ev.source_ip, ev.message, ev.raw),
        )
        return (await cur.fetchone())[0]


async def insert_alert(a: Alert) -> int:
    async with _pool.connection() as conn:
        cur = await conn.execute(
            """INSERT INTO alerts (ts, rule, entity, title, severity, count, detail)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (a.ts, a.rule, a.entity, a.title, _int(a.severity), a.count, Json(a.detail)),
        )
        return (await cur.fetchone())[0]


async def recent_events(limit: int = 100) -> list[dict]:
    async with _pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, ts, host, app, pid, facility, severity, message "
                "FROM events ORDER BY id DESC LIMIT %s", (limit,))
            return await cur.fetchall()


async def recent_alerts(limit: int = 50) -> list[dict]:
    async with _pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, ts, rule, entity, title, severity, count "
                "FROM alerts ORDER BY id DESC LIMIT %s", (limit,))
            return await cur.fetchall()


async def max_event_id() -> int:
    async with _pool.connection() as conn:
        cur = await conn.execute("SELECT COALESCE(MAX(id), 0) FROM events")
        return (await cur.fetchone())[0]


async def events_since(last_id: int, limit: int = 200) -> list[dict]:
    async with _pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id, ts, host, app, pid, facility, severity, message "
                "FROM events WHERE id > %s ORDER BY id ASC LIMIT %s", (last_id, limit))
            return await cur.fetchall()
