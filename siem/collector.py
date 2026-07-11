"""Syslog collector: listens on UDP+TCP, runs each line through the pipeline.

This is the glue. Every incoming line goes: parse -> store -> detect -> alert.
It imports your parser and detector, so once those are implemented the whole thing
runs end to end.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from . import alerting, config, storage
from .detection import BruteForceDetector
from .parser import parse_line

detector = BruteForceDetector(
    threshold=config.BRUTE_FORCE_THRESHOLD,
    window_seconds=config.BRUTE_FORCE_WINDOW,
)

# keep references to fire-and-forget UDP tasks so they aren't garbage collected
_bg_tasks: set[asyncio.Task] = set()


async def handle_line(raw: str, source_ip: str | None) -> None:
    raw = raw.rstrip("\r\n")
    if not raw.strip():
        return
    try:
        ev = parse_line(raw, received_at=datetime.now(timezone.utc), source_ip=source_ip)
    except Exception as e:
        print(f"[collector] parse error: {e!r} on line: {raw[:200]}")
        return
    if ev is None:
        return
    await storage.insert_event(ev)
    alert = detector.process(ev)
    if alert is not None:
        await storage.insert_alert(alert)
        await alerting.dispatch(alert)


class _UDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr) -> None:
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines():  # a datagram may hold several messages
            t = asyncio.create_task(handle_line(line, addr[0]))
            _bg_tasks.add(t)
            t.add_done_callback(_bg_tasks.discard)


async def _handle_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else None
    while True:
        line = await reader.readline()
        if not line:
            break
        await handle_line(line.decode("utf-8", errors="replace"), ip)
    writer.close()


async def main() -> None:
    await storage.init_pool()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        _UDPProtocol, local_addr=(config.SYSLOG_HOST, config.SYSLOG_PORT))
    server = await asyncio.start_server(_handle_tcp, config.SYSLOG_HOST, config.SYSLOG_PORT)
    print(f"[collector] listening on {config.SYSLOG_HOST}:{config.SYSLOG_PORT} (udp+tcp)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
