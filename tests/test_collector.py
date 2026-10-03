import asyncio

from siem import collector


async def test_tcp_connection_survives_a_failing_line(monkeypatch):
    # one bad line (here: the database insert blowing up) must not drop the sender's connection
    stored = []

    async def insert_event(ev):
        if "boom" in ev.message:
            raise RuntimeError("database hiccup")
        stored.append(ev.message)

    monkeypatch.setattr(collector.storage, "insert_event", insert_event)

    server = await asyncio.start_server(collector._handle_tcp, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"<78>Jul 11 09:00:00 host1 cron: boom\n")
        writer.write(b"<78>Jul 11 09:00:01 host1 cron: still here\n")
        await writer.drain()
        for _ in range(100):
            if stored:
                break
            await asyncio.sleep(0.01)
        writer.close()
        await writer.wait_closed()
    assert stored == ["still here"]
