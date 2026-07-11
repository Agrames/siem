"""FastAPI dashboard backend: JSON endpoints plus a server-sent-events live feed."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse

from . import storage

_INDEX = Path(__file__).parent / "web" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await storage.init_pool()
    yield
    await storage.close_pool()


app = FastAPI(title="siem", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return _INDEX.read_text()


@app.get("/api/events")
async def events(limit: int = 100):
    return await storage.recent_events(limit)


@app.get("/api/alerts")
async def alerts(limit: int = 50):
    return await storage.recent_alerts(limit)


@app.get("/api/stream")
async def stream():
    # long-lived SSE stream: poll for new events once a second and push them
    async def gen():
        last_id = await storage.max_event_id()
        while True:
            rows = await storage.events_since(last_id, limit=200)
            for r in rows:
                last_id = max(last_id, r["id"])
                yield {"event": "log", "data": json.dumps(jsonable_encoder(r))}
            await asyncio.sleep(1.0)

    return EventSourceResponse(gen())
