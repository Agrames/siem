"""Send alerts to a webhook, with a small throttle so we don't spam."""
from __future__ import annotations

import time

import httpx

from . import config
from .models import Alert

# remember when we last sent each (rule, entity) so a noisy burst is one message
_last_sent: dict[tuple[str, str], float] = {}
_THROTTLE_SECONDS = 60


def _payload(alert: Alert) -> dict:
    text = f":rotating_light: {alert.title or alert.rule} | entity={alert.entity} count={alert.count}"
    # Discord webhooks want "content", Slack wants "text". Cover both.
    if "discord" in config.WEBHOOK_URL:
        return {"content": text}
    return {"text": text}


async def dispatch(alert: Alert) -> None:
    key = (alert.rule, alert.entity)
    now = time.monotonic()
    last = _last_sent.get(key)
    if last is not None and now - last < _THROTTLE_SECONDS:
        return
    _last_sent[key] = now

    if not config.WEBHOOK_URL:
        return  # no webhook set, nothing to send

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(config.WEBHOOK_URL, json=_payload(alert))
    except Exception as e:
        # a webhook failure must never take down the pipeline
        print(f"[alerting] webhook failed: {e!r}")
