# siem

A small SIEM I built from scratch to learn how log based detection works end to end. It takes in syslog, normalizes it, runs detection rules, fires alerts, and shows everything on a live dashboard.

## Why build it instead of using ELK

Most "SIEM projects" are just a configured Elastic stack. This is the opposite. The ingestion, parsing, and detection are all my own Python, so I understand every stage rather than gluing tools together.

## Architecture

```
collector -> parser -> Postgres -> detection -> alerting -> dashboard
```

- **collector** asyncio UDP/TCP syslog listener on port 5514
- **parser** RFC 3164 and RFC 5424 lines into one normalized Event
- **storage** Postgres via async psycopg
- **detection** single event rules plus sliding window correlation
- **alerting** webhook with throttling so one burst is not 500 messages
- **dashboard** FastAPI with server sent events, live event tail and alerts

## Status

Milestone 1 in progress: syslog in, SSH brute force detection, webhook alert, live dashboard, deployed with Docker Compose behind a Cloudflare Tunnel.

## Run locally

```
docker compose up
python tools/replay.py sample-logs/auth.log   # replay some test logs
```

Dashboard on http://localhost:8000

## Tests

```
uv run pytest
```
