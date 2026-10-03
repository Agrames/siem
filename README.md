# siem

A security tool that spots someone trying to break into a server and raises an alarm.

## What it does

The most common way to break into a server is to guess passwords over and over, like a
burglar trying thousands of keys in a lock.

One wrong password is normal; everyone makes typos. Five or more from the same place within
two minutes is treated as an attack. This tool watches every login attempt, spots that
pattern, and shows an alert on a live dashboard.

## How it works

1. **Listen:** collect login activity from a server.
2. **Understand:** turn each raw message into who, when, and what happened.
3. **Save:** store it in a database.
4. **Detect:** look for too many failed logins from one place in a short time.
5. **Alert:** flag the attack on the dashboard.

## Built with

Python, PostgreSQL, Docker and FastAPI. The core (understanding messages and detecting
attacks) is written from scratch rather than using an off-the-shelf tool.

## Try it (for developers)

There is no online demo. It runs on your own computer with Docker, using fake attacks, so
nothing real is at risk.

```
git clone https://github.com/Agrames/siem.git
cd siem
docker compose up
```

In a second terminal window:

```
python3 tools/simulate.py attack 45.9.1.8
```

Open http://localhost:8000 to see the alert. Each address alerts only once, so change the
last number (45.9.1.9, 45.9.1.10, ...) to try again.

Run the tests with `uv run pytest`.
