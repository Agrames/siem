# siem

A security tool that watches a server for break-in attempts and flags them in real time.

**Live demo: https://siem.davidagugharam.com**

## What it does (in plain English)

Servers get attacked constantly. The most common attack is simple: someone tries to log
in over and over, guessing passwords and hoping one works, like a burglar trying thousands
of keys in a lock. One failed login is normal (we all mistype passwords). Fifty failed
logins from the same place in two minutes is an attack.

This tool watches the stream of login activity, spots that pattern, and raises an alert the
moment it sees someone hammering the door, while ignoring the everyday noise. Everything
shows up on a live dashboard.

It is a small, built-from-scratch version of the kind of monitoring system that professional
security teams use to keep an eye on their systems.

## See it running

The dashboard is live at **https://siem.davidagugharam.com**. It shows a live feed of
incoming activity and any alerts the system has raised. The data on it is simulated (safe,
made-up attacks), so there is nothing sensitive to see.

## How it works

Each log message passes through five steps:

1. **Collect** — listen for log messages coming from a server.
2. **Read** — make sense of each message (they arrive as messy text) and pull out the useful
   parts: who, when, and what happened.
3. **Store** — save them to a database.
4. **Detect** — watch for the attack pattern: too many failed logins from one place, too fast.
5. **Alert** — when it spots one, raise an alert and show it on the dashboard.

## Built with

Python, PostgreSQL, Docker, and FastAPI, running on a cloud server behind a Cloudflare
tunnel. The heart of it, reading the log messages and detecting the attacks, is written from
scratch rather than using an off-the-shelf tool, so every part is understood rather than just
wired together.

## Run it yourself

```
docker compose up                            # start everything
python tools/simulate.py attack 45.9.1.8     # fire a fake attack and watch it get caught
```

Then open the dashboard at http://localhost:8000.

Run the tests with:

```
uv run pytest
```
