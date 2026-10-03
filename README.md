# siem

A security tool that watches a server for break-in attempts and flags them in real time.

## What it does

Servers get attacked constantly. The most common attack is simple: someone tries to log
in over and over, guessing passwords and hoping one works, like a burglar trying thousands
of keys in a lock. One failed login is normal (we all mistype passwords). Fifty failed
logins from the same place in two minutes is an attack.

This tool watches the stream of login activity, spots that pattern, and raises an alert the
moment it sees someone hammering the door, while ignoring the everyday noise. Everything
shows up on a live dashboard.

It is a small, built-from-scratch version of the kind of monitoring system that professional
security teams use to keep an eye on their systems.

## How it works

Each log message passes through five steps:

1. **Collect** — listen for log messages coming from a server.
2. **Read** — make sense of each message (they arrive as messy text) and pull out the useful
   parts: who, when, and what happened.
3. **Store** — save them to a database.
4. **Detect** — watch for the attack pattern: too many failed logins from one place, too fast.
5. **Alert** — when it spots one, raise an alert and show it on the dashboard.

## Built with

Python, PostgreSQL, Docker, and FastAPI. It previously ran as a public demo on a cloud server
behind a Cloudflare tunnel; that hosted demo has been retired. The heart of it, reading the
log messages and detecting the attacks, is written from scratch rather than using an
off-the-shelf tool, so every part is understood rather than just wired together.

## Run it yourself

Everything runs on your own machine with Docker. The attacks are simulated, so nothing real
is touched.

```
git clone https://github.com/Agrames/siem.git
cd siem
docker compose up                            # start everything (leave this running)
```

In a second terminal, from the same folder:

```
python3 tools/simulate.py attack 45.9.1.8    # fire a fake attack and watch it get caught
```

Then open the dashboard at http://localhost:8000. It shows a live feed of incoming activity
and any alerts the system has raised. Each address only triggers one alert until the collector
restarts, so use a different one (45.9.1.9, 45.9.1.10, ...) each time you run `attack`.

Run the tests with:

```
uv run pytest
```
