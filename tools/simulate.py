"""Fire test syslog events at the running SIEM so you can watch it react.

The collector must be running (docker compose up). Then, from the project folder:

  uv run python tools/simulate.py attack 45.9.1.7      # 6 failed logins -> should raise ONE alert
  uv run python tools/simulate.py attack 45.9.1.7 10   # 10 failures instead of the default 6
  uv run python tools/simulate.py fail 45.9.1.7        # a single failed login (no alert on its own)
  uv run python tools/simulate.py ok david             # a normal, successful login (never alerts)
  uv run python tools/simulate.py raw "<86>..."        # send any raw syslog line you write yourself

Tip: use a DIFFERENT ip each time you run 'attack'. Once your detector has
alerted on an ip it remembers it and won't alert again (that is your fire-once
rule working). To forget them all, restart the collector:
  docker compose restart collector
"""
import socket
import sys
import time
from datetime import datetime

HOST = "127.0.0.1"
PORT = 5514
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send(line):
    sock.sendto(line.encode("utf-8"), (HOST, PORT))
    print("sent:", line)


def stamp():
    # an RFC 3164 timestamp for right now, e.g. "Jul 20 14:30:00"
    return datetime.now().strftime("%b %d %H:%M:%S")


def failed(ip, pid):
    return f"<86>{stamp()} webserver sshd[{pid}]: Failed password for invalid user admin from {ip} port 4242 ssh2"


def accepted(user):
    return f"<86>{stamp()} webserver sshd[2201]: Accepted password for {user} from 10.0.0.5 port 51314 ssh2"


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "help"

    if cmd == "attack":
        ip = args[1]
        count = int(args[2]) if len(args) > 2 else 6
        print(f"sending {count} failed logins from {ip} (threshold is 5)...")
        for i in range(count):
            send(failed(ip, 2000 + i))
            time.sleep(0.4)
        print("done - check your dashboard for the alert")
    elif cmd == "fail":
        send(failed(args[1], 2001))
    elif cmd == "ok":
        send(accepted(args[1] if len(args) > 1 else "david"))
    elif cmd == "raw":
        send(args[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
