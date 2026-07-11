"""Replay a log file to the collector over UDP, to simulate a syslog source.

Usage:
    python tools/replay.py sample-logs/auth.log

Env: SIEM_SYSLOG_HOST (default 127.0.0.1), SIEM_SYSLOG_PORT (5514),
     REPLAY_DELAY seconds between lines (default 0.2).
"""
import os
import socket
import sys
import time


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "sample-logs/auth.log"
    host = os.environ.get("SIEM_SYSLOG_HOST", "127.0.0.1")
    port = int(os.environ.get("SIEM_SYSLOG_PORT", "5514"))
    delay = float(os.environ.get("REPLAY_DELAY", "0.2"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            sock.sendto(line.encode("utf-8"), (host, port))
            sent += 1
            print("sent:", line[:90])
            time.sleep(delay)
    print(f"done, sent {sent} lines to {host}:{port}")


if __name__ == "__main__":
    main()
