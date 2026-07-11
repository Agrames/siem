"""All runtime config comes from environment variables, with dev-friendly defaults."""
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://siem:siem@localhost:5432/siem")

# syslog listener. Binds inside the container/host; the compose file only publishes
# this to localhost, never to the public internet.
SYSLOG_HOST = os.environ.get("SIEM_SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.environ.get("SIEM_SYSLOG_PORT", "5514"))

# alerting webhook (Slack or Discord incoming webhook). blank means don't send.
WEBHOOK_URL = os.environ.get("SIEM_WEBHOOK_URL", "")

# brute force rule tuning
BRUTE_FORCE_THRESHOLD = int(os.environ.get("SIEM_BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.environ.get("SIEM_BRUTE_FORCE_WINDOW", "120"))
