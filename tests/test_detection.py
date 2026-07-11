from datetime import datetime, timedelta, timezone

from siem.detection import BruteForceDetector
from siem.models import Event


def _failed_login(ip, ts):
    return Event(
        ts=ts,
        host="webserver",
        app="sshd",
        message=f"Failed password for invalid user admin from {ip} port 4242 ssh2",
        raw="raw line",
    )


def test_fires_after_threshold_within_window():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = []
    for i in range(5):
        a = det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 10)))
        if a:
            alerts.append(a)
    assert len(alerts) == 1
    assert alerts[0].entity == "203.0.113.7"
    assert alerts[0].count >= 5


def test_no_alert_below_threshold():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = [det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 10))) for i in range(4)]
    assert all(a is None for a in alerts)


def test_slow_trickle_does_not_fire():
    # 5 failures spread over 10 minutes, so never 5 inside one 2 minute window
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    alerts = [det.process(_failed_login("203.0.113.7", base + timedelta(minutes=2 * i + 1))) for i in range(5)]
    assert all(a is None for a in alerts)


def test_separate_ips_tracked_independently():
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    # 4 from each of two IPs, interleaved, neither reaches 5
    alerts = []
    for i in range(4):
        alerts.append(det.process(_failed_login("10.0.0.1", base + timedelta(seconds=i))))
        alerts.append(det.process(_failed_login("10.0.0.2", base + timedelta(seconds=i))))
    assert all(a is None for a in alerts)


def test_ignores_non_ssh_events():
    det = BruteForceDetector(threshold=1, window_seconds=120)
    ev = Event(ts=datetime.now(timezone.utc), host="h", app="cron", message="job ran", raw="raw")
    assert det.process(ev) is None


def test_fires_once_not_repeatedly():
    # once fired, more failures in the same window must not spam a new alert each time
    det = BruteForceDetector(threshold=5, window_seconds=120)
    base = datetime(2026, 7, 11, 22, 0, 0, tzinfo=timezone.utc)
    fired = 0
    for i in range(10):
        a = det.process(_failed_login("203.0.113.7", base + timedelta(seconds=i * 5)))
        if a:
            fired += 1
    assert fired == 1
