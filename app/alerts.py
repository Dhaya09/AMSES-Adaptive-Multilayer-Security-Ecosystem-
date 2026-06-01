"""
AMSES - Alerting + Logging Module
alerts.py

Handles structured file-based logging across all security layers
and optional SMTP email alerting (simulated if SMTP not configured).
"""

import os
import time
import smtplib
import threading
from email.mime.text import MIMEText
from config import (
    LOG_AUTH, LOG_RISK, LOG_ALERTS, LOG_BLOCKED, LOG_EVENTS,
    SMTP_ENABLED, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL
)

_alert_history: list = []   # in-memory recent alerts
_lock = threading.Lock()


def _write(path: str, message: str) -> None:
    """Append a timestamped line to a log file."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(path, "a") as f:
            f.write(line)
    except OSError:
        pass


def log_auth(ip: str, username: str, success: bool, detail: str = "") -> None:
    status = "SUCCESS" if success else "FAILURE"
    _write(LOG_AUTH, f"AUTH {status} | IP={ip} | user={username} | {detail}")
    _write(LOG_EVENTS, f"AUTH {status} | IP={ip} | user={username}")


def log_risk(ip: str, score: float, level: str, trigger: str) -> None:
    _write(LOG_RISK, f"RISK | IP={ip} | score={score:.1f} | level={level} | trigger={trigger}")
    _write(LOG_EVENTS, f"RISK {level} | IP={ip} | score={score:.1f}")


def log_blocked(ip: str, reason: str) -> None:
    _write(LOG_BLOCKED, f"BLOCKED | IP={ip} | reason={reason}")
    _write(LOG_EVENTS, f"BLOCKED | IP={ip}")


def log_alert(level: str, message: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    _write(LOG_ALERTS, f"[{level}] {message}")
    with _lock:
        _alert_history.insert(0, {
            "level": level,
            "message": message,
            "timestamp": ts,
        })
        _alert_history[:] = _alert_history[:50]


def raise_alert(ip: str, event_type: str, detail: str, risk_level: str) -> None:
    """Main alert trigger - logs, stores, optionally emails."""
    message = f"[{risk_level}] {event_type} from {ip} — {detail}"
    log_alert(risk_level, message)
    if SMTP_ENABLED:
        _send_email(f"AMSES ALERT: {event_type}", message)


def _send_email(subject: str, body: str) -> None:
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [ALERT_EMAIL], msg.as_string())
    except Exception:
        pass   # silently fall back to log-only


def get_recent_alerts(limit: int = 20) -> list:
    with _lock:
        return _alert_history[:limit]


def tail_log(path: str, lines: int = 50) -> list:
    """Read last N lines of a log file."""
    try:
        with open(path, "r") as f:
            all_lines = f.readlines()
        return [l.rstrip() for l in all_lines[-lines:]][::-1]
    except OSError:
        return []


def get_all_logs() -> dict:
    return {
        "auth":    tail_log(LOG_AUTH),
        "risk":    tail_log(LOG_RISK),
        "alerts":  tail_log(LOG_ALERTS),
        "blocked": tail_log(LOG_BLOCKED),
        "events":  tail_log(LOG_EVENTS),
    }