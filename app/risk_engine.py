"""
AMSES - Risk Scoring Engine (FIXED)
risk_engine.py

Core novelty module: collects signals from all layers, calculates a
0-100 risk score per IP, classifies it, and drives adaptive responses.

FIXES:
- Prevent blocked IPs from immediately decaying to 0
- Keep blocked IP visible as HIGH risk on dashboard
- More stable risk behavior for demo and real-time monitoring
"""

import time
import threading
from collections import defaultdict
from config import (
    RISK_LOW_MAX, RISK_MEDIUM_MAX,
    SCORE_FAILED_LOGIN, SCORE_BLOCKED_ATTEMPT, SCORE_INVALID_INPUT,
    SCORE_SUSPICIOUS_REQUEST, SCORE_UNAUTHORIZED_ACCESS,
    SCORE_FLOOD_REQUEST, SCORE_ATTACK_SIM, SCORE_DECAY_PER_SECOND,
    ENCRYPTION_LOW, ENCRYPTION_MEDIUM, ENCRYPTION_HIGH
)
from app.firewall import is_blocked

_lock = threading.RLock()

# Per-IP state
_ip_state: dict = defaultdict(lambda: {
    "score": 0.0,
    "events": [],
    "last_update": time.time()
})

# Global event history
_global_events: list = []
MAX_GLOBAL_EVENTS = 200

# Signal weights
SIGNAL_WEIGHTS = {
    "failed_login":        SCORE_FAILED_LOGIN,
    "blocked_attempt":     SCORE_BLOCKED_ATTEMPT,
    "invalid_input":       SCORE_INVALID_INPUT,
    "suspicious_request":  SCORE_SUSPICIOUS_REQUEST,
    "unauthorized_access": SCORE_UNAUTHORIZED_ACCESS,
    "flood_request":       SCORE_FLOOD_REQUEST,
    "attack_simulation":   SCORE_ATTACK_SIM,
}


def _decay(ip: str) -> None:
    """
    Apply passive time-based score decay for an IP.

    IMPORTANT FIX:
    If IP is actively blocked, do NOT decay it immediately.
    Keep score elevated for dashboard consistency.
    """
    state = _ip_state[ip]
    now = time.time()

    # 🚫 If blocked, pin minimum score so dashboard still shows threat
    if is_blocked(ip):
        state["score"] = max(state["score"], 85.0)
        state["last_update"] = now
        return

    elapsed = now - state["last_update"]
    decay_amount = elapsed * SCORE_DECAY_PER_SECOND
    state["score"] = max(0.0, state["score"] - decay_amount)
    state["last_update"] = now


def record_event(ip: str, signal: str, detail: str = "") -> dict:
    """
    Record a security signal for an IP, update its risk score,
    and return the new risk profile.
    """
    with _lock:
        _decay(ip)
        weight = SIGNAL_WEIGHTS.get(signal, 5)
        _ip_state[ip]["score"] = min(100.0, _ip_state[ip]["score"] + weight)

        event = {
            "ip": ip,
            "signal": signal,
            "detail": detail,
            "score_after": round(_ip_state[ip]["score"], 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        _ip_state[ip]["events"].append(event)
        _ip_state[ip]["events"] = _ip_state[ip]["events"][-50:]

        _global_events.insert(0, event)
        if len(_global_events) > MAX_GLOBAL_EVENTS:
            _global_events.pop()

        return get_risk_profile(ip)


def get_risk_profile(ip: str) -> dict:
    """Return full risk profile for an IP."""
    from app import firewall

    with _lock:
        _decay(ip)

        score = round(_ip_state[ip]["score"], 2)

        # 🔥 FORCE HIGH if blocked
        if firewall.is_blocked(ip):
            score = max(score, 85.0)

        level = classify(score)

        return {
            "ip": ip,
            "score": score,
            "level": level,
            "encryption_mode": encryption_for_level(level),
            "events": _ip_state[ip]["events"][-10:],
        }


def get_risk_score(ip: str) -> float:
    with _lock:
        _decay(ip)
        return round(_ip_state[ip]["score"], 2)


def get_risk_level(ip: str) -> str:
    return classify(get_risk_score(ip))


def classify(score: float) -> str:
    if score <= RISK_LOW_MAX:
        return "LOW"
    elif score <= RISK_MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


def encryption_for_level(level: str) -> str:
    return {
        "LOW":    ENCRYPTION_LOW,
        "MEDIUM": ENCRYPTION_MEDIUM,
        "HIGH":   ENCRYPTION_HIGH,
    }.get(level, ENCRYPTION_LOW)


def get_all_ip_states() -> list:
    from app import firewall

    with _lock:
        result = []

        for ip, state in _ip_state.items():
            _decay(ip)
            score = round(state["score"], 2)

            # 🔥 FORCE HIGH if blocked
            if firewall.is_blocked(ip):
                score = max(score, 85.0)

            result.append({
                "ip": ip,
                "score": score,
                "level": classify(score),
                "event_count": len(state["events"]),
            })

        return sorted(result, key=lambda x: x["score"], reverse=True)

def get_global_events(limit: int = 50) -> list:
    with _lock:
        return _global_events[:limit]


def reset_ip(ip: str) -> None:
    with _lock:
        if ip in _ip_state:
            _ip_state[ip]["score"] = 0.0
            _ip_state[ip]["events"] = []
            _ip_state[ip]["last_update"] = time.time()