"""
AMSES - Dashboard Data Module (FIXED)
dashboard.py

Aggregates system state from all modules and serves it
to the dashboard template / API.

FIXES:
- Keeps blocked IPs visible even if decay occurs
- Ensures dashboard reflects real active threat state
"""

from app import risk_engine, firewall, alerts, detector


def get_dashboard_data() -> dict:
    """Collect and return complete system state for the dashboard."""

    recent_events   = risk_engine.get_global_events(50)
    blocked_ips     = firewall.get_blocked_ips()
    block_history   = firewall.get_block_history(20)
    all_ips         = risk_engine.get_all_ip_states()
    recent_alerts   = alerts.get_recent_alerts(20)
    detector_stats  = detector.get_all_stats()

    # 🔥 IMPORTANT FIX:
    # Ensure blocked IPs are also represented in all_ips
    existing_ips = {ip["ip"] for ip in all_ips}

    for blocked in blocked_ips:
        ip = blocked["ip"]
        if ip not in existing_ips:
            all_ips.append({
                "ip": ip,
                "score": 85.0,
                "level": "HIGH",
                "event_count": 0,
            })

    # Re-sort after injecting blocked IPs
    all_ips = sorted(all_ips, key=lambda x: x["score"], reverse=True)

    # Global max risk
    max_score = max((ip["score"] for ip in all_ips), default=0)
    max_level = risk_engine.classify(max_score)

    return {
        "global_max_score": round(max_score, 1),
        "global_max_level": max_level,
        "encryption_mode":  risk_engine.encryption_for_level(max_level),

        "blocked_count":    len(blocked_ips),
        "blocked_ips":      blocked_ips,
        "block_history":    block_history,

        "all_ips":          all_ips,
        "recent_events":    recent_events,
        "recent_alerts":    recent_alerts,
        "detector_stats":   detector_stats,
    }