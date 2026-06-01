"""
AMSES - Attack Simulation: Suspicious / Unauthorized Access
attacks/suspicious_access.py

Simulates:
  1. Unauthorized access to protected endpoints (no token)
  2. Invalid input injection attempts
  3. Multiple attack simulation events

Purpose: Educational demo — triggers unauthorized_access + invalid_input
         risk signals and raises alerts in AMSES.

Expected result:
  - Risk score rises per unauthorized attempt
  - invalid_input signals logged
  - Alerts appear in dashboard
  - Encryption mode may escalate

Run:
    python attacks/suspicious_access.py
"""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"

SUSPICIOUS_INPUTS = [
    {"username": "admin' OR '1'='1", "password": "anything"},
    {"username": "<script>alert(1)</script>", "password": "test"},
    {"username": "admin; DROP TABLE users;--", "password": "test"},
    {"username": "../../../etc/passwd", "password": "test"},
]


def run():
    print("=" * 60)
    print("  AMSES Attack Simulation: SUSPICIOUS ACCESS")
    print("  Target: localhost only (educational demo)")
    print("=" * 60)

    # 1. Unauthorized access to /api/secure-data (no token)
    print("\n[1] Attempting unauthorized access to secure endpoint...")
    for i in range(6):
        try:
            resp = requests.get(f"{BASE_URL}/api/secure-data", timeout=5)
            print(f"  Attempt {i+1}: status={resp.status_code}  response={resp.json().get('error','?')}")
        except Exception as e:
            print(f"  Attempt {i+1}: ERROR {e}")
        time.sleep(0.2)

    # 2. Injection-style login attempts
    print("\n[2] Sending injection-style login inputs...")
    for inp in SUSPICIOUS_INPUTS:
        try:
            resp = requests.post(
                f"{BASE_URL}/api/login",
                json=inp,
                timeout=5,
            )
            data = resp.json()
            print(f"  user={inp['username'][:30]:<30} -> {data.get('error','?')} (code={resp.status_code})")
        except Exception as e:
            print(f"  ERROR: {e}")
        time.sleep(0.3)

    # 3. Direct simulation triggers
    print("\n[3] Triggering attack simulation signals...")
    sim_events = [
        {"signal": "unauthorized_access", "detail": "scraping attempt on /api/secure-data"},
        {"signal": "suspicious_request",  "detail": "abnormal User-Agent detected"},
        {"signal": "attack_simulation",   "detail": "reconnaissance scan pattern"},
    ]
    for ev in sim_events:
        try:
            resp = requests.post(
                f"{BASE_URL}/api/sim/trigger",
                json=ev,
                timeout=5,
            )
            data = resp.json()
            profile = data.get("profile", {})
            print(f"  signal={ev['signal']:<25} score={profile.get('score','?')} level={profile.get('level','?')}")
        except Exception as e:
            print(f"  ERROR: {e}")
        time.sleep(0.2)

    print(f"\n  Simulation complete. Check dashboard: {BASE_URL}/dashboard")


if __name__ == "__main__":
    run()