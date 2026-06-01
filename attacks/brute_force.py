"""
AMSES - Attack Simulation: Brute Force Login
attacks/brute_force.py

Simulates repeated failed login attempts against the local AMSES server.
Purpose: Educational demonstration only — targets localhost only.

Expected result after running:
  - Risk score rises rapidly
  - IP gets auto-blocked after MAX_FAILED_LOGINS_BEFORE_BLOCK failures
  - Dashboard shows HIGH risk level
  - Encryption mode escalates
  - Block is visible in dashboard + logs

Run:
    python attacks/brute_force.py
"""

import requests
import time

BASE_URL = "http://127.0.0.1:5000"

WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty",
    "password123", "admin123", "root", "toor", "pass",
    "welcome", "login", "test", "guest", "secret",
]

TARGET_USER = "admin"
DELAY       = 0.3   # seconds between attempts


def run():
    print("=" * 60)
    print("  AMSES Attack Simulation: BRUTE FORCE LOGIN")
    print("  Target: localhost only (educational demo)")
    print("=" * 60)

    for i, pwd in enumerate(WORDLIST, 1):
        try:
            resp = requests.post(
                f"{BASE_URL}/api/login",
                json={"username": TARGET_USER, "password": pwd},
                headers={"X-Forwarded-For": "127.0.0.1"},
                timeout=5,
            )
            data = resp.json()
            status = "✓ SUCCESS" if data.get("success") else "✗ FAIL"
            risk   = data.get("risk", "—")
            print(f"  [{i:02d}] {pwd:<20} {status}  risk={risk}  code={resp.status_code}")

            if data.get("blocked"):
                print("\n  🚫 IP has been BLOCKED by AMSES Firewall!")
                print("     Check dashboard: http://127.0.0.1:5000/dashboard")
                break

            if data.get("success"):
                print("     ✓ Login succeeded (expected: demo credentials)")
                break

        except requests.exceptions.ConnectionError:
            print("  ERROR: Cannot connect to AMSES server. Is it running?")
            print("  Start server with: python run.py")
            break
        except Exception as e:
            print(f"  ERROR: {e}")

        time.sleep(DELAY)

    print("\n  Simulation complete. Check dashboard for risk changes.")
    print(f"  Dashboard: {BASE_URL}/dashboard")


if __name__ == "__main__":
    run()