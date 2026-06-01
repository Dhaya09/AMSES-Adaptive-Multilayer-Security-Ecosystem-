"""
AMSES - Attack Simulation: Request Flood
attacks/request_flood.py

Simulates a high-frequency request flood (DoS-style) against the local server.
Purpose: Educational demonstration — triggers flood detection in AMSES IDS layer.

Expected result after running:
  - IDS flood detection fires
  - Risk score spikes
  - IP may be blocked if risk reaches HIGH
  - Dashboard shows flood_suspect = True for source IP

Run:
    python attacks/request_flood.py
"""

import requests
import time
import threading

BASE_URL  = "http://127.0.0.1:5000"
REQUESTS  = 50      # total requests to send
THREADS   = 5       # concurrent threads
DELAY     = 0.05    # delay between each thread's requests


_results = {"ok": 0, "error": 0, "blocked": 0}
_lock = threading.Lock()


def flood_worker(thread_id: int, count: int):
    for i in range(count):
        try:
            resp = requests.get(f"{BASE_URL}/", timeout=3)
            with _lock:
                if resp.status_code == 403:
                    _results["blocked"] += 1
                else:
                    _results["ok"] += 1
        except Exception:
            with _lock:
                _results["error"] += 1
        time.sleep(DELAY)


def run():
    print("=" * 60)
    print("  AMSES Attack Simulation: REQUEST FLOOD")
    print("  Target: localhost only (educational demo)")
    print(f"  Sending {REQUESTS} requests via {THREADS} threads")
    print("=" * 60)

    per_thread = REQUESTS // THREADS
    threads = []
    start = time.time()

    for t in range(THREADS):
        th = threading.Thread(target=flood_worker, args=(t, per_thread))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    elapsed = time.time() - start
    rps = REQUESTS / elapsed

    print(f"\n  Results:")
    print(f"    OK:       {_results['ok']}")
    print(f"    Blocked:  {_results['blocked']}")
    print(f"    Errors:   {_results['error']}")
    print(f"    Duration: {elapsed:.1f}s")
    print(f"    Rate:     {rps:.1f} req/s")

    # Also trigger the sim endpoint directly for score visibility
    try:
        requests.post(
            f"{BASE_URL}/api/sim/trigger",
            json={"signal": "flood_request", "detail": f"simulated flood: {REQUESTS} requests in {elapsed:.1f}s"},
            timeout=5,
        )
    except Exception:
        pass

    print(f"\n  Simulation complete. Check dashboard: {BASE_URL}/dashboard")


if __name__ == "__main__":
    run()