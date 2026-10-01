"""
CyberTrace AI — CLI shortcut to inject a live attack scenario.

Run from repo root:
    python scripts/simulate_attack.py --server http://<SERVER_IP>:8000
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberTrace AI Attack Simulator")
    parser.add_argument("--server", default="http://localhost:8000", help="SOC Server URL (e.g. http://192.168.1.100:8000 or Render URL)")
    args = parser.parse_args()

    server_url = args.server.rstrip("/")
    print(f"💥 Injecting Laptop C brute-force + exfiltration scenario to {server_url}…")
    try:
        resp = httpx.post(f"{server_url}/simulate_attack", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print(f"\n✅ Injected {data['injected_auth']} auth rows + {data['injected_activity']} activity rows.")
        print(f"\n📌 {data['hint']}\n")
    except httpx.ConnectError:
        print(f"❌ Backend not running at {server_url}.")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
