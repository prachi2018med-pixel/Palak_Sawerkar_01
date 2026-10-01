"""
CyberTrace AI — CLI shortcut to inject a live attack scenario.

Run from repo root:
    python scripts/simulate_attack.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx


def main() -> None:
    print("💥 Injecting Laptop C brute-force + exfiltration scenario…")
    try:
        resp = httpx.post("http://localhost:8000/simulate_attack", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        print(f"\n✅ Injected {data['injected_auth']} auth rows + {data['injected_activity']} activity rows.")
        print(f"\n📌 {data['hint']}\n")
    except httpx.ConnectError:
        print("❌  Backend not running. Start with: uvicorn backend.main:app --reload --port 8000")
    except Exception as e:
        print(f"❌  Error: {e}")


if __name__ == "__main__":
    main()
