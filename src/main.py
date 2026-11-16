#!/usr/bin/env python3
"""aiops-console belepesi pont: szolgaltatas (hatterszal + API) vagy egyszeri futtatas.

  python3 main.py                                   # szolgaltatas: utemezo + sor + REST API (STATUS_PORT)
  python3 main.py --once input|digest|notify-test   # egyszeri futtatas (a tarolt konfiggal)
"""
import argparse
import os
import sys
import threading

import aiops
import console
import runtime
from store import Store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", choices=["input", "digest", "notify-test"])
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data_dir = os.environ.get("DATA_DIR", "/data")
    os.makedirs(data_dir, exist_ok=True)
    rt = runtime.Runtime(Store(os.path.join(data_dir, "console.db")))
    rt.bootstrap()

    if args.once:
        return aiops.run_once(args.once, rt.get_known(), args.hours, args.dry_run)

    import uvicorn
    threading.Thread(target=aiops.service_loop, args=(rt.get_known, rt.store), daemon=True, name="aiops-worker").start()
    uvicorn.run(console.create_app(rt), host="0.0.0.0", port=aiops.CFG["STATUS_PORT"], log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
