#!/usr/bin/env python3
"""SDN Shield - shared run-event logger (JSONL, monotonic + wall clock)."""
import json
import os
import time
from datetime import datetime, timezone


class EventLog:
    def __init__(self, run_id, out_dir="runs", config=None):
        self.run_id = run_id
        os.makedirs(os.path.join(out_dir, run_id), exist_ok=True)
        self.path = os.path.join(out_dir, run_id, "events.jsonl")
        self._f = open(self.path, "a", buffering=1)
        self.log("run_start", config=config or {})

    def log(self, event, **extra):
        rec = {
            "run_id": self.run_id,
            "event": event,
            "t_wall": datetime.now(timezone.utc).isoformat(),
            "t_mono": time.monotonic(),
            **extra,
        }
        self._f.write(json.dumps(rec) + "\n")

    def close(self):
        self.log("run_end")
        self._f.close()


if __name__ == "__main__":
    ev = EventLog("selftest", config={"seed": 1})
    ev.log("normal_start")
    ev.log("attack_start", kind="udp", attackers=["h1", "h2"], rate_pps=1000)
    ev.log("attack_end")
    ev.close()
    print("wrote", ev.path)
