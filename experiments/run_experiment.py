
import argparse
import json
import math
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from events import EventLog  # noqa: E402

MGMT = "/var/run/openvswitch/s1.mgmt"
CONTROLLER = "sdn-shield-controller"
ATTACKS = ("syn", "udp", "icmp")
SCENARIOS = ATTACKS + ("normal", "highvol")
HTTP_PORT = 8080
PING_INTERVAL = 0.2
END_EVENT = {"syn": "attack_end", "udp": "attack_end", "icmp": "attack_end",
             "highvol": "highvol_end", "normal": "quiet_phase_end"}

CURL_LOOP = (
    "end=$((SECONDS+{seconds})); while [ $SECONDS -lt $end ]; do "
    "t=$(date +%s.%N); "
    "r=$(curl -s -o /dev/null -m 2 -w '%{{http_code}} %{{time_total}}' http://{target}:{port}/ || true); "
    "[ -n \"$r\" ] || r='000 2'; echo \"$t $r\"; sleep 0.5; done"
)
PING_RE = re.compile(r"^\[(\d+\.\d+)\].*time=([\d.]+) ms")


# ---------- small helpers (pure Python, no Mininet) ----------

def ovs(*args):
    return subprocess.check_output(args, text=True, timeout=10)


def sleep_until(moment):
    time.sleep(max(0.0, moment - time.monotonic()))


def wait_until(condition, timeout, message):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise RuntimeError(message)
        time.sleep(0.1)


def attack_cmd(kind, target, rate, seconds):
    """hping3 command: `rate` packets/s for `seconds` (bounded by -c)."""
    interval = f"u{max(1, int(1_000_000 / rate))}"
    base = ["hping3", "-q", "-i", interval, "-c", str(int(rate * seconds))]
    if kind == "syn":
        return base + ["-S", "-p", "80", target]
    if kind == "udp":
        return base + ["--udp", "-p", "53", "-d", "64", target]
    return base + ["--icmp", target]


def parse_record(line):
    """'SAMPLE window=1 destination=00:..:08 packets=5 ...' -> ('SAMPLE', {...})"""
    prefix, *parts = line.split()
    fields = {}
    for part in parts:
        key, _, value = part.partition("=")
        if key in ("destination", "mitigation"):
            fields[key] = value
            continue
        try:
            fields[key] = float(value) if any(c in value for c in ".eE") else int(value)
        except ValueError:
            fields[key] = value
    return prefix, fields


def read_ping(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        match = PING_RE.match(line)
        if match:
            rows.append((float(match[1]), float(match[2])))
    return rows


def read_curl(path):
    rows = []
    for line in Path(path).read_text().splitlines():
        parts = line.split()
        if len(parts) == 3:
            try:
                rows.append((float(parts[0]), parts[1] == "200", float(parts[2])))
            except ValueError:
                pass
    return rows


def legit_impact(pings, curls, bounds, n_clients):
    """Per-phase legitimate-user impact from ping/curl logs (wall-clock bucketing)."""
    out = {}
    for name, start, end in bounds:
        rtts = [rtt for ts, rtt in pings if start <= ts < end]
        fetches = [(ok, sec) for ts, ok, sec in curls if start <= ts < end]
        expected = round((end - start) / PING_INTERVAL) * n_clients
        out[name] = {
            "ping_received": len(rtts),
            "ping_expected": expected,
            "ping_loss": round(max(0.0, 1 - len(rtts) / expected), 4) if expected else None,
            "ping_mean_rtt_ms": round(sum(rtts) / len(rtts), 3) if rtts else None,
            "curl_total": len(fetches),
            "curl_ok": sum(1 for ok, _ in fetches if ok),
            "curl_mean_seconds": round(sum(s for _, s in fetches) / len(fetches), 4) if fetches else None,
        }
    return out


def detection_summary(alarm_times, attack_start, attack_end, is_attack):
    """Alarm counts per phase. Times are the driver's monotonic receipt times."""
    before = [t for t in alarm_times if t < attack_start]
    during = [t for t in alarm_times if attack_start <= t <= attack_end]
    after = [t for t in alarm_times if t > attack_end]
    out = {"alarms_baseline": len(before), "alarms_during": len(during),
           "alarms_recovery": len(after)}
    if is_attack:
        out["detected"] = bool(during)
        out["detection_latency_s"] = round(during[0] - attack_start, 3) if during else None
        out["false_alarms"] = len(before)
    else:
        out["false_alarms"] = len(alarm_times)  # no attack happened: every alarm is false
    return out


# ---------- background workers ----------

class Monitor:
    """Runs `sdn-shield-controller monitor ...` and logs every record it prints."""

    def __init__(self, log, run_dir, interval_ms, windows, pps, bps):
        self.samples, self.alarms = [], []
        self.ready = threading.Event()
        self.err = open(run_dir / "monitor.stderr.log", "w")
        self.proc = subprocess.Popen(
            [CONTROLLER, "monitor", MGMT, str(interval_ms), str(windows), str(pps), str(bps)],
            stdout=subprocess.PIPE, stderr=self.err, text=True)
        self.thread = threading.Thread(target=self._read, args=(log,), daemon=True)
        self.thread.start()

    def _read(self, log):
        for line in self.proc.stdout:
            now = time.monotonic()
            if not line.strip():
                continue
            prefix, fields = parse_record(line)
            log(prefix.lower(), **fields)
            if prefix == "MONITOR_READY":
                self.ready.set()
            elif prefix == "SAMPLE":
                self.samples.append((now, fields))
            elif prefix == "THRESHOLD_ALARM":
                self.alarms.append((now, fields))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.thread.join(timeout=2)
        self.err.close()


def sample_resources(pid, path, stop):
    """CPU% and RSS of one process, from /proc, every 0.5 s (no extra packages needed)."""
    tick = os.sysconf("SC_CLK_TCK")
    last = None
    with open(path, "w") as out:
        out.write("t_mono,cpu_percent,rss_kb\n")
        while not stop.is_set():
            try:
                stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                cpu = int(stat[11]) + int(stat[12])  # utime + stime
                rss = int(re.search(r"VmRSS:\s+(\d+)", Path(f"/proc/{pid}/status").read_text())[1])
            except (OSError, TypeError):
                break
            now = time.monotonic()
            if last:
                percent = 100 * (cpu - last[1]) / tick / (now - last[0])
                out.write(f"{now:.3f},{percent:.2f},{rss}\n")
            last = (now, cpu)
            stop.wait(0.5)


def switch_ready():
    try:
        connected = ovs("ovs-vsctl", "get", "Controller", "s1", "is_connected").strip() == "true"
        flows = ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1")
    except subprocess.SubprocessError:
        return False
    return connected and "actions=CONTROLLER" in flows


# ---------- one run ----------

def run_one(args, scenario, rep, out_dir):
    from topology import build  # imported here: needs Mininet

    interval_s = args.interval_ms / 1000
    total = args.baseline + args.duration + args.recovery
    windows = math.ceil(total / interval_s) + 3
    is_attack = scenario in ATTACKS
    run_id = f"{scenario}-r{rep}-{datetime.now():%H%M%S}"
    config = {"scenario": scenario, "rep": rep, "attackers": args.attackers,
              "rate_pps_per_attacker": args.rate, "highvol_mbit": args.highvol_mbit,
              "baseline_s": args.baseline, "duration_s": args.duration,
              "recovery_s": args.recovery, "interval_ms": args.interval_ms,
              "pps_limit": args.pps_limit, "byte_limit": args.byte_limit,
              "link_mbit": args.bw, "seed": args.seed}
    events = EventLog(run_id, out_dir=str(out_dir), config=config)
    run_dir = Path(events.path).parent
    lock = threading.Lock()

    def log(event, **fields):
        with lock:
            events.log(event, **fields)

    net = controller = monitor = sampler = None
    stop_sampling = threading.Event()
    procs, files = [], []

    def open_log(name):
        handle = (run_dir / f"{name}.log").open("w")
        files.append(handle)
        return handle

    def spawn(host, name, cmd):
        proc = host.popen(cmd, stdout=open_log(name), stderr=subprocess.STDOUT)
        procs.append(proc)
        return proc

    def stop_procs(group):
        for proc in group:
            if proc.poll() is None:
                proc.terminate()
        for proc in group:
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    summary = {"run_id": run_id, "scenario": scenario, "config": config}
    try:
        controller = subprocess.Popen([CONTROLLER], stdout=subprocess.PIPE,
                                      stderr=open_log("controller.stderr"), text=True)
        if not controller.stdout.readline().startswith("LISTENING"):
            raise RuntimeError("controller did not start (is port 6653 free?)")
        net = build("127.0.0.1", 6653, args.bw)
        wait_until(switch_ready, 20, "switch did not connect to the Rust controller")
        loss = net.pingAll(timeout="1")
        log("warmup", pingall_loss_percent=loss)
        if loss:
            raise RuntimeError(f"warm-up pingAll lost {loss}% of packets")
        sampler = threading.Thread(target=sample_resources, daemon=True,
                                   args=(controller.pid, run_dir / "resources.csv", stop_sampling))
        sampler.start()

        attackers = [net.get(f"h{i}") for i in range(1, args.attackers + 1)]
        clients = [net.get(name) for name in ("h5", "h6", "h7")]
        victim = net.get("h8")
        target = victim.IP()
        spawn(victim, "http-server", ["python3", "-m", "http.server", str(HTTP_PORT),
                                      "--bind", target, "--directory", "/tmp"])
        spawn(victim, "iperf3-server", ["iperf3", "-s", "-B", target])
        wait_until(lambda: (lambda s: f":{HTTP_PORT}" in s and ":5201" in s)(victim.cmd("ss -ltn")),
                   10, "victim servers did not start")

        monitor = Monitor(log, run_dir, args.interval_ms, windows, args.pps_limit, args.byte_limit)
        wait_until(monitor.ready.is_set, 10, "monitor did not become ready")

        # --- phase 1: baseline (legitimate traffic only) ---
        t0, w0 = time.monotonic(), time.time()
        log("normal_start", clients=[c.name for c in clients])
        legit = []
        for client in clients:
            legit.append(spawn(client, f"{client.name}-ping", [
                "ping", "-n", "-D", "-i", str(PING_INTERVAL), "-W", "1",
                "-c", str(int(total / PING_INTERVAL)), target]))
            legit.append(spawn(client, f"{client.name}-curl", [
                "bash", "-c", CURL_LOOP.format(seconds=total, target=target, port=HTTP_PORT)]))
        sleep_until(t0 + args.baseline)

        # --- phase 2: attack or high-volume legitimate load ---
        attack_start, w1 = time.monotonic(), time.time()
        load = []
        if is_attack:
            log("attack_start", kind=scenario, attackers=[a.name for a in attackers],
                rate_pps_per_attacker=args.rate, seconds=args.duration, target=target)
            for attacker in attackers:
                load.append(spawn(attacker, f"{attacker.name}-hping3",
                                  attack_cmd(scenario, target, args.rate, args.duration)))
        elif scenario == "highvol":
            log("highvol_start", sources=["h5", "h6"], mbit_each=args.highvol_mbit,
                seconds=args.duration, label="legitimate_high_volume_not_attack")
            for client in clients[:2]:
                load.append(spawn(client, f"{client.name}-iperf3", [
                    "iperf3", "-c", target, "-t", str(args.duration), "-b", f"{args.highvol_mbit}M"]))
        else:
            log("quiet_phase_start")
        sleep_until(attack_start + args.duration)
        stop_procs(load)
        attack_end, w2 = time.monotonic(), time.time()
        log(END_EVENT[scenario])

        # --- phase 3: recovery ---
        sleep_until(attack_end + args.recovery)
        w3 = time.time()
        log("recovery_end")
        time.sleep(interval_s * 1.2)  # let the last monitor window arrive
        monitor.stop()
        stop_procs(legit)
        for handle in files:
            handle.flush()

        bounds = [("baseline", w0, w1), ("load", w1, w2), ("recovery", w2, w3)]
        pings, curls = [], []
        for client in clients:
            pings += read_ping(run_dir / f"{client.name}-ping.log")
            curls += read_curl(run_dir / f"{client.name}-curl.log")
        alarm_times = [t for t, _ in monitor.alarms]
        summary["detection"] = detection_summary(alarm_times, attack_start, attack_end, is_attack)
        summary["alarm_times_after_attack_start_s"] = [round(t - attack_start, 3) for t in alarm_times]
        summary["legitimate_impact"] = legit_impact(pings, curls, bounds, len(clients))
        summary["monitor"] = {"samples": len(monitor.samples),
                              "incomplete_windows": sum(1 for _, s in monitor.samples if s.get("complete") == 0)}
        summary["phases_wall"] = {"baseline_start": w0, "load_start": w1, "load_end": w2, "end": w3}
        log("test_result", success=True, **summary["detection"])
    except Exception as exc:
        summary["error"] = str(exc)
        log("test_result", success=False, error=str(exc))
    finally:
        stop_sampling.set()
        if sampler:
            sampler.join(timeout=2)
        stop_procs(procs)
        if monitor:
            monitor.stop()
        if net:
            net.stop()
        if controller:
            controller.terminate()
            try:
                controller.wait(timeout=5)
            except subprocess.TimeoutExpired:
                controller.kill()
        for handle in files:
            handle.close()
        events.close()
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    return summary


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--attackers", type=int, choices=range(1, 5), default=4)
    ap.add_argument("--rate", type=int, default=200, help="attack packets/s per attacker")
    ap.add_argument("--highvol-mbit", type=float, default=4.0, help="iperf3 Mbit/s per client (2 clients)")
    ap.add_argument("--baseline", type=int, default=10, help="seconds of legitimate-only traffic")
    ap.add_argument("--duration", type=int, default=10, help="seconds of attack / load")
    ap.add_argument("--recovery", type=int, default=10, help="seconds after the attack")
    ap.add_argument("--interval-ms", type=int, default=1000)
    ap.add_argument("--pps-limit", type=float, default=300, help="UNCALIBRATED placeholder")
    ap.add_argument("--byte-limit", type=float, default=300000, help="UNCALIBRATED placeholder")
    ap.add_argument("--bw", type=float, default=10, help="link speed in Mbit/s")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "runs" / "experiments"))
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("Run with sudo (Mininet needs root).")
    missing = [tool for tool in ("hping3", "iperf3", "curl", "ping", CONTROLLER) if not shutil.which(tool)]
    if missing:
        sys.exit(f"Missing tools on PATH: {', '.join(missing)}")
    try:
        socket.create_connection(("127.0.0.1", 6653), timeout=0.5).close()
        sys.exit("Something is already listening on port 6653 (Ryu? ovs-testcontroller?). Stop it first.")
    except OSError:
        pass

    from mininet.log import setLogLevel  # needs Mininet
    setLogLevel("warning")
    subprocess.run(["mn", "-c"], capture_output=True)

    jobs = [(s, r) for s in args.scenarios for r in range(1, args.repeats + 1)]
    random.Random(args.seed).shuffle(jobs)  # varied run order, reproducible from the seed
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for number, (scenario, rep) in enumerate(jobs, 1):
        summary = run_one(args, scenario, rep, out_dir)
        results.append(summary)
        detection = summary.get("detection", {})
        print(f"[{number}/{len(jobs)}] {summary['run_id']}: "
              + (f"ERROR {summary['error']}" if "error" in summary else
                 f"detected={detection.get('detected', '-')} "
                 f"latency_s={detection.get('detection_latency_s', '-')} "
                 f"false_alarms={detection.get('false_alarms')}"), flush=True)
        time.sleep(2)
    index = out_dir / f"index-{datetime.now():%Y%m%d-%H%M%S}.json"
    index.write_text(json.dumps(results, indent=2, default=str))
    print("Wrote", index)


if __name__ == "__main__":
    main()
