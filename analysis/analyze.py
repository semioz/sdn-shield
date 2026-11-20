
import argparse
import csv
import json
import math
import statistics
from pathlib import Path

ATTACKS = ("syn", "udp", "icmp")
ORDER = ("syn", "udp", "icmp", "normal", "highvol")
START_EVENTS = ("attack_start", "highvol_start", "quiet_phase_start")
END_EVENTS = ("attack_end", "highvol_end", "quiet_phase_end")
BOUNDARY_FRACTION = 0.5
DETECTORS = {"threshold": "alarm_threshold"}  # name -> column in windows.csv (add entropy / ml later)
PHASES = ("baseline", "load", "recovery")

# chart colours (validated light-mode categorical slots 1-3, see dataviz palette)
SURFACE, INK, SECONDARY, GRID, SHADE = "#fcfcfb", "#0b0b0b", "#52514e", "#e3e2de", "#ecebe7"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"


# ---------- loading ----------

def load_run(run_dir):
    path = run_dir / "events.jsonl"
    if not path.exists():
        return None
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def first(names):
        return next((e for e in events if e["event"] in names), None)

    start, end = first(START_EVENTS), first(END_EVENTS)
    result = next((e for e in reversed(events) if e["event"] == "test_result"), None)
    config = next((e.get("config", {}) for e in events if e["event"] == "run_start"), {})
    if not (start and end and result and result.get("success")):
        print(f"  skipped {run_dir.name}: run did not finish successfully")
        return None
    scenario = config.get("scenario") or run_dir.name.split("-")[0]
    summary_path = run_dir / "summary.json"
    return {
        "dir": run_dir, "run_id": run_dir.name, "scenario": scenario, "rep": config.get("rep"),
        "config": config, "events": events, "is_attack": scenario in ATTACKS,
        "load_start": start["t_mono"], "load_end": end["t_mono"],
        "summary": json.loads(summary_path.read_text()) if summary_path.exists() else {},
    }


def window_rows(run, victim_mac):
    a0, a1 = run["load_start"], run["load_end"]
    rows = []
    for e in run["events"]:
        if e["event"] != "sample" or e.get("destination") != victim_mac:
            continue
        t_end = e["t_mono"]
        length = e["elapsed_seconds"]
        t_start = t_end - length
        overlap = max(0.0, min(t_end, a1) - max(t_start, a0))
        if run["is_attack"]:
            fraction = overlap / length
            label = "attack" if fraction >= BOUNDARY_FRACTION else ("normal" if overlap == 0 else "boundary")
        else:
            label = "normal"
        middle = (t_start + t_end) / 2
        phase = "baseline" if middle < a0 else ("load" if middle <= a1 else "recovery")
        rows.append({
            "run_id": run["run_id"], "scenario": run["scenario"], "rep": run["rep"],
            "window": e["window"], "t_start": round(t_start - a0, 3), "t_end": round(t_end - a0, 3),
            "phase": phase, "label": label,
            "packets": e["packets"], "bytes": e["bytes"],
            "pps": e["packets_per_second"], "bps": e["bytes_per_second"],
            "source_count": e.get("source_count", 0),
            "source_entropy_bits": e.get("source_entropy_bits"),
            "compared": e["compared"], "new": e["new"], "reset": e["reset"],
            "unsupported": e["unsupported"], "expired": e["expired"], "complete": e["complete"],
            "alarm_threshold": e["alarm"],
        })
    return rows


def detection_latency(run, victim_mac):
    """Seconds from attack start to the first threshold alarm on the victim during the attack."""
    if not run["is_attack"]:
        return None
    times = [e["t_mono"] for e in run["events"]
             if e["event"] == "threshold_alarm" and e.get("destination") == victim_mac
             and run["load_start"] <= e["t_mono"] <= run["load_end"]]
    return round(min(times) - run["load_start"], 3) if times else None


def read_resources(path):
    if not path.exists():
        return None
    cpu, rss = [], []
    with path.open() as handle:
        for row in csv.DictReader(handle):
            cpu.append(float(row["cpu_percent"]))
            rss.append(float(row["rss_kb"]))
    if not cpu:
        return None
    return {"cpu_avg": statistics.mean(cpu), "cpu_peak": max(cpu), "rss_peak_kb": max(rss)}


# ---------- metrics ----------

def confusion(rows, column):
    tp = fp = tn = fn = 0
    for row in rows:
        if row["label"] == "boundary":
            continue
        alarm = row[column] == 1
        if row["label"] == "attack":
            tp += alarm
            fn += not alarm
        else:
            fp += alarm
            tn += not alarm
    return tp, fp, tn, fn


def rates(tp, fp, tn, fn):
    def div(a, b):
        return round(a / b, 4) if b else None
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 0.0 if precision + recall == 0 else round(2 * precision * recall / (precision + recall), 4)
    return {"accuracy": div(tp + tn, tp + fp + tn + fn), "precision": precision,
            "recall": recall, "f1": f1, "fpr": div(fp, fp + tn)}


def med(values):
    values = [v for v in values if v is not None]
    return round(statistics.median(values), 3) if values else None


def fmt(value, digits=3):
    return "-" if value is None else (f"{value:.{digits}f}" if isinstance(value, float) else str(value))


def print_table(title, headers, rows):
    print(f"\n{title}")
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    print("  " + "  ".join(str(h).ljust(w) for h, w in zip(headers, widths)))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        print("  " + "  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def write_csv(path, rows, fields=None):
    if not rows:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields or list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# ---------- charts ----------

def make_charts(out_dir, by_run, durations, legit, limit):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib is not installed here - charts skipped. "
              "Use ~/sdn-shield/.venv/bin/python analysis/analyze.py (that environment has it).")
        return
    scenarios = [s for s in ORDER if s in by_run]
    caption = {"syn": "SYN flood", "udp": "UDP flood", "icmp": "ICMP flood",
               "normal": "normal traffic only", "highvol": "high-volume legitimate load"}
    shade_label = {"syn": "attack", "udp": "attack", "icmp": "attack",
                   "normal": "quiet", "highvol": "load"}

    def style(ax):
        ax.set_facecolor(SURFACE)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(GRID)
        ax.tick_params(colors=SECONDARY, labelsize=9)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)

    # 1) traffic at the victim over time, one small panel per scenario
    cols = min(3, len(scenarios))
    rows = math.ceil(len(scenarios) / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(4.2 * cols, 3.3 * rows), sharey=True,
                             facecolor=SURFACE, squeeze=False)
    for ax in axes.flat:
        style(ax)
    for ax, scenario in zip(axes.flat, scenarios):
        ax.axvspan(0, durations[scenario], color=SHADE, zorder=0)
        for rws in by_run[scenario].values():
            ax.plot([r["t_end"] for r in rws], [r["pps"] for r in rws], color=BLUE,
                    linewidth=1.5, alpha=0.85, zorder=2)
        ax.axhline(limit, color=SECONDARY, linestyle="--", linewidth=1, zorder=1)
        ax.text(0.99, limit, f"limit {limit:g}/s", transform=ax.get_yaxis_transform(),
                ha="right", va="bottom", fontsize=8, color=SECONDARY)
        ax.text(durations[scenario] / 2, 0.72, shade_label[scenario], transform=ax.get_xaxis_transform(),
                ha="center", va="center", fontsize=8, color=SECONDARY)
        ax.set_title(caption[scenario], loc="left", fontsize=10, color=INK)
        ax.set_xlabel("seconds from attack/load start", fontsize=9, color=SECONDARY)
    for ax in axes[:, 0]:
        ax.set_ylabel("packets/s to the victim", fontsize=9, color=SECONDARY)
    for ax in list(axes.flat)[len(scenarios):]:
        ax.set_visible(False)
    fig.suptitle("Traffic reaching the victim per 1-second window (one line per run)",
                 x=0.01, ha="left", fontsize=12, color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(out_dir / "pps_timeline.png", dpi=150, facecolor=SURFACE)
    plt.close(fig)

    # 2) legitimate-user success (HTTP fetches) per phase
    if legit:
        names = [s for s in ORDER if s in legit]
        fig, ax = plt.subplots(figsize=(9, 4), facecolor=SURFACE)
        style(ax)
        width = 0.26
        for k, (phase, colour) in enumerate(zip(PHASES, (BLUE, ORANGE, AQUA))):
            xs = [i + (k - 1) * width for i in range(len(names))]
            ys = [legit[s].get(phase) for s in names]
            bars = ax.bar(xs, [y or 0 for y in ys], width=width * 0.92, color=colour,
                          edgecolor=SURFACE, linewidth=2, label=phase, zorder=2)
            for bar, y in zip(bars, ys):
                if y is not None:
                    ax.text(bar.get_x() + bar.get_width() / 2, y + 1.5, f"{y:.0f}", ha="center",
                            va="bottom", fontsize=8, color=INK)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels([caption[s] for s in names], fontsize=9)
        ax.set_ylim(0, 112)
        ax.set_ylabel("legitimate HTTP requests that succeeded (%)", fontsize=9, color=SECONDARY)
        ax.set_title("Legitimate users during each phase (median over runs)", loc="left", fontsize=11, color=INK)
        ax.legend(frameon=False, fontsize=9, loc="lower left", ncol=3, bbox_to_anchor=(0, -0.28))
        fig.tight_layout()
        fig.savefig(out_dir / "legit_impact.png", dpi=150, facecolor=SURFACE)
        plt.close(fig)


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs_dir", nargs="?", default="runs/experiments")
    ap.add_argument("--victim-mac", default="00:00:00:00:00:08")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    runs_dir = Path(args.runs_dir)
    out_dir = Path(args.out) if args.out else runs_dir / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    runs = [r for r in (load_run(d) for d in sorted(runs_dir.iterdir()) if d.is_dir() and d.name != "analysis") if r]
    if not runs:
        raise SystemExit(f"No finished runs found in {runs_dir}")
    print(f"Loaded {len(runs)} runs from {runs_dir}")

    all_rows, by_run, durations = [], {}, {}
    per_scenario = {}
    for run in runs:
        rows = window_rows(run, args.victim_mac)
        all_rows += rows
        s = run["scenario"]
        by_run.setdefault(s, {})[run["run_id"]] = rows
        durations[s] = run["load_end"] - run["load_start"]
        per_scenario.setdefault(s, []).append((run, rows))
    write_csv(out_dir / "windows.csv", all_rows)

   
    # detection metrics
    metric_rows = []
    table = []

    for detector_name, column in DETECTORS.items():
        for s in [x for x in ORDER if x in per_scenario]:
            tp = fp = tn = fn = 0
            latencies = []
            missed = 0
            windows_incomplete = 0

            for run, rows in per_scenario[s]:
                a, b, c, d = confusion(rows, column)
                tp += a
                fp += b
                tn += c
                fn += d

                windows_incomplete += sum(
                    1 for row in rows if row["complete"] == 0
                )

                if run["is_attack"]:
                    latency = detection_latency(run, args.victim_mac)
                    if latency is None:
                        missed += 1
                    else:
                        latencies.append(latency)

            r = rates(tp, fp, tn, fn)
            n_runs = len(per_scenario[s])

            record = {
                "detector": detector_name,
                "scenario": s,
                "runs": n_runs,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                **r,
                "latency_median_s": med(latencies),
                "latency_min_s": min(latencies) if latencies else None,
                "latency_max_s": max(latencies) if latencies else None,
                "missed_attacks": missed if s in ATTACKS else None,
                "incomplete_windows": windows_incomplete,
            }

            metric_rows.append(record)

            table.append([
                s,
                n_runs,
                tp,
                fp,
                tn,
                fn,
                fmt(r["accuracy"]),
                fmt(r["precision"]),
                fmt(r["recall"]),
                fmt(r["f1"]),
                fmt(r["fpr"]),
                fmt(record["latency_median_s"]),
                fmt(record["missed_attacks"]),
                windows_incomplete,
            ])

    write_csv(out_dir / "metrics.csv", metric_rows)

    print_table(
        "Detection (windows at the victim; boundary windows excluded; pooled over runs)",
        [
            "scenario", "runs", "TP", "FP", "TN", "FN",
            "acc", "prec", "recall", "F1", "FPR",
            "latency_med_s", "missed", "incompl"
        ],
        table,
    )

    # legitimate-user impact (median over runs of the per-run rate)
    legit = {}
    table = []

    for s in [x for x in ORDER if x in per_scenario]:
        legit[s] = {}
        line = [s]

        for phase in PHASES:
            ok_rates = []
            losses = []
            rtts = []

            for run, _ in per_scenario[s]:
                p = run["summary"].get("legitimate_impact", {}).get(phase)

                if not p:
                    continue

                if p["curl_total"]:
                    ok_rates.append(
                        100 * p["curl_ok"] / p["curl_total"]
                    )

                losses.append(p["ping_loss"])
                rtts.append(p["ping_mean_rtt_ms"])

            legit[s][phase] = med(ok_rates)

            line += [
                fmt(med(ok_rates), 0),
                fmt(med([100 * x for x in losses if x is not None]), 1),
                fmt(med(rtts), 2),
            ]

        table.append(line)

    headers = ["scenario"] + [
        f"{p}:{m}"
        for p in PHASES
        for m in ("http_ok%", "ping_loss%", "rtt_ms")
    ]

    print_table(
        "Legitimate users (median over runs; ping loss is approximate)",
        headers,
        table,
    )

    # controller resources
    resource_rows = []
    table = []

    for s in [x for x in ORDER if x in per_scenario]:
        res = [
            read_resources(run["dir"] / "resources.csv")
            for run, _ in per_scenario[s]
        ]

        res = [r for r in res if r]

        if res:
            row = {
                "scenario": s,
                "cpu_avg_percent": med([r["cpu_avg"] for r in res]),
                "cpu_peak_percent": med([r["cpu_peak"] for r in res]),
                "rss_peak_mb": med([r["rss_peak_kb"] / 1024 for r in res]),
            }

            resource_rows.append(row)

            table.append([
                s,
                fmt(row["cpu_avg_percent"], 2),
                fmt(row["cpu_peak_percent"], 2),
                fmt(row["rss_peak_mb"], 2),
            ])

    write_csv(out_dir / "resources.csv", resource_rows)

    print_table(
        "Rust forwarding controller resources (median over runs)",
        ["scenario", "cpu_avg%", "cpu_peak%", "rss_peak_MB"],
        table,
    )

    limit = next(
        (
            r["config"].get("pps_limit")
            for r in runs
            if r["config"].get("pps_limit")
        ),
        0,
    )

    make_charts(out_dir, by_run, durations, legit, limit)

    print(f"\nWrote files to {out_dir}")



if __name__ == "__main__":
    main()
