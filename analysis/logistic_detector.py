
import csv
import sys
from collections import defaultdict
from pathlib import Path

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

INPUT = Path("runs/experiments/analysis/windows.csv")
OUTPUT = Path("runs/experiments/analysis")

FEATURES = ["packets", "bytes", "pps", "bps"]
SCENARIOS = ("syn", "udp", "icmp", "normal", "highvol")


def main():
    if not INPUT.exists():
        sys.exit(f"Cannot find {INPUT}. Run analysis/analyze.py first.")

    with INPUT.open(newline="") as handle:
        rows = list(csv.DictReader(handle))

    # Keep only complete, clearly labelled windows.
    rows = [
        row for row in rows
        if row["complete"] == "1"
        and row["label"] in ("normal", "attack")
        and row["scenario"] in SCENARIOS
    ]

    if not rows:
        sys.exit("No usable labelled windows found.")

    # Hold out the highest-repetition run in each scenario.
    runs_by_scenario = defaultdict(set)
    for row in rows:
        runs_by_scenario[row["scenario"]].add(row["run_id"])

    test_runs = set()
    for scenario, run_ids in runs_by_scenario.items():
        def run_order(run_id):
            matching = next(r for r in rows if r["run_id"] == run_id)
            return (int(matching["rep"]), run_id)

        selected = max(run_ids, key=run_order)
        test_runs.add(selected)

    train_rows = [r for r in rows if r["run_id"] not in test_runs]
    test_rows = [r for r in rows if r["run_id"] in test_runs]

    if not train_rows or not test_rows:
        sys.exit("Training or test data is empty.")

    def features(data):
        return [[float(row[name]) for name in FEATURES] for row in data]

    def labels(data):
        return [1 if row["label"] == "attack" else 0 for row in data]

    y_train = labels(train_rows)
    y_test = labels(test_rows)

    if len(set(y_train)) != 2:
        sys.exit("Training data must contain both normal and attack windows.")

    # Scaling is fitted only on training data, preventing test-data leakage.
    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42),
    )
    model.fit(features(train_rows), y_train)

    predictions = model.predict(features(test_rows))
    probabilities = model.predict_proba(features(test_rows))[:, 1]

    print("LOGISTIC REGRESSION — UNSEEN-RUN TEST")
    print("-------------------------------------")
    print("Features:", ", ".join(FEATURES))
    print("Training runs:", len(set(r["run_id"] for r in train_rows)))
    print("Testing runs:", len(test_runs))
    print("Held-out runs:")
    for run_id in sorted(test_runs):
        print(" ", run_id)

    print("\nOverall test results")
    print("Accuracy: ", round(accuracy_score(y_test, predictions), 4))
    print("Precision:", round(precision_score(y_test, predictions, zero_division=0), 4))
    print("Recall:   ", round(recall_score(y_test, predictions, zero_division=0), 4))
    print("F1:       ", round(f1_score(y_test, predictions, zero_division=0), 4))

    print("\nPer-scenario test results")
    print("scenario  TP  FP  TN  FN  accuracy  precision  recall  F1")

    metric_rows = []
    for scenario in SCENARIOS:
        indexes = [i for i, row in enumerate(test_rows) if row["scenario"] == scenario]
        if not indexes:
            continue

        actual = [y_test[i] for i in indexes]
        predicted = [predictions[i] for i in indexes]
        tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()

        record = {
            "detector": "logistic_regression",
            "scenario": scenario,
            "test_runs": len({test_rows[i]["run_id"] for i in indexes}),
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "accuracy": round(accuracy_score(actual, predicted), 4),
            "precision": round(precision_score(actual, predicted, zero_division=0), 4),
            "recall": round(recall_score(actual, predicted, zero_division=0), 4),
            "f1": round(f1_score(actual, predicted, zero_division=0), 4),
        }
        metric_rows.append(record)

        print(
            f"{scenario:<9} {tp:<3} {fp:<3} {tn:<3} {fn:<3} "
            f"{record['accuracy']:<9} {record['precision']:<10} "
            f"{record['recall']:<7} {record['f1']}"
        )

    OUTPUT.mkdir(parents=True, exist_ok=True)

    with (OUTPUT / "logistic_metrics.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(metric_rows[0]))
        writer.writeheader()
        writer.writerows(metric_rows)

    prediction_rows = []
    for i, row in enumerate(test_rows):
        prediction_rows.append({
            "run_id": row["run_id"],
            "scenario": row["scenario"],
            "true_label": row["label"],
            "predicted_label": "attack" if predictions[i] else "normal",
            "attack_probability": round(float(probabilities[i]), 6),
        })

    with (OUTPUT / "logistic_predictions.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(prediction_rows[0]))
        writer.writeheader()
        writer.writerows(prediction_rows)

    print("\nSaved:")
    print(OUTPUT / "logistic_metrics.csv")
    print(OUTPUT / "logistic_predictions.csv")


if __name__ == "__main__":
    main()
