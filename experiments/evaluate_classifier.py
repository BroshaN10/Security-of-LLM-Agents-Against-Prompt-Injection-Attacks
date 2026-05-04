import json
import csv
import sys
from pathlib import Path
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score
import numpy as np

# Add workspace root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agent import process_query
from app.config import CLASSIFIER_MODEL

CASES_FILE = Path("experiments/pipeline_test_inputs.json")
RESULTS_JSON = Path("experiments/correlation_results.json")
RESULTS_CSV = Path("experiments/correlation_results.csv")

def run_evaluation():
    """
    Run classifier on test inputs, compare predictions vs ground truth, compute metrics.
    """
    cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
    results = []
    predictions = []
    ground_truths = []

    print(f"\n===== CLASSIFIER EVALUATION =====")
    print(f"Running {len(cases)} test cases...\n")

    for i, case in enumerate(cases, 1):
        user = case.get("user", "anonymous")
        message = case.get("message", "")
        ground_truth = case.get("isMalicious", -1)  # -1 = unknown
        description = case.get("description", "")

        # Call the classifier directly
        res = process_query(
            user_input=message,
            user=user,
            model=CLASSIFIER_MODEL,
            enable_intent_classifier=True,
            enable_rbac=False,
            enable_arg_filter=False
        )

        # Extract classifier's malicious prediction
        classification = res.get("classification", {})
        predicted_malicious = classification.get("malicious", -1)

        # Record result
        results.append({
            "case_id": i,
            "user": user,
            "message": message,
            "description": description,
            "ground_truth": ground_truth,
            "predicted_malicious": predicted_malicious,
            "response_status": res.get("status"),
            "blocked": 1 if res.get("status") == "blocked" else 0,
            "match": 1 if predicted_malicious == ground_truth else 0
        })

        if ground_truth >= 0 and predicted_malicious >= 0:
            predictions.append(predicted_malicious)
            ground_truths.append(ground_truth)

        match_str = "✓" if predicted_malicious == ground_truth else "✗"
        print(f"{i}. {match_str} | GT: {ground_truth} | PRED: {predicted_malicious} | {description}")

    # Compute confusion matrix and metrics
    if predictions and ground_truths:
        tn, fp, fn, tp = confusion_matrix(ground_truths, predictions).ravel()
        accuracy = accuracy_score(ground_truths, predictions)
        precision = precision_score(ground_truths, predictions, zero_division=0)
        recall = recall_score(ground_truths, predictions, zero_division=0)
        f1 = f1_score(ground_truths, predictions, zero_division=0)

        print(f"\n===== CORRELATION MATRIX =====")
        print(f"True Negatives (TN):  {tn}")
        print(f"False Positives (FP): {fp}")
        print(f"False Negatives (FN): {fn}")
        print(f"True Positives (TP):  {tp}")
        print(f"\n===== METRICS =====")
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1-Score:  {f1:.4f}")

        metrics = {
            "total_cases": len(results),
            "evaluated_cases": len(predictions),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1)
        }
    else:
        print("\n[ERROR] Not enough valid predictions to compute metrics")
        metrics = {}

    # Save results
    RESULTS_JSON.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_JSON.open("w", encoding="utf-8") as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)

    with RESULTS_CSV.open("w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "case_id", "user", "message", "description", 
            "ground_truth", "predicted_malicious", "response_status", "blocked", "match"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"\n[SAVED] Results to {RESULTS_JSON} and {RESULTS_CSV}")
    return results, metrics

if __name__ == "__main__":
    run_evaluation()
