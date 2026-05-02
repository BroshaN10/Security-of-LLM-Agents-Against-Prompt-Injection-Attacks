import json
import csv
from datetime import datetime

from app.agent import process_query
from app.config import MODELS
from experiments.attacks import generate_all_attacks
from experiments.utility import UTILITY_TASKS
from experiments.metrics import (
    is_attack_success,
    is_utility_success,
    is_false_positive
)

attacks = generate_all_attacks()

results = []

for model in MODELS:
    print(f"\n===== MODEL: {model} =====")

    attack_success = 0
    utility_success = 0
    false_positive = 0

    # --- ATTACK TESTING ---
    for category, attack in attacks:
        res = process_query(attack, role="user", model=model)

        attack_flag = is_attack_success(res)

        if attack_flag:
            attack_success += 1

        results.append({
            "type": "attack",
            "category": category,
            "model": model,
            "input": attack,
            "response": str(res),
            "attack_success": attack_flag,
            "utility_success": None,
            "false_positive": None
        })

    # --- UTILITY TESTING ---
    for task in UTILITY_TASKS:
        res = process_query(task, role="user", model=model)

        util_flag = is_utility_success(res)
        fp_flag = is_false_positive(res)

        if util_flag:
            utility_success += 1
        if fp_flag:
            false_positive += 1

        results.append({
            "type": "utility",
            "category": None,
            "model": model,
            "input": task,
            "response": str(res),
            "attack_success": None,
            "utility_success": util_flag,
            "false_positive": fp_flag
        })
    ASR = attack_success / len(attacks)
    USR = utility_success / len(UTILITY_TASKS)
    FPR = false_positive / len(UTILITY_TASKS)

    print(f"{model} ASR: {ASR}")
    print(f"{model} USR: {USR}")
    print(f"{model} FPR: {FPR}")

# Save JSON
with open("experiments/results.json", "w") as f:
    json.dump(results, f, indent=4)

# Save CSV
FIELDNAMES = [
    "type",
    "category",
    "model",
    "input",
    "response",
    "attack_success",
    "utility_success",
    "false_positive"
]
with open("experiments/results.csv", "w", newline="") as f:
    for row in results:
     for field in FIELDNAMES:
        if field not in row:
            row[field] = None
    writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(results)

print("\nResults saved.")