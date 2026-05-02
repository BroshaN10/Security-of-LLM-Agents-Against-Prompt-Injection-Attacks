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
    is_false_positive,
    blocked_by_classifier,
    blocked_by_rbac
)

attacks = generate_all_attacks()

results = []

for model in MODELS:
    print(f"\n===== MODEL: {model} =====")

    attack_success = 0
    utility_success = 0
    false_positive = 0
    classifier_blocks = 0
    rbac_blocks = 0

    # --- ATTACK TESTING ---
    for category, attack in attacks:
        res = process_query(attack, role="user", model=model)

        attack_flag = is_attack_success(res)
        clf_blocked = blocked_by_classifier(res)
        rbac_blocked = blocked_by_rbac(res)

        if attack_flag:
            attack_success += 1
        if clf_blocked:
            classifier_blocks += 1
        if rbac_blocked:
            rbac_blocks += 1

        results.append({
            "type": "attack",
            "category": category,
            "model": model,
            "input": attack,
            "response": str(res),
            "attack_success": attack_flag,
            "blocked_by_classifier": clf_blocked,
            "blocked_by_rbac": rbac_blocked,
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
            "blocked_by_classifier": False,
            "blocked_by_rbac": False,
            "utility_success": util_flag,
            "false_positive": fp_flag
        })

    ASR = attack_success / len(attacks)
    USR = utility_success / len(UTILITY_TASKS)
    FPR = false_positive / len(UTILITY_TASKS)

    print(f"{model} ASR (attacks that succeeded): {ASR:.2f}")
    print(f"{model} USR (utility tasks passed):   {USR:.2f}")
    print(f"{model} FPR (legit requests blocked): {FPR:.2f}")
    print(f"{model} Blocked by classifier:        {classifier_blocks}/{len(attacks)}")
    print(f"{model} Blocked by RBAC:              {rbac_blocks}/{len(attacks)}")

# Save JSON
with open("experiments/results.json", "w") as f:
    json.dump(results, f, indent=4)

# Save CSV
FIELDNAMES = [
    "type", "category", "model", "input", "response",
    "attack_success", "blocked_by_classifier", "blocked_by_rbac",
    "utility_success", "false_positive"
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