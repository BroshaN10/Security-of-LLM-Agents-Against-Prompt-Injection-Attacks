import argparse
import csv
import json
from pathlib import Path

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
from experiments.plot_results import plot_results

SCENARIO_PATH = Path("experiments/defense_scenarios.json")
RESULTS_JSON = Path("experiments/results.json")
RESULTS_CSV = Path("experiments/results.csv")
SUMMARY_JSON = Path("experiments/results_summary.json")


def load_scenarios(path=SCENARIO_PATH):
    if path.exists():
        content = json.loads(path.read_text(encoding="utf-8"))
        scenarios = content.get("scenarios", [])
        for scenario in scenarios:
            if scenario.get("id") is None:
                toggles = scenario.get("toggles", {})
                scenario["id"] = (
                    f"intent_classifier_{toggles.get('ENABLE_INTENT_CLASSIFIER')}_"
                    f"rbac_{toggles.get('ENABLE_RBAC')}_"
                    f"arg_filter_{toggles.get('ENABLE_ARG_FILTER')}"
                )
        return scenarios

    return [
        {
            "id": "intent_classifier_off_rbac_off_arg_filter_off",
            "toggles": {
                "ENABLE_INTENT_CLASSIFIER": False,
                "ENABLE_RBAC": False,
                "ENABLE_ARG_FILTER": False
            },
            "description": "No defenses enabled."
        },
        {
            "id": "intent_classifier_off_rbac_on_arg_filter_on",
            "toggles": {
                "ENABLE_INTENT_CLASSIFIER": False,
                "ENABLE_RBAC": True,
                "ENABLE_ARG_FILTER": True
            },
            "description": "RBAC and argument filtering enabled."
        },
    ]


def run_experiment(scenario, models):
    attacks = generate_all_attacks()
    results = []
    summaries = []

    print(f"\n===== SCENARIO: {scenario['id']} =====")
    print(f"toggles={scenario['toggles']}\n")

    for model in models:
        print(f"\n===== MODEL: {model} =====")

        attack_success = 0
        utility_success = 0
        false_positive = 0
        classifier_blocks = 0
        rbac_blocks = 0

        for category, attack in attacks:
            res = process_query(
                attack,
                role="user",
                model=model,
                enable_intent_classifier=scenario["toggles"]["ENABLE_INTENT_CLASSIFIER"],
                enable_rbac=scenario["toggles"]["ENABLE_RBAC"],
                enable_arg_filter=scenario["toggles"]["ENABLE_ARG_FILTER"]
            )

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
                "scenario_id": scenario["id"],
                "enable_intent_classifier": scenario["toggles"]["ENABLE_INTENT_CLASSIFIER"],
                "enable_rbac": scenario["toggles"]["ENABLE_RBAC"],
                "enable_arg_filter": scenario["toggles"]["ENABLE_ARG_FILTER"],
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

        for task in UTILITY_TASKS:
            res = process_query(
                task,
                role="user",
                model=model,
                enable_intent_classifier=scenario["toggles"]["ENABLE_INTENT_CLASSIFIER"],
                enable_rbac=scenario["toggles"]["ENABLE_RBAC"],
                enable_arg_filter=scenario["toggles"]["ENABLE_ARG_FILTER"]
            )

            util_flag = is_utility_success(res)
            fp_flag = is_false_positive(res)

            if util_flag:
                utility_success += 1
            if fp_flag:
                false_positive += 1

            results.append({
                "scenario_id": scenario["id"],
                "enable_intent_classifier": scenario["toggles"]["ENABLE_INTENT_CLASSIFIER"],
                "enable_rbac": scenario["toggles"]["ENABLE_RBAC"],
                "enable_arg_filter": scenario["toggles"]["ENABLE_ARG_FILTER"],
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

        total_attacks = len(attacks)
        total_utility = len(UTILITY_TASKS)
        ASR = attack_success / total_attacks if total_attacks else 0.0
        USR = utility_success / total_utility if total_utility else 0.0
        FPR = false_positive / total_utility if total_utility else 0.0

        print(f"{model} ASR (attacks that succeeded): {ASR:.2f}")
        print(f"{model} USR (utility tasks passed):   {USR:.2f}")
        print(f"{model} FPR (legit requests blocked): {FPR:.2f}")
        print(f"{model} Blocked by classifier:        {classifier_blocks}/{len(attacks)}")
        print(f"{model} Blocked by RBAC:              {rbac_blocks}/{len(attacks)}")

        summaries.append({
            "scenario_id": scenario["id"],
            "model": model,
            "enable_intent_classifier": scenario["toggles"]["ENABLE_INTENT_CLASSIFIER"],
            "enable_rbac": scenario["toggles"]["ENABLE_RBAC"],
            "enable_arg_filter": scenario["toggles"]["ENABLE_ARG_FILTER"],
            "ASR": ASR,
            "USR": USR,
            "FPR": FPR,
            "blocked_by_classifier": classifier_blocks,
            "blocked_by_rbac": rbac_blocks
        })

    return results, summaries


def save_results(results, csv_path=RESULTS_CSV, json_path=RESULTS_JSON):
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    fieldnames = [
        "scenario_id",
        "enable_intent_classifier",
        "enable_rbac",
        "enable_arg_filter",
        "type",
        "category",
        "model",
        "input",
        "response",
        "attack_success",
        "blocked_by_classifier",
        "blocked_by_rbac",
        "utility_success",
        "false_positive"
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)


def save_summary(summaries, path=SUMMARY_JSON):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(summaries, f, indent=4)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the helpdesk attack/utility evaluation pipeline with defense scenario toggles and create summary plots."
    )
    parser.add_argument(
        "--scenario",
        nargs="+",
        help="One or more scenario ids from experiments/defense_scenarios.json to run. Omit to run all scenarios."
    )
    parser.add_argument(
        "--no-plot",
        dest="plot",
        action="store_false",
        help="Disable plot generation after running the evaluation."
    )
    parser.add_argument(
        "--output-dir",
        default="experiments",
        help="Directory to write results and plots."
    )
    return parser.parse_args()


def main():
    args = parse_args()
    scenarios = load_scenarios()

    if args.scenario:
        scenario_ids = set(args.scenario)
        scenarios = [s for s in scenarios if s["id"] in scenario_ids]
        if not scenarios:
            raise ValueError(f"No matching scenarios found for ids: {args.scenario}")

    all_results = []
    all_summaries = []

    for scenario in scenarios:
        results, summaries = run_experiment(scenario, MODELS)
        all_results.extend(results)
        all_summaries.extend(summaries)

    save_results(all_results, RESULTS_CSV, RESULTS_JSON)
    save_summary(all_summaries, SUMMARY_JSON)

    if args.plot:
        plot_results(csv_path=RESULTS_CSV, output_dir=Path(args.output_dir))

    print(f"\nPipeline complete. Results saved to {RESULTS_JSON} and {RESULTS_CSV}.")
    print(f"Summary saved to {SUMMARY_JSON}.")
    if args.plot:
        print(f"Plots saved to {args.output_dir}")


if __name__ == "__main__":
    main()
