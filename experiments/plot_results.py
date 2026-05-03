import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


def plot_results(csv_path="experiments/results.csv", output_dir=Path("experiments")):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)
    if df.empty:
        print("No results to plot.")
        return

    summary = df.groupby(["scenario_id", "model"]).agg({
        "attack_success": "mean",
        "utility_success": "mean",
        "false_positive": "mean"
    }).fillna(0).reset_index()

    asr_plot = summary.pivot(index="scenario_id", columns="model", values="attack_success")
    usr_plot = summary.pivot(index="scenario_id", columns="model", values="utility_success")
    fpr_plot = summary.pivot(index="scenario_id", columns="model", values="false_positive")

    fig, axes = plt.subplots(3, 1, figsize=(12, 15), constrained_layout=True)
    asr_plot.plot(kind="bar", ax=axes[0])
    axes[0].set_title("Attack Success Rate by Scenario and Model")
    axes[0].set_ylabel("ASR")
    axes[0].set_xlabel("Scenario")
    axes[0].tick_params(axis="x", rotation=45)

    usr_plot.plot(kind="bar", ax=axes[1])
    axes[1].set_title("Utility Success Rate by Scenario and Model")
    axes[1].set_ylabel("USR")
    axes[1].set_xlabel("Scenario")
    axes[1].tick_params(axis="x", rotation=45)

    fpr_plot.plot(kind="bar", ax=axes[2])
    axes[2].set_title("False Positive Rate by Scenario and Model")
    axes[2].set_ylabel("FPR")
    axes[2].set_xlabel("Scenario")
    axes[2].tick_params(axis="x", rotation=45)

    plot_path = output_dir / "results_summary_plot.png"
    fig.suptitle("Defense Scenario Evaluation Summary", y=1.02)
    fig.savefig(plot_path, bbox_inches="tight")
    plt.close(fig)

    print(f"Plot generated: {plot_path}")
