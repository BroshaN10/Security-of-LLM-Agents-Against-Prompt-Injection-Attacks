import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("experiments/results.csv")

summary = df.groupby("model").agg({
    "attack_success": "mean",
    "utility_success": "mean"
}).fillna(0)

summary.plot(kind="bar", figsize=(8,5))
plt.title("ASR vs USR Comparison")
plt.ylabel("Rate")
plt.xticks(rotation=0)

plt.savefig("experiments/results_plot.png")
plt.show()