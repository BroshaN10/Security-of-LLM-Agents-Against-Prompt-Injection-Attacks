# Security of LLM Agents Against Prompt Injection Attacks

An empirical study of prompt injection, intent ambiguity, and layered defenses in an LLM-powered IT helpdesk assistant.

This repository is the implementation and evaluation harness for a research project that studies how a helpdesk agent behaves when exposed to malicious prompts and ambiguous but legitimate requests. It is designed to support paper writing by making the system architecture, methodology, metrics, and findings explicit and reproducible.

## Research Snapshot

- Models evaluated: `llama3` and `mistral-small3.2`
- Defense layers: intent classifier, RBAC, and argument filtering
- Scenarios tested: 8 defense combinations
- Attack prompts: 10 across direct, indirect, confusion, multi-step, and jailbreak styles
- Legitimate tasks: 6 usability-oriented helpdesk requests
- Core metrics: Attack Success Rate (ASR), Utility Success Rate (USR), and False Positive Rate (FPR)

## Main Findings

Across the current evaluation runs, the system shows a clear safety-utility tradeoff:

- With no defenses enabled, some attacks succeed on both tested models.
- RBAC and the intent classifier each reduce observed attack success to zero in this benchmark, but both materially reduce utility and increase false positives.
- Argument filtering alone is not sufficient as a primary defense.
- The strongest balance in these runs came from RBAC plus argument filtering, which kept ASR at zero while preserving more utility than the full stack.
- Enabling all defenses did not improve over RBAC plus argument filtering on this dataset because the classifier introduced additional blocking without improving attack resistance further.

## Reproducible Outputs

The evaluation pipeline writes the following artifacts to `experiments/`:

- `results.json` - detailed per-request outputs
- `results.csv` - tabular results for analysis
- `results_summary.json` - per-scenario summary metrics
- `results_summary_plot.png` - comparison plot

## How To Reproduce

Run the full evaluation pipeline:

```bash
py -m experiments.run_full_eval
```

Run specific scenarios:

```bash
py -m experiments.run_full_eval --scenario intent_classifier_off_rbac_on_arg_filter_on
```

Skip plot generation:

```bash
py -m experiments.run_full_eval --no-plot
```

## Documentation

- [README_TECHNICAL.md](README_TECHNICAL.md) - architecture, metrics, methodology, and results interpretation
- [README_SIMPLE.md](README_SIMPLE.md) - plain-language project overview

## Suggested Paper Use

Use this repository to support the following paper sections:

- Introduction: why prompt injection matters for tool-using helpdesk assistants
- Methods: system design, defenses, evaluation scenarios, and metrics
- Results: attack resistance versus usability tradeoffs
- Discussion: why layered controls help, where they fail, and what still needs improvement
