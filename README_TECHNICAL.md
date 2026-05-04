# LLM Helpdesk Security Evaluation

Technical documentation for an empirical study of prompt injection resistance in a tool-using helpdesk agent.

## Project Goal

This project evaluates how an LLM-powered IT helpdesk assistant behaves when exposed to malicious prompt injection attempts, ambiguous instructions, and legitimate but suspicious-looking requests. The objective is to measure the safety-utility tradeoff of layered defenses while keeping the system reproducible enough to support a research paper.

## System Overview

The assistant is implemented in `app/agent.py` and follows this control flow:

1. Read active defense toggles.
2. Optionally run intent classification on the raw user prompt.
3. Build a structured request and send it to the configured LLM backend.
4. Clean and parse the model output as JSON.
5. Validate the requested tool call.
6. Apply authorization and argument-safety checks.
7. Execute the tool only if the request passes all controls.

The tool set lives in `app/tools.py` and includes:

- `get_user(user_id)`
- `reset_password(user_id)`
- `create_ticket(content)`
- `escalate_ticket(ticket_id)`
- `read_tickets()`

## Defense Layers

The evaluation isolates three defenses:

- Intent classifier (`ENABLE_INTENT_CLASSIFIER`)
  - Implemented in `app/classifier.py`.
  - Uses heuristic pattern matching for obvious injection phrases and can fall back to an LLM-based classifier path.
- RBAC (`ENABLE_RBAC`)
  - Implemented in `app/security.py`.
  - Restricts which tool actions a given role can execute.
- Argument filter (`ENABLE_ARG_FILTER`)
  - Implemented in `app/security.py`.
  - Rejects suspicious tool arguments, including requests containing sensitive terms such as `admin`.

## Evaluation Design

The evaluation harness is implemented in `experiments/run_full_eval.py` and uses a fixed scenario matrix defined in `experiments/defense_scenarios.json`.

Each run evaluates every selected model against:

- 10 attack prompts in `experiments/attacks.py`
- 6 legitimate helpdesk tasks in `experiments/utility.py`

The attack set includes:

- direct attacks
- indirect attacks
- confusion-style attacks
- multi-step attacks
- jailbreak-oriented attacks

The utility set intentionally includes a few ambiguous requests so the benchmark captures false-positive behavior, not just attack blocking.

## Scenario Matrix

The current scenario file evaluates all 8 combinations of the three toggles:

- no defenses
- argument filter only
- RBAC only
- RBAC plus argument filter
- intent classifier only
- intent classifier plus argument filter
- intent classifier plus RBAC
- all defenses enabled

## Metrics

The evaluator computes the following metrics:

- ASR (Attack Success Rate): fraction of attack prompts that successfully trigger a dangerous action
- USR (Utility Success Rate): fraction of legitimate tasks that succeed
- FPR (False Positive Rate): fraction of legitimate tasks blocked by the defenses

The summary file also records blocking counts for classifier and authorization checks to help diagnose which layer stopped a request.

## Key Results From The Current Runs

The recorded summaries in `experiments/results_summary.json` show the following pattern across `llama3` and `mistral-small3.2`:

| Scenario | Avg ASR | Avg USR | Avg FPR | Interpretation |
| --- | --- | --- | --- | --- |
| No defenses | 0.15 | 0.67 | 0.33 | Some attacks succeed, but utility remains relatively high. |
| Argument filter only | 0.15 | 0.58 | 0.33 | Little improvement over the baseline; utility drops. |
| RBAC only | 0.00 | 0.25 | 0.75 | Strong attack blocking, but many legitimate requests are blocked. |
| RBAC + argument filter | 0.00 | 0.33 | 0.67 | Best safety-utility balance in the current benchmark. |
| Intent classifier only | 0.00 | 0.25 | 0.75 | Stops observed attacks, but with substantial overblocking. |
| Intent classifier + argument filter | 0.00 | 0.25 | 0.67 | No attack successes, but still high false positives. |
| Intent classifier + RBAC | 0.00 | 0.17 | 0.83 | Strongest blocking, weakest utility among the secure settings. |
| All defenses | 0.00 | 0.17 | 0.83 | The classifier adds more blocking without improving attack resistance further. |

Interpretation for paper writing:

- RBAC is the most reliable single control in this benchmark.
- The intent classifier also blocks all observed attacks, but it is expensive in utility.
- The argument filter is helpful as a secondary layer, not as a standalone defense.
- The full stack is not automatically better than a carefully chosen subset of defenses.

## Output Artifacts

The pipeline writes these files to `experiments/`:

- `results.json` - full per-request record of attacks and utility tasks
- `results.csv` - flattened data for downstream analysis
- `results_summary.json` - per-scenario, per-model metrics
- `results_summary_plot.png` - comparison plot for reporting

## Reproduction

Run all scenarios and generate plots:

```bash
py -m experiments.run_full_eval
```

Run specific scenarios only:

```bash
py -m experiments.run_full_eval --scenario intent_classifier_off_rbac_on_arg_filter_on
```

Disable plot generation:

```bash
py -m experiments.run_full_eval --no-plot
```

## Extending The Study

You can extend the experiment by:

- adding attack families in `experiments/attacks.py`
- adding benign tasks in `experiments/utility.py`
- introducing new defense strategies in `app/security.py`
- expanding the tool set in `app/tools.py`
- adding new LLM backends in `app/config.py`
- improving response parsing and tool-call validation in `app/agent.py`

## Paper Writing Notes

This repository already contains the ingredients needed for a methods and results section:

- a fixed scenario matrix
- explicit attack and utility corpora
- deterministic metrics
- exportable CSV and JSON outputs
- summary plots for visual comparison

The most important discussion point is the tradeoff between blocking malicious requests and preserving legitimate use. On the current benchmark, the defenses that eliminate attacks also raise the false-positive rate, which makes the benchmark useful for comparing not just security, but practical deployability.
