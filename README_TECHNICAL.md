# LLM Helpdesk Security Evaluation — Technical Documentation

## Project Purpose
This project evaluates the security of an LLM-powered IT helpdesk assistant against prompt injection and ambiguous requests. It measures how well different defense layers protect against dangerous actions while preserving legitimate utility.

## Repository Structure

- `app/`
  - `agent.py` — Core assistant pipeline: prompt assembly, LLM call, JSON extraction, security validation, tool execution.
  - `classifier.py` — Intent classifier for prompt injection detection.
  - `config.py` — Model selection, endpoint configuration, and defense toggle defaults.
  - `memory.py` — Ticket memory store used by tools.
  - `security.py` — RBAC and argument filtering logic.
  - `tools.py` — Tool implementations available to the assistant.
  - `main.py` — Project entrypoint if used directly.
- `experiments/`
  - `run_full_eval.py` — Single pipeline for scenario-driven evaluation and plotting.
  - `plot_results.py` — Generates comparison plots from evaluation results.
  - `attacks.py` — Attack prompt definitions grouped by category.
  - `utility.py` — Legitimate user tasks for usability testing.
  - `metrics.py` — Scoring functions for ASR, USR, FPR, and defense blocking.
  - `defense_scenarios.json` — Definitions for all defense toggle combinations.
- `requirements.txt` — Python dependencies.

## Core Concepts

### 1. Agent Workflow

The agent pipeline is implemented in `app/agent.py`:

1. Read defense toggle overrides and determine active protections.
2. Optionally run the intent classifier on raw user input.
3. Build a structured prompt and send it to the configured LLM via `OLLAMA_URL`.
4. Clean the LLM response to extract JSON output.
5. Parse the JSON and validate the requested tool call.
6. Apply security checks before executing any tool.
7. Execute the allowed tool and return the result.

### 2. Defense Layers

This project supports three defense layers:

- **Intent Classifier** (`ENABLE_INTENT_CLASSIFIER`) — First line of defense in `app/classifier.py`.
  - Uses regex patterns for obvious injection phrases.
  - Falls back to an LLM-based classifier prompt when needed.
- **RBAC** (`ENABLE_RBAC`) — Role-based access control in `app/security.py`.
  - Defines allowed tool actions per role.
  - Example: regular `user` can only create tickets.
- **Argument Filter** (`ENABLE_ARG_FILTER`) — Prevents suspicious tool arguments.
  - Denies calls containing the keyword `admin` in arguments.

### 3. Tools

Available tools are defined in `app/tools.py`:

- `get_user(user_id)`
- `reset_password(user_id)`
- `create_ticket(content)`
- `escalate_ticket(ticket_id)`
- `read_tickets()`

Each tool is mapped in `TOOLS`, and validation ensures required arguments are present before execution.

### 4. Evaluation Pipeline

The evaluation pipeline is in `experiments/run_full_eval.py`.

- Loads attack prompts and legitimate utility tasks.
- Iterates over configured models.
- Runs each scenario from `experiments/defense_scenarios.json`.
- Records:
  - `attack_success`
  - `utility_success`
  - `false_positive`
  - `blocked_by_classifier`
  - `blocked_by_rbac`
- Writes final outputs to JSON and CSV.

### 5. Scenario Management

`experiments/defense_scenarios.json` defines the eight combinations of the three defense toggles:

- No defenses
- Arg filter only
- RBAC only
- RBAC + arg filter
- Intent classifier only
- Intent classifier + arg filter
- Intent classifier + RBAC
- All defenses enabled

### 6. Plotting

`experiments/plot_results.py` reads `experiments/results.csv` and saves a summarized visualization.
It creates comparison plots for:

- Attack Success Rate (ASR)
- Utility Success Rate (USR)
- False Positive Rate (FPR)

### 7. Configuration

`app/config.py` controls:

- `MODELS` — list of LLM backends to test.
- `OLLAMA_URL` — local request endpoint.
- `CLASSIFIER_MODEL` — model used for the intent classifier.
- Defense toggles:
  - `ENABLE_INTENT_CLASSIFIER`
  - `ENABLE_RBAC`
  - `ENABLE_ARG_FILTER`

### 8. Running the Project

To execute the full pipeline:

```bash
py -m experiments.run_full_eval
```

Run specific scenarios only:

```bash
py -m experiments.run_full_eval --scenario intent_classifier_off_rbac_on_arg_filter_on
```

Skip plot generation:

```bash
py -m experiments.run_full_eval --no-plot
```

### 9. Output Files

- `experiments/results.json` — detailed per-query results
- `experiments/results.csv` — tabular output for analysis
- `experiments/results_summary.json` — summarized metrics by scenario/model
- `experiments/results_summary_plot.png` — visual comparison chart

### 10. Extension Points

You can extend this project by:

- Adding new attack categories in `experiments/attacks.py`
- Adding new legitimate tasks in `experiments/utility.py`
- Adding more tools to `app/tools.py`
- Adding stronger defenses in `app/security.py`
- Supporting additional LLM backends in `app/config.py`
- Enhancing cleaning and parsing logic in `app/agent.py`
