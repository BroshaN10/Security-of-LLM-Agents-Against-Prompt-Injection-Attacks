# LLM Helpdesk Security Project — Simple Explanation

## Why this project exists
This project was created to test whether an AI helpdesk assistant can be tricked into doing dangerous things, like resetting an admin password or escalating a support ticket without authorization.

The goal is to understand how different protections work together and how safe helpers can be built with LLMs.

## What the project does

1. It simulates a helpdesk assistant that can use tools.
2. It sends the assistant both:
   - malicious prompts that try to force bad actions, and
   - normal helpdesk requests that a real user might make.
3. It measures whether the bad prompts succeed and whether normal requests are still allowed.

## How it works in simple terms

- The assistant is driven by a local LLM backend.
- The LLM is asked to output a safe JSON command, like:
  - `reset_password`
  - `create_ticket`
  - `get_user`
  - `escalate_ticket`
- Before the system runs the command, it checks whether the request is allowed.

## The protections used

There are three safety checks you can turn on or off:

- **Intent classifier**
  - Looks at the user message and tries to detect if it is an attack.
  - Blocks clearly malicious requests before the LLM runs.
- **RBAC (Role-Based Access Control)**
  - Makes sure only the right user can call certain tools.
  - For example, a normal user should not be allowed to reset passwords.
- **Argument filter**
  - Blocks requests that mention sensitive terms such as `admin` in tool arguments.

## What is tested

The project runs:

- a set of attack phrases that try to bypass the assistant,
- a set of normal helpdesk tasks to check usability.

It then calculates:

- how many attacks succeeded,
- how many normal tasks still worked,
- how many normal tasks were wrongly blocked.

## How to use it

Run the whole evaluation pipeline with:

```bash
py -m experiments.run_full_eval
```

Pick a specific defense setup with:

```bash
py -m experiments.run_full_eval --scenario intent_classifier_off_rbac_on_arg_filter_on
```

Turn off plots with:

```bash
py -m experiments.run_full_eval --no-plot
```

## What you get

After running, the project saves:

- a detailed results file,
- a CSV file for analysis,
- a summary of metrics,
- a plot showing how different settings compare.

## Why it matters

This project helps teams understand the tradeoff between:

- making AI assistants safe,
- and keeping them useful.

By testing different defenses together, it shows which protections are most effective and where the system may still fail.
