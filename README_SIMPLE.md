# LLM Helpdesk Security Project

## In One Sentence

This project tests whether an AI helpdesk assistant can be tricked into unsafe actions and measures how well different protections stop those attacks without breaking normal support tasks.

## What It Simulates

The assistant can use helpdesk tools such as:

- `create_ticket`
- `get_user`
- `reset_password`
- `escalate_ticket`

The evaluation sends the assistant two kinds of prompts:

- attack prompts that try to make it do something dangerous
- normal helpdesk requests that a real user might ask for

## The Safety Checks

Three protections can be turned on or off:

- Intent classifier - tries to detect attack-like input before the model acts on it
- RBAC - limits which tools a user role is allowed to call
- Argument filter - blocks suspicious arguments, especially ones that look like admin-related misuse

## What The Experiment Found

The current results show a clear tradeoff:

- Without defenses, some attacks succeed.
- RBAC and the intent classifier stop all observed attacks in this benchmark.
- Those same defenses also block many normal requests, which increases false positives.
- Argument filtering helps, but it is not strong enough by itself.
- The best balance in the current runs came from RBAC plus argument filtering.

## What Gets Saved

After the evaluation finishes, the project saves:

- detailed request-by-request results
- a CSV file for analysis
- a summary JSON file with the metrics
- a plot that compares the different defense setups

## How To Run It

Run everything:

```bash
py -m experiments.run_full_eval
```

Run one scenario:

```bash
py -m experiments.run_full_eval --scenario intent_classifier_off_rbac_on_arg_filter_on
```

Skip the plot:

```bash
py -m experiments.run_full_eval --no-plot
```

## Why It Matters

This project shows that making a helpdesk agent safer is not just about blocking attacks. A good defense also has to preserve useful behavior. That balance is the main takeaway for the research paper.
