# Tests quick guide

A test is just a quick check that something still works.

This repo has two main checks:

- `tests/validate.py` checks the setup.
  - It makes sure the YAML files still parse.
  - It checks the agent and plugin match.
  - It makes sure the schemas and tool names line up.

- `tests/e2e/` checks the actual agent flow.
  - It runs mock investigation scenarios.
  - It helps catch broken prompts, bad tool calls, or bad results.

## Basic example

If I change the agent manifest and accidentally rename a tool, `tests/validate.py` will fail fast and tell me the setup is out of sync.

```bash
cd /Users/kevintigges/work/LIAPOC
. .venv/bin/activate
python tests/validate.py
```

If I change the prompt or investigation logic, I run the end-to-end mock checks:

```bash
cd /Users/kevintigges/work/LIAPOC
. .venv/bin/activate
python tests/e2e/run_e2e.py
```

The short version: `validate.py` is a config sanity check, and `run_e2e.py` is a behavior check.
