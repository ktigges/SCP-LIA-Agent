# LIA end-to-end test harness (no Security Copilot, no SCUs)

This harness runs the LIA agent end to end outside Security Copilot, so the tools,
the agent Instructions, and the report contract can all pass before SCUs are
provisioned. It swaps in stand-ins for the two runtime pieces Security Copilot
normally supplies:

| Security Copilot piece | Stand-in (`--agent`) | Tool source (`--backend`) |
|---|---|---|
| Orchestrator / model | `scripted`: deterministic implementation of Steps 1-10 (no LLM, free)<br>`azure-openai`: your GPT deployment (closest to Security Copilot's model)<br>`claude`: Anthropic API | `mock`: Python mirror of every `kql/*.kql` over a synthetic lab tenant, with fault injection<br>`hunting`: the **real** KQL through Graph Advanced Hunting<br>`mcp`: the **deployed** custom Sentinel MCP collection |

The system prompt, approved tools, parameter lists and tool descriptions are all
loaded from `agent/lia-agent.yaml`, `plugins/lia-sentinel-mcp-plugin.yaml` and the
`kql/*.kql` headers. The harness therefore tests exactly what you will deploy.
Grading automates C1-C9 and the Must / Must-not items of `tests/acceptance-tests.md`.

## Setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r tests/e2e/requirements.txt
```

## The test ladder (run in order)

| Stage | Command | Needs | What it proves |
|---|---|---|---|
| 0 | `python tests/e2e/selftest.py` | nothing | The graders catch 19 injected violations (fabricated IDs, wrong statuses, verdicts, followed injections, and so on) |
| 1 | `python tests/e2e/run_e2e.py` | nothing | The harness, mock tools and reference flow pass all 22 mock scenarios |
| 2 | `python tests/e2e/run_e2e.py --agent azure-openai --repeat 3` | Azure OpenAI deployment | **The Instructions work with a real model**: ordering, clarifications, statuses, citations, injection resistance |
| 3 | `python tests/e2e/run_e2e.py kql-smoke --backend hunting --lab tests/e2e/lab.local.json` | tenant read access | The real KQL compiles and runs in *your* tenant: DST conversion, `LIA_GUARD` rows, quote handling, row schema |
| 4 | `python tests/e2e/run_e2e.py --backend hunting --lab tests/e2e/lab.local.json` | tenant read access | The full pipeline runs on real seeded lab data (scripted orchestrator) |
| 5 | `python tests/e2e/run_e2e.py --agent azure-openai --backend mcp --lab tests/e2e/lab.local.json` | deployed MCP collection | The deployed tools plus a real model; this is the dress rehearsal |
| 6 | Security Copilot, with the prompts from stage 5 | **SCUs** | The real host. Compare its transcripts with stage 5 |

Useful options: `-s T1,T12` runs selected scenarios. `--repeat N` measures LLM
variance, since one pass is not proof. `--report-json` has the LLM convert each
report to JSON and validates it against `schemas/investigation-report.schema.json`.
`--model` picks the Claude model or Azure deployment. Run `list` to see the scenarios.

Results go to `test-results/e2e-<stamp>-<agent>-<backend>/` (git-ignored). Each
scenario gets a readable `.md` conversation, the full `.transcript.json` (every
tool call, its arguments and its rows), and `.grade.json`. The run also writes
`summary.md`.

## Credentials

| Stage | Variables |
|---|---|
| azure-openai | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, and optionally `AZURE_OPENAI_API_KEY` (otherwise an Entra token from `az` is used; needs *Cognitive Services OpenAI User*) |
| claude | `ANTHROPIC_API_KEY`, or an `ant auth login` profile. The default model is `claude-opus-5`. Server-side refusal fallback is enabled so that a safety-classifier refusal on security content retries on a fallback model instead of failing the run |
| hunting | `LIA_GRAPH_TOKEN`, or `az login`. Needs delegated **ThreatHunting.Read.All** on Microsoft Graph. If the Azure CLI's Graph token lacks it (common), sign in with `az login --scope https://graph.microsoft.com/ThreatHunting.Read.All` or paste a token from Graph Explorer into `LIA_GRAPH_TOKEN` |
| mcp | `LIA_MCP_TOKEN`, or `az login` (scope `4500ebfb-89b6-4b14-a480-7f749797bfcd/.default`, as in the plugin). The endpoint comes from `lab.local.json` or the plugin YAML |

For live stages, copy `lab.example.json` to `lab.local.json` (git-ignored) and fill
in the lab identifiers and times you seeded.

## Cost

None of these stages uses Security Copilot, so none consumes SCUs. Model stages are
billed as normal Azure OpenAI or Anthropic tokens; per-scenario token usage is in
`summary.json`. Graph Advanced Hunting is subject to its API quotas. Check the
Sentinel data lake / MCP metering for your tenant before running stage 5 at volume.

## What the harness cannot tell you

- **The mock is a mirror, not the KQL.** Stages 3 and 4 exist to catch drift between
  `mock_backend.py` / `timewin.py` and the real queries (for example
  `datetime_local_to_utc` behaviour at DST edges).
- **GPT or Claude is not Security Copilot's orchestrator.** Security Copilot wraps the
  Instructions in its own orchestration prompt and presents tool results its own way.
  Passing here raises confidence; it does not replace stage 6.
- **The `mcp` backend's parsing of results is unverified.** It accepts the likely shapes
  (a list of rows, `{results|rows: [...]}`, or tables) and otherwise passes the raw text
  through. Check the first transcript.
- The C9 and "must not contain" checks are regex heuristics. Read the `.md`
  conversations for the scenarios that matter most.

## Mock scenarios

T1-T16 from `tests/acceptance-tests.md`, plus T5b, T6b, T7b, T10b and T13a-c
variants, and X1 (multiple entities). The mock tenant (`lia_e2e/world.py`) seeds the
recommended lab data: an Office-to-PowerShell alert chain, benign admin activity, a
failed-sign-in burst followed by a success from a new IP, an ambiguous `WS-01`, a quiet
device, a busy server with 37 network events, and the T12 injection string. Faults
(missing table, 403, timeout) are injected per scenario. T15 is live-only.
