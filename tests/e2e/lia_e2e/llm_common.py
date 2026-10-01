"""Shared pieces for LLM orchestrators: system prompt, tool list, JSON conversion."""
import json
import re

from .contract import ROOT, tool_json_schema


def system_prompt(contract, now_utc):
    # The manifest Instructions are passed verbatim. The runtime-context line stands in
    # for the date context Security Copilot gives the model.
    return (contract.instructions.rstrip()
            + f"\n\n# Runtime context (test harness)\nCurrent date/time (UTC): {now_utc:%Y-%m-%dT%H:%M:%SZ}\n")


def tool_defs(contract):
    """(name, description, json_schema) for each approved tool."""
    out = []
    for name in contract.approved_tools:
        spec = contract.tools[name]
        desc = f"{spec.description} Read-only. Returns rows as JSON."
        out.append((name, desc, tool_json_schema(spec)))
    return out


REPORT_JSON_PROMPT = """Convert the investigation report below into ONE JSON object that validates against
the JSON schema that follows. Use only content present in the report; do not add facts, IDs or techniques.
Return only the JSON object, with no code fences or commentary.

JSON SCHEMA:
{schema}

REPORT:
{report}
"""


def report_json_prompt(report_md):
    schema = (ROOT / "schemas/investigation-report.schema.json").read_text()
    return REPORT_JSON_PROMPT.format(schema=schema, report=report_md)


def extract_json(text):
    text = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if m:
        text = m.group(1)
    start, end = text.find("{"), text.rfind("}")
    return json.loads(text[start:end + 1])
