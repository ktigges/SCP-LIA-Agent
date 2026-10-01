"""Load the LIA contract straight from the repository files.

Everything the harness gives an orchestrator (system prompt, approved tools,
tool parameter lists and descriptions) is read from agent/lia-agent.yaml,
plugins/lia-sentinel-mcp-plugin.yaml and the kql/*.kql headers, so the harness
tests exactly what will be deployed.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]

KQL_FILES = {
    "normalize_time_window": "normalize-time-window.kql",
    "resolve_device": "resolve-device.kql",
    "resolve_user": "resolve-user.kql",
    "get_device_timeline": "device-timeline.kql",
    "get_user_authentication_timeline": "user-authentication-timeline.kql",
    "get_file_hash_activity": "file-hash-activity.kql",
    "get_related_alerts": "related-alerts.kql",
    "match_observed_indicators": "match-observed-indicators.kql",
    "get_source_coverage": "source-coverage.kql",
}

REPORT_SECTIONS = [
    "Executive Summary",
    "Log Overview",
    "Source Coverage and Query Status",
    "Key Findings",
    "Timeline of Notable Events",
    "Extracted Entities",
    "Security Observations",
    "Potential Risks",
    "Recommended Next Steps",
    "Conclusion",
]

NOT_OBSERVED_PHRASE = "Not observed in the provided log data"
STATUSES = ("Observed", "NotObserved", "Unavailable", "AccessDenied", "QueryFailed")


@dataclass
class ToolSpec:
    name: str
    description: str
    params: list
    param_docs: dict = field(default_factory=dict)
    kql_path: Path = None

    def kql(self):
        return self.kql_path.read_text()


@dataclass
class Contract:
    instructions: str
    approved_tools: list
    tools: dict
    plugin_description_for_model: str
    approved_workspace: str
    suggested_prompts: list


def _parse_kql_header(text):
    header = []
    for line in text.splitlines():
        if not line.startswith("//"):
            break
        header.append(line[2:].rstrip())
    joined = "\n".join(header)

    m = re.search(r"Save tool parameters \(no braces\):\s*(.+)", joined)
    params = [p.strip() for p in m.group(1).split(",")] if m else []

    purpose = re.search(r"Purpose:\s*(.+?)\n\s*(?:Save tool parameters|Parameters:)", joined, re.S)
    description = " ".join(purpose.group(1).split()) if purpose else ""

    docs = {}
    pblock = re.search(r"Parameters:(.+?)\n\s*(?:Engine:)", joined, re.S)
    if pblock:
        current = None
        for line in pblock.group(1).splitlines():
            pm = re.match(r"\s*\{(\w+)\}\s*(.*)", line)
            if pm:
                current = pm.group(1)
                docs[current] = pm.group(2).strip()
            elif current and line.strip():
                docs[current] += " " + line.strip()
    return params, description, docs


def load_contract():
    agent = yaml.safe_load((ROOT / "agent/lia-agent.yaml").read_text())
    plugin = yaml.safe_load((ROOT / "plugins/lia-sentinel-mcp-plugin.yaml").read_text())
    skill = agent["SkillGroups"][0]["Skills"][0]
    instructions = skill["Settings"]["Instructions"]
    approved = [t.strip() for t in plugin["SkillGroups"][0]["Settings"]["AllowedTools"].split(",")]
    child = skill["ChildSkills"]
    tools = {}
    for name in child:
        path = ROOT / "kql" / KQL_FILES[name]
        params, desc, docs = _parse_kql_header(path.read_text())
        tools[name] = ToolSpec(name, desc, params, docs, path)
    ws = re.search(r"ApprovedWorkspace:\s*(\S+)", instructions)
    return Contract(
        instructions=instructions,
        approved_tools=[t for t in approved if t in child],
        tools=tools,
        plugin_description_for_model=" ".join(plugin["Descriptor"]["DescriptionForModel"].split()),
        approved_workspace=ws.group(1) if ws else "",
        suggested_prompts=[p["Prompt"] for p in skill.get("SuggestedPrompts", [])],
    )


def tool_json_schema(spec):
    """JSON schema for a tool's inputs (every LIA parameter is a string)."""
    return {
        "type": "object",
        "properties": {
            p: {"type": "string", "description": spec.param_docs.get(p, p)} for p in spec.params
        },
        "required": list(spec.params),
        "additionalProperties": False,
    }
