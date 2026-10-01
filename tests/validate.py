#!/usr/bin/env python3
"""Local syntax and contract checks for the LIA proof of concept.

Checks (no network, no deployment):
  1. Every YAML file parses.
  2. Every JSON file parses; both schemas are valid Draft 2020-12 schemas.
  3. Report fixtures: valid-*.json must validate, invalid-*.json must fail.
  4. Timeline event fixture validates against timeline-event.schema.json.
  5. Agent manifest contract: identifiers and skill targets are consistent,
     interactive interface, single UserRequest input, starter prompts present,
     ChildSkills are a subset of the plugin AllowedTools, and RequiredSkillsets
     include the plugin name.
  6. KQL contract: every kql file defines MaxWindow = 24h (except resolvers),
     projects SourceTable, and uses only the declared {Parameters}.

Usage:  pip install pyyaml jsonschema   &&   python tests/validate.py
KQL is NOT compiled here; run each query in Defender Advanced Hunting.
"""
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
failures = []


def check(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        failures.append(msg)


# 1. YAML
docs = {}
for p in sorted(ROOT.rglob("*.yaml")):
    try:
        docs[p.relative_to(ROOT).as_posix()] = yaml.safe_load(p.read_text())
        check(True, f"YAML parses: {p.relative_to(ROOT)}")
    except yaml.YAMLError as e:
        check(False, f"YAML parses: {p.relative_to(ROOT)} ({e})")

# 2. JSON + schemas
for p in sorted(ROOT.rglob("*.json")):
    try:
        json.loads(p.read_text())
        check(True, f"JSON parses: {p.relative_to(ROOT)}")
    except json.JSONDecodeError as e:
        check(False, f"JSON parses: {p.relative_to(ROOT)} ({e})")

report_schema = json.loads((ROOT / "schemas/investigation-report.schema.json").read_text())
event_schema = json.loads((ROOT / "schemas/timeline-event.schema.json").read_text())
for name, s in (("investigation-report", report_schema), ("timeline-event", event_schema)):
    try:
        Draft202012Validator.check_schema(s)
        check(True, f"Valid Draft 2020-12 schema: {name}")
    except Exception as e:  # noqa: BLE001
        check(False, f"Valid Draft 2020-12 schema: {name} ({e})")

# 3. Report fixtures
rv = Draft202012Validator(report_schema)
for p in sorted((ROOT / "tests/fixtures").glob("*-report*.json")) + sorted(
    (ROOT / "tests/fixtures").glob("invalid-*.json")
):
    errs = list(rv.iter_errors(json.loads(p.read_text())))
    if p.name.startswith("valid-"):
        check(not errs, f"Fixture validates: {p.name}" + (f" ({errs[0].message})" if errs else ""))
    elif p.name.startswith("invalid-"):
        check(bool(errs), f"Fixture correctly rejected: {p.name}")

# 4. Event fixture
ev = Draft202012Validator(event_schema)
for i, e in enumerate(json.loads((ROOT / "tests/fixtures/sample-timeline-events.json").read_text())):
    errs = list(ev.iter_errors(e))
    check(not errs, f"Timeline event #{i} validates" + (f" ({errs[0].message})" if errs else ""))

# 5. Manifest contract
agent = docs.get("agent/lia-agent.yaml", {})
plugin = docs.get("plugins/lia-sentinel-mcp-plugin.yaml", {})
desc_name = agent["Descriptor"]["Name"]
adef = agent["AgentDefinitions"][0]
skills = [s for g in agent["SkillGroups"] if str(g["Format"]).lower() == "agent" for s in g["Skills"]]
check(len(skills) == 1, "Exactly one Agent-format skill")
skill = skills[0]
expected_skill = f"{desc_name}.{skill['Name']}"
check(adef.get("Name") == desc_name, "Agent definition name equals Descriptor.Name")
check("InteractiveAgent" in skill.get("Interfaces", []), "Interfaces includes InteractiveAgent")
inputs = skill.get("Inputs", [])
check(len(inputs) == 1 and inputs[0]["Name"] == "UserRequest" and inputs[0]["Required"] is True,
      "Single required input named UserRequest")
check(adef.get("PromptSkill") == expected_skill, "PromptSkill targets the agent skill")
triggers = adef.get("Triggers", [])
check(
    len(triggers) == 1
    and triggers[0].get("DefaultPollPeriodSeconds") == 0
    and "DefaultPeriodSeconds" not in triggers[0],
    "Interactive trigger uses DefaultPollPeriodSeconds: 0",
)
check(
    len(triggers) == 1 and triggers[0].get("ProcessSkill") == expected_skill,
    "ProcessSkill targets the agent skill",
)
starters = [p for p in skill.get("SuggestedPrompts", []) if p.get("IsStarterAgent")]
check(len(starters) >= 2 and all(p.get("Title") and p.get("Personas") for p in starters),
      "At least two starter prompts with Title and Personas")
check(any("device" in p["Prompt"].lower() for p in starters) and any("user" in p["Prompt"].lower() for p in starters),
      "Starter prompts cover device and user investigations")
check(any("sha256" in p["Prompt"].lower() for p in starters),
      "Starter prompts cover SHA256 investigations")
allowed = {t.strip() for t in plugin["SkillGroups"][0]["Settings"]["AllowedTools"].split(",")}
child = set(skill.get("ChildSkills", []))
check(child and child <= allowed, f"ChildSkills subset of AllowedTools ({sorted(child - allowed) or 'ok'})")
check(plugin["Descriptor"]["Name"] in adef["RequiredSkillsets"], "RequiredSkillsets includes MCP plugin name")
check(desc_name in adef["RequiredSkillsets"], "RequiredSkillsets includes the agent skillset")
check(not any(re.search(r"run_?any|execute_?kql|free_?query", t, re.I) for t in allowed),
      "No unrestricted query tool in AllowedTools")
raw_agent = (ROOT / "agent/lia-agent.yaml").read_text()
check(not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", raw_agent, re.I),
      "No GUIDs (tenant/subscription IDs) hard-coded in agent manifest")

kql_tools = {"normalize-time-window": "normalize_time_window", "resolve-device": "resolve_device",
             "resolve-user": "resolve_user", "device-timeline": "get_device_timeline",
             "user-authentication-timeline": "get_user_authentication_timeline",
             "file-hash-activity": "get_file_hash_activity",
             "related-alerts": "get_related_alerts",
             "match-observed-indicators": "match_observed_indicators",
             "source-coverage": "get_source_coverage"}
check({p.stem for p in (ROOT / "kql").glob("*.kql")} == set(kql_tools), "Every KQL file maps to a known tool")
check(set(kql_tools.values()) == child, "ChildSkills cover exactly the KQL tools")
check(set(report_schema["$defs"]["toolName"]["enum"]) == child, "Report schema toolName enum matches ChildSkills")

# 6. KQL contract
declared = {
    "normalize-time-window.kql": {"StartTimeLocal", "EndTimeLocal", "TimeZone"},
    "resolve-device.kql": {"DeviceName", "Workspace"},
    "resolve-user.kql": {"UserIdentifier", "Workspace"},
    "device-timeline.kql": {"DeviceId", "StartTimeUtc", "EndTimeUtc", "Workspace"},
    "user-authentication-timeline.kql": {"UserIdentifier", "StartTimeUtc", "EndTimeUtc", "Workspace"},
    "file-hash-activity.kql": {"SHA256", "StartTimeUtc", "EndTimeUtc", "Workspace"},
    "related-alerts.kql": {"EntityIdentifier", "StartTimeUtc", "EndTimeUtc", "Workspace"},
    "match-observed-indicators.kql": {"Indicators", "StartTimeUtc", "EndTimeUtc", "Workspace"},
    "source-coverage.kql": {"EntityType", "EntityIdentifier", "StartTimeUtc", "EndTimeUtc", "Workspace"},
}
for name, params in declared.items():
    text = (ROOT / "kql" / name).read_text()
    # Drop full-line comments only; "//" also appears inside regex/URL literals.
    code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("//"))
    used = set(re.findall(r'"\{([A-Za-z][A-Za-z0-9]*)\}"', code))
    check(used == params, f"{name}: parameters {sorted(used)}")
    check("SourceTable" in code, f"{name}: projects SourceTable")
    if params & {"StartTimeUtc", "StartTimeLocal"}:
        max_window = "30d" if name in {
            "normalize-time-window.kql",
            "file-hash-activity.kql",
            "related-alerts.kql",
            "match-observed-indicators.kql",
        } else "24h"
        check(re.search(rf"let MaxWindow = {max_window};", code) is not None,
              f"{name}: MaxWindow = {max_window}")
    check(not re.search(r"\bunion\s+\*|\bsearch\s", code), f"{name}: no 'union *' or 'search'")

print()
print(f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
