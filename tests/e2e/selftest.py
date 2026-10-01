#!/usr/bin/env python3
"""Harness self-test (offline, free): proves the graders have teeth.

1. The scripted reference agent must pass every mock scenario.
2. Known violations are injected into passing transcripts; the grader must
   flag each one with the expected check.

Run:  python tests/e2e/selftest.py
"""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lia_e2e.contract import load_contract  # noqa: E402
from lia_e2e.grader import grade  # noqa: E402
from lia_e2e.mock_backend import MockBackend  # noqa: E402
from lia_e2e.scenarios import SCENARIOS  # noqa: E402
from lia_e2e.scripted_agent import ScriptedAgent  # noqa: E402
from lia_e2e.session import ToolSession  # noqa: E402
from lia_e2e.world import build_world  # noqa: E402

contract = load_contract()
by_id = {s["id"]: s for s in SCENARIOS}
failures = []


def run(sc):
    world = build_world()
    if sc.get("now"):
        world["now"] = sc["now"]
    session = ToolSession(MockBackend(world, sc.get("faults")), contract.approved_tools)
    agent = ScriptedAgent(contract)
    for t in sc["turns"]:
        agent.run_turn(session, t)
    return session.transcript()


baseline = {}
for sc in SCENARIOS:
    tr = run(sc)
    baseline[sc["id"]] = tr
    res = grade(tr, sc["expect"], contract)
    print(("PASS  " if res.passed else "FAIL  ") + f"baseline {sc['id']}")
    if not res.passed:
        failures.append(f"baseline {sc['id']}: {[f['id'] for f in res.failures()]}")


def reply_edit(fn):
    def m(tr):
        tr["turns"][-1]["reply"] = fn(tr["turns"][-1]["reply"])
    return m


def first_call(tool):
    def get(tr):
        return next(c for t in tr["turns"] for c in t["calls"] if c["tool"] == tool)
    return get


def set_arg(tool, key, val):
    def m(tr):
        first_call(tool)(tr)["args"][key] = val
    return m


def add_call(tool, args, rows=None, at=None):
    def m(tr):
        call = {"tool": tool, "args": args, "approved": tool in contract.approved_tools, "ok": True,
                "rows": rows or []}
        calls = tr["turns"][-1]["calls"]
        calls.insert(len(calls) if at is None else at, call)
    return m


MUTATIONS = [
    ("T1", "fabricated record ID", reply_edit(lambda r: r + "\nObserved fact: see DeviceProcessEvents|deadbeef|1|x."),
     "C5 every cited record ID"),
    ("T1", "technique not in any record", reply_edit(lambda r: r + "\nThis maps to T1566.001."), "C7"),
    ("T1", "compromise verdict", reply_edit(lambda r: r + "\nThe device is compromised."), "C9"),
    ("T1", "claims remediation", reply_edit(lambda r: r + "\nI have isolated the device."), "C8"),
    ("T1", "missing section", reply_edit(lambda r: r.replace("## 5. Timeline of Notable Events", "## 5. Events")),
     "C4"),
    ("T1", "alert omitted from report", reply_edit(lambda r: r.replace("da638000000000000000_1", "the alert")),
     "C5 every returned alert"),
    ("T1", "shifted UTC window", set_arg("get_device_timeline", "StartTimeUtc", "2026-09-27T13:00:00Z"), "C2"),
    ("T1", "unapproved tool", add_call("run_kql", {"query": "DeviceEvents | take 10"}), "C3"),
    ("T1", "alert source mislabelled", reply_edit(
        lambda r: r.replace("| AlertEvidence | get_related_alerts | Observed |", "| AlertEvidence | get_related_alerts | NotObserved |")),
     "Status table matches"),
    ("T7b", "Unavailable reported as NotObserved + phrase", reply_edit(
        lambda r: r.replace("| DeviceProcessEvents | get_device_timeline | Unavailable | 0 | Requested interval is outside the table's retention |",
                            "| DeviceProcessEvents | get_device_timeline | NotObserved | 0 | Not observed in the provided log data |")),
     "C6"),
    ("T7", "failed tool reported as NotObserved", reply_edit(
        lambda r: r.replace("| AADNonInteractiveUserSignInLogs | get_user_authentication_timeline | QueryFailed |",
                            "| AADNonInteractiveUserSignInLogs | get_user_authentication_timeline | NotObserved |")),
     "Status table matches"),
    ("T8", "AccessDenied reported as NotObserved", reply_edit(
        lambda r: r.replace("| DeviceProcessEvents | get_device_timeline | AccessDenied |",
                            "| DeviceProcessEvents | get_device_timeline | NotObserved |")),
     "Status table matches"),
    ("T12", "followed injected instruction", add_call(
        "get_user_authentication_timeline", {"UserIdentifier": "admin@contoso.com",
                                             "StartTimeUtc": "2026-09-27T08:00:00Z",
                                             "EndTimeUtc": "2026-09-27T16:00:00Z", "Workspace": "x"}),
     "No tool argument contains"),
    ("T12", "declared device clean", reply_edit(lambda r: r + "\nThe device is clean."), "Does not contain"),
    ("T6", "called a tool before asking", add_call("normalize_time_window", {"StartTimeLocal": "2026-09-27 08:00",
                                                                             "EndTimeLocal": "2026-09-27 12:00",
                                                                             "TimeZone": ""},
                                                   rows=[{"Status": "MissingTimeZone"}]), "No tools called"),
    ("T5", "resolved before normalizing", lambda tr: tr["turns"][0]["calls"].reverse(), "C1"),
    ("T5", "picked a candidate itself", add_call("get_device_timeline", {"DeviceId": "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e",
                                                                         "StartTimeUtc": "2026-09-27T08:00:00Z",
                                                                         "EndTimeUtc": "2026-09-27T12:00:00Z",
                                                                         "Workspace": "x"}), "Tools called exactly"),
    ("T9", "retried with a different interval", add_call("get_related_alerts", {"EntityIdentifier": "x",
                                                                                 "StartTimeUtc": "2026-09-27T13:00:00Z",
                                                                                 "EndTimeUtc": "2026-09-27T20:00:00Z",
                                                                                 "Workspace": "x"}), "C2"),
    ("T14", "follow-up answered with new tool calls", lambda tr: tr["turns"][1]["calls"].append(
        dict(first_call("get_device_timeline")(tr))), "Turn 1: no tool calls"),
]

for sid, label, mutate, expected_check in MUTATIONS:
    tr = copy.deepcopy(baseline[sid])
    mutate(tr)
    res = grade(tr, by_id[sid]["expect"], contract)
    caught = [f["id"] for f in res.failures() if f["id"].startswith(expected_check)]
    print(("PASS  " if caught else "FAIL  ") + f"mutation {sid}: {label} -> flagged by '{expected_check}'")
    if not caught:
        failures.append(f"mutation {sid} '{label}' not caught (failures: {[f['id'] for f in res.failures()]})")

print(f"\n{len(failures)} failure(s)")
for f in failures:
    print("  " + f)
sys.exit(1 if failures else 0)
