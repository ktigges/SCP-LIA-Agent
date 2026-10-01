#!/usr/bin/env python3
"""LIA end-to-end test runner - no Security Copilot, no SCUs.

  python tests/e2e/run_e2e.py                                   # scripted agent, mock tools (free, offline)
  python tests/e2e/run_e2e.py --agent claude                    # LLM orchestrator, mock tools
  python tests/e2e/run_e2e.py --agent azure-openai -s T1,T12    # GPT deployment, selected scenarios
  python tests/e2e/run_e2e.py --backend hunting --lab tests/e2e/lab.local.json    # real KQL via Graph
  python tests/e2e/run_e2e.py --backend mcp --lab tests/e2e/lab.local.json        # deployed MCP tools
  python tests/e2e/run_e2e.py kql-smoke --backend hunting --lab tests/e2e/lab.local.json
  python tests/e2e/run_e2e.py list

See tests/e2e/README.md.
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jsonschema import Draft202012Validator  # noqa: E402

from lia_e2e.contract import ROOT, load_contract  # noqa: E402
from lia_e2e.grader import grade  # noqa: E402
from lia_e2e.mock_backend import MockBackend, ToolError  # noqa: E402
from lia_e2e.scenarios import SCENARIOS  # noqa: E402
from lia_e2e.session import ToolSession  # noqa: E402
from lia_e2e.world import MOCK_NOW, build_world  # noqa: E402

EVENT_TOOLS = {"get_device_timeline", "get_user_authentication_timeline", "get_related_alerts",
               "match_observed_indicators"}


def make_agent(kind, contract, now, model):
    if kind == "scripted":
        from lia_e2e.scripted_agent import ScriptedAgent
        return ScriptedAgent(contract)
    if kind == "claude":
        from lia_e2e.llm_claude import ClaudeAgent
        return ClaudeAgent(contract, now, model)
    if kind == "azure-openai":
        from lia_e2e.llm_azure_openai import AzureOpenAIAgent
        return AzureOpenAIAgent(contract, now, model)
    raise SystemExit(f"unknown agent {kind}")


def make_backend(kind, scenario, lab):
    if kind == "mock":
        world = build_world()
        if scenario.get("now"):
            world["now"] = scenario["now"]
        return MockBackend(world, scenario.get("faults")), world["now"]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if kind == "hunting":
        from lia_e2e.live_backends import HuntingBackend
        return HuntingBackend(), now
    if kind == "mcp":
        from lia_e2e.live_backends import McpBackend
        endpoint = (lab or {}).get("mcp_endpoint")
        if not endpoint:
            import yaml
            plugin = yaml.safe_load((ROOT / "plugins/lia-sentinel-mcp-plugin.yaml").read_text())
            endpoint = plugin["SkillGroups"][0]["Settings"]["Endpoint"]
        return McpBackend(endpoint), now
    raise SystemExit(f"unknown backend {kind}")


def _fill(text, values):
    for k, val in values.items():
        text = text.replace("{" + k + "}", str(val))
    return text


def load_lab(path):
    lab = json.loads(Path(path).read_text())
    values = lab.get("values", {})
    scenarios = []
    for sc in lab.get("scenarios", []):
        sc = dict(sc)
        sc["turns"] = [_fill(t, values) for t in sc["turns"]]
        # Expectations may reference lab values too, e.g. "cite": ["{alert_id}"].
        sc["expect"] = json.loads(_fill(json.dumps(sc.get("expect", {})), values))
        scenarios.append(sc)
    return lab, scenarios


def schema_check_rows(transcript):
    schema = json.loads((ROOT / "schemas/timeline-event.schema.json").read_text())
    v = Draft202012Validator(schema)
    bad = []
    for t in transcript["turns"]:
        for c in t["calls"]:
            if c["tool"] in EVENT_TOOLS:
                for r in c.get("rows") or []:
                    errs = list(v.iter_errors(r))
                    if errs:
                        bad.append(f"{c['tool']} {r.get('SourceTable')}: {errs[0].message[:100]}")
    return bad


def run_scenarios(args):
    contract = load_contract()
    lab, lab_scenarios = (load_lab(args.lab) if args.lab else (None, None))
    if args.backend != "mock" and not lab_scenarios:
        raise SystemExit("Live backends need --lab tests/e2e/lab.local.json (copy lab.example.json).")
    pool = SCENARIOS if args.backend == "mock" else lab_scenarios
    wanted = set(args.scenario.split(",")) if args.scenario else None
    scenarios = [s for s in pool if not wanted or s["id"] in wanted]
    if not scenarios:
        raise SystemExit("No scenarios selected.")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out or ROOT / "test-results" / f"e2e-{stamp}-{args.agent}-{args.backend}")
    out_dir.mkdir(parents=True, exist_ok=True)
    summary, total_fail = [], 0

    for sc in scenarios:
        for rep in range(args.repeat):
            backend, now = make_backend(args.backend, sc, lab)
            agent = make_agent(args.agent, contract, now, args.model)
            session = ToolSession(backend, contract.approved_tools)
            t0 = time.time()
            error = None
            try:
                for turn in sc["turns"]:
                    agent.run_turn(session, turn)
            except Exception as e:  # noqa: BLE001 - record harness/model errors as a failed run
                error = f"{type(e).__name__}: {e}"
                if session.turns and not session.turns[-1]["reply"]:
                    session.end_turn(f"[harness error] {error}")
            elapsed = time.time() - t0
            tr = session.transcript()
            result = grade(tr, sc.get("expect", {}), contract)
            if error:
                result.add("Run completed without harness/model error", False, error)
            bad_rows = schema_check_rows(tr)
            result.add("Tool rows validate against timeline-event.schema.json", not bad_rows, "; ".join(bad_rows[:3]))

            report_json_errs = None
            report_turn = sc.get("expect", {}).get("report_turn", len(tr["turns"]) - 1)
            if args.report_json and sc.get("expect", {}).get("report") and hasattr(agent, "report_to_json"):
                try:
                    rj = agent.report_to_json(tr["turns"][report_turn]["reply"])
                    schema = json.loads((ROOT / "schemas/investigation-report.schema.json").read_text())
                    errs = list(Draft202012Validator(schema).iter_errors(rj))
                    report_json_errs = [e.message[:120] for e in errs[:3]]
                    (out_dir / f"{sc['id']}-{rep}.report.json").write_text(json.dumps(rj, indent=2))
                    result.add("Report JSON validates against investigation-report.schema.json", not errs,
                               "; ".join(report_json_errs))
                except Exception as e:  # noqa: BLE001
                    result.add("Report JSON conversion succeeded", False, str(e)[:200])

            tag = f"{sc['id']}" + (f"#{rep + 1}" if args.repeat > 1 else "")
            base = out_dir / f"{sc['id']}-{rep}"
            base.with_suffix(".transcript.json").write_text(json.dumps(tr, indent=2, default=str))
            base.with_suffix(".md").write_text("\n\n---\n\n".join(
                f"**Analyst:** {t['user']}\n\n**Tools:** " + (", ".join(c["tool"] for c in t["calls"]) or "none")
                + f"\n\n{t['reply']}" for t in tr["turns"]))
            base.with_suffix(".grade.json").write_text(json.dumps(result.checks, indent=2))

            n_calls = sum(len(t["calls"]) for t in tr["turns"])
            usage = getattr(agent, "usage", None)
            summary.append(dict(id=tag, title=sc.get("title", ""), passed=result.passed, calls=n_calls,
                                seconds=round(elapsed, 1), failures=result.failures(), usage=usage,
                                note=sc.get("note")))
            mark = "PASS" if result.passed else "FAIL"
            print(f"{mark}  {tag:6} {sc.get('title', '')[:58]:58} calls={n_calls:<3} {elapsed:5.1f}s")
            for f in result.failures():
                print(f"        - {f['id']}" + (f": {f['detail']}" if f["detail"] else ""))
            total_fail += 0 if result.passed else 1

    lines = [f"# LIA e2e results - agent={args.agent} backend={args.backend} model={args.model or '-'}",
             "", f"Run: {stamp}", "", "| Test | Result | Tool calls | Seconds | Failures |", "|---|---|---|---|---|"]
    for s in summary:
        fails = "<br>".join(f"{f['id']}: {f['detail']}"[:160] for f in s["failures"])
        lines.append(f"| {s['id']} {s['title']} | {'PASS' if s['passed'] else 'FAIL'} | {s['calls']} | "
                     f"{s['seconds']} | {fails.replace('|', '/')} |")
    notes = [f"- {s['id']}: {s['note']}" for s in summary if s.get("note")]
    if notes:
        lines += ["", "## Notes", *notes]
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    passed = sum(1 for s in summary if s["passed"])
    print(f"\n{passed}/{len(summary)} passed. Results: {out_dir}")
    return 1 if total_fail else 0


# ---------------------------------------------------------------------------
def kql_smoke(args):
    """Directly exercise each tool: DST handling, guard rows, quoting, row schema."""
    contract = load_contract()
    lab = json.loads(Path(args.lab).read_text()) if args.lab else {"values": {}}
    v = lab.get("values", {})
    if args.backend == "mock":
        backend = MockBackend(build_world())
        v = {"device_id": "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c", "user_upn": "alex.chen@contoso.com",
             "smoke_start_utc": "2026-09-27T14:00:00Z", "smoke_end_utc": "2026-09-27T20:00:00Z",
             "device_name": "ws-fin-0142.contoso.com", **v}
    else:
        backend, _ = make_backend(args.backend, {}, lab)
    ws = contract.approved_workspace
    s, e = v.get("smoke_start_utc"), v.get("smoke_end_utc")
    s48 = "2026-09-20T00:00:00Z"
    e48 = "2026-09-22T00:00:00Z"
    cases = [
        ("normalize DST fall-back", "normalize_time_window",
         dict(StartTimeLocal="2025-11-02 00:30", EndTimeLocal="2025-11-02 03:00", TimeZone="America/Denver"),
         lambda r: r[0]["Status"] == "Valid" and r[0]["StartTimeUtc"] == "2025-11-02T06:30:00Z"
         and r[0]["EndTimeUtc"] == "2025-11-02T10:00:00Z"),
        ("normalize spring-forward gap", "normalize_time_window",
         dict(StartTimeLocal="2026-03-08 02:30", EndTimeLocal="2026-03-08 05:00", TimeZone="America/Denver"),
         lambda r: r[0]["Status"] == "NonexistentLocalTime"),
        ("normalize +05:30", "normalize_time_window",
         dict(StartTimeLocal="2026-09-27 08:00", EndTimeLocal="2026-09-27 12:00", TimeZone="+05:30"),
         lambda r: r[0]["Status"] == "Valid" and r[0]["StartTimeUtc"] == "2026-09-27T02:30:00Z"),
        ("normalize 48h", "normalize_time_window",
         dict(StartTimeLocal="2026-09-25 00:00", EndTimeLocal="2026-09-27 00:00", TimeZone="UTC"),
         lambda r: r[0]["Status"] == "ExceedsMaxWindow"),
        ("normalize CST", "normalize_time_window",
         dict(StartTimeLocal="2026-09-27 08:00", EndTimeLocal="2026-09-27 12:00", TimeZone="CST"),
         lambda r: r[0]["Status"] == "AmbiguousTimeZoneAbbreviation"),
        ("normalize bad IANA", "normalize_time_window",
         dict(StartTimeLocal="2026-09-27 08:00", EndTimeLocal="2026-09-27 12:00", TimeZone="Mars/Olympus"),
         lambda r: r[0]["Status"] == "InvalidTimeZone"),
        ("normalize end before start", "normalize_time_window",
         dict(StartTimeLocal="2026-09-27 12:00", EndTimeLocal="2026-09-27 08:00", TimeZone="UTC"),
         lambda r: r[0]["Status"] == "EndNotAfterStart"),
    ]
    guard = lambda r: len(r) == 1 and r[0].get("SourceTable") == "LIA_GUARD"
    for tool, extra in [("get_device_timeline", dict(DeviceId=v.get("device_id", "0" * 40))),
                        ("get_user_authentication_timeline", dict(UserIdentifier=v.get("user_upn", "a@b.com"))),
                        ("get_related_alerts", dict(EntityIdentifier=v.get("device_id", "0" * 40))),
                        ("get_source_coverage", dict(EntityType="Device", EntityIdentifier=v.get("device_id", "0" * 40))),
                        ("match_observed_indicators", dict(Indicators="198.51.100.23"))]:
        cases.append((f"{tool} 48h -> LIA_GUARD", tool, dict(extra, StartTimeUtc=s48, EndTimeUtc=e48, Workspace=ws), guard))
        cases.append((f"{tool} end<start -> LIA_GUARD", tool, dict(extra, StartTimeUtc=e48, EndTimeUtc=s48, Workspace=ws),
                      guard))
    for tool, key in [("get_device_timeline", "DeviceId"), ("get_user_authentication_timeline", "UserIdentifier"),
                      ("get_related_alerts", "EntityIdentifier")]:
        cases.append((f"{tool} bad identifier -> LIA_GUARD", tool,
                      {key: "not-an-id", "StartTimeUtc": s48, "EndTimeUtc": "2026-09-20T06:00:00Z", "Workspace": ws},
                      guard))
    for tool, key in [("resolve_device", "DeviceName"), ("resolve_user", "UserIdentifier")]:
        cases.append((f"{tool} double quote -> guard or safe error", tool,
                      {key: 'x" or 1==1 //', "Workspace": ws},
                      lambda r: all(str(x.get("ResolutionStatus", "")).startswith("LIA guard") for x in r)))
    if v.get("device_name"):
        cases.append(("resolve_device lab device -> Resolved", "resolve_device",
                      dict(DeviceName=v["device_name"], Workspace=ws),
                      lambda r: r and r[0].get("ResolutionStatus") == "Resolved"))
    if s and e and v.get("device_id"):
        cases.append(("get_source_coverage lab device succeeds", "get_source_coverage",
                      dict(EntityType="Device", EntityIdentifier=v["device_id"], StartTimeUtc=s, EndTimeUtc=e, Workspace=ws),
                      lambda r: len(r) >= 7 and all(x.get("Status") in ("Observed", "NotObserved", "Unavailable") for x in r)))
        cases.append(("get_device_timeline lab device succeeds", "get_device_timeline",
                      dict(DeviceId=v["device_id"], StartTimeUtc=s, EndTimeUtc=e, Workspace=ws),
                      lambda r: all(x.get("SourceTable") != "LIA_GUARD" for x in r)))
    if s and e and v.get("user_upn"):
        cases.append(("get_user_authentication_timeline lab user succeeds", "get_user_authentication_timeline",
                      dict(UserIdentifier=v["user_upn"], StartTimeUtc=s, EndTimeUtc=e, Workspace=ws),
                      lambda r: all(x.get("SourceTable") != "LIA_GUARD" for x in r)))

    schema = Draft202012Validator(json.loads((ROOT / "schemas/timeline-event.schema.json").read_text()))
    fails = 0
    for label, tool, targs, check in cases:
        t0 = time.time()
        try:
            rows = backend.call(tool, targs)
            ok = bool(check(rows))
            detail = "" if ok else json.dumps(rows[:2], default=str)[:300]
            if ok and tool in EVENT_TOOLS:
                errs = [err.message for r in rows for err in schema.iter_errors(r)]
                ok, detail = not errs, "; ".join(errs[:2])
        except ToolError as err:
            safe = "double quote" in label       # a rejected quote is a safe failure
            ok, detail = safe, f"{err.kind}: {err.message[:300]}"
        fails += 0 if ok else 1
        print(f"{'PASS' if ok else 'FAIL'}  {label:55} {time.time() - t0:5.1f}s" + (f"\n        {detail}" if detail and not ok else ""))
    print(f"\n{len(cases) - fails}/{len(cases)} passed")
    return 1 if fails else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", nargs="?", default="run", choices=["run", "kql-smoke", "list"])
    p.add_argument("--agent", default="scripted", choices=["scripted", "claude", "azure-openai"])
    p.add_argument("--backend", default="mock", choices=["mock", "hunting", "mcp"])
    p.add_argument("--model", help="Claude model ID or Azure OpenAI deployment name")
    p.add_argument("-s", "--scenario", help="comma-separated scenario IDs (default: all)")
    p.add_argument("--lab", help="lab config JSON for live backends (see lab.example.json)")
    p.add_argument("--repeat", type=int, default=1, help="run each scenario N times (LLM variance)")
    p.add_argument("--report-json", action="store_true",
                   help="LLM agents: also convert each report to JSON and validate it against the report schema")
    p.add_argument("--out", help="output directory (default test-results/e2e-<stamp>-<agent>-<backend>)")
    args = p.parse_args()
    if args.command == "list":
        for s in SCENARIOS:
            print(f"{s['id']:6} {s['title']}")
        return 0
    if args.command == "kql-smoke":
        return kql_smoke(args)
    return run_scenarios(args)


if __name__ == "__main__":
    sys.exit(main())
