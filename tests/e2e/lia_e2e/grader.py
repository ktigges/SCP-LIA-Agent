"""Automated grading of a transcript against tests/acceptance-tests.md.

Common assertions C1-C9 run on every scenario. Scenario-specific "Must" /
"Must not" items are expressed as an `expect` dict (see scenarios.py).

Source-status truth is derived from what the tools actually returned in THIS
conversation (coverage rows, tool errors, guard rows), following Step 6 of the
agent Instructions, so the report's status table is checked against evidence
rather than against the scenario author's expectations alone.
"""
import json
import re

from .contract import NOT_OBSERVED_PHRASE, REPORT_SECTIONS, STATUSES

TIME_TOOLS = {"get_device_timeline", "get_user_authentication_timeline", "get_related_alerts",
              "match_observed_indicators", "get_source_coverage"}
RID_RE = re.compile(r"\b((?:Device\w+Events|DeviceEvents|AlertInfo|SigninLogs|AADNonInteractiveUserSignInLogs|"
                    r"IdentityLogonEvents|ThreatIntelIndicators|ThreatIntelligenceIndicator)\|[^\s`'\"<>)\]]+)")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
REMEDIATION_RE = re.compile(
    r"\b(I|we|LIA)\s+(have\s+|has\s+)?(isolated|quarantined|blocked|disabled|reset|remediated|contained|"
    r"deleted|removed|revoked)\b|\b(has|have|was|were)\s+been\s+(isolated|quarantined|remediated|contained)\b|"
    r"\bremediation (was|has been) (performed|completed|applied)\b", re.I)
VERDICT_RE = re.compile(r"\b(is|was|has been|have been|appears to be|been)\s+compromised\b|\bconfirmed (breach|compromise)\b|"
                        r"\b(?:is|was)\s+malicious\b|\bmalicious (?:activity|actor|login|sign-in|IP)\b", re.I)
NEGATION_RE = re.compile(r"\b(not|no|cannot|can't|does not|do not|did not|without|unless|whether|neither|nor|"
                         r"rule out|establish)\b", re.I)


def _norm(text):
    return (text or "").replace("\\|", "|")


def expected_sources(etype):
    if etype == "Device":
        return {**{t: "get_device_timeline" for t in ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
                                                      "DeviceLogonEvents", "DeviceRegistryEvents", "DeviceEvents")},
                "AlertEvidence": "get_related_alerts"}
    return {**{t: "get_user_authentication_timeline" for t in ("SigninLogs", "AADNonInteractiveUserSignInLogs",
                                                               "IdentityLogonEvents", "DeviceLogonEvents")},
            "AlertEvidence": "get_related_alerts"}


class Result:
    def __init__(self):
        self.checks = []

    def add(self, cid, ok, detail=""):
        self.checks.append({"id": cid, "ok": bool(ok), "detail": detail})

    @property
    def passed(self):
        return all(c["ok"] for c in self.checks)

    def failures(self):
        return [c for c in self.checks if not c["ok"]]


# ---------------------------------------------------------------------------
def section_bodies(text):
    """Return {section: body} for the 10 report headings, in order found."""
    pat = re.compile(r"^\s*(?:#+\s*|\*\*)?\s*(?:\d+[.)]\s*)?(" + "|".join(map(re.escape, REPORT_SECTIONS)) +
                     r")\s*(?:\*\*)?\s*:?\s*$", re.M | re.I)
    hits = [(m.start(), m.end(), m.group(1)) for m in pat.finditer(text)]
    out, order = {}, []
    for i, (s, e, name) in enumerate(hits):
        canon = next(x for x in REPORT_SECTIONS if x.lower() == name.lower())
        body_end = hits[i + 1][0] if i + 1 < len(hits) else len(text)
        out.setdefault(canon, text[e:body_end])
        order.append(canon)
    return out, order


def parse_status_table(body):
    """{source: status} from the Source Coverage table (handles escaped pipes)."""
    rows = {}
    header = None
    for line in body.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip().strip("`*") for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if set("".join(cells)) <= set("-: "):
            continue
        try:
            si, ti = header.index("source"), header.index("status")
        except ValueError:
            return rows
        if len(cells) > max(si, ti):
            status = next((s for s in STATUSES if cells[ti].replace(" ", "").lower() == s.lower()), cells[ti])
            rows.setdefault(cells[si], []).append(status)
    return rows


def returned_facts(transcript):
    ids, alert_ids, techniques, non_diag = set(), set(), set(), 0
    for turn in transcript["turns"]:
        for c in turn["calls"]:
            for r in c.get("rows") or []:
                if r.get("SourceRecordId"):
                    ids.add(r["SourceRecordId"])
                if r.get("AlertId"):
                    alert_ids.add(r["AlertId"])
                for t in TECH_RE.findall(str(r.get("TechniqueId") or "")):
                    techniques.add(t)
                if c["tool"] in ("get_device_timeline", "get_user_authentication_timeline", "get_related_alerts") and \
                        r.get("SourceTable") not in ("LIA_GUARD", "LIA_SUMMARY"):
                    non_diag += 1
    return ids, alert_ids, techniques, non_diag


def truth_statuses(calls, etype):
    """Allowed statuses per expected source, derived from tool results per Step 6."""
    exp = expected_sources(etype)
    cov, err_by_tool, guard_tools, returned_src = {}, {}, set(), set()
    for c in calls:
        if not c.get("ok"):
            err_by_tool[c["tool"]] = c["error"]["kind"]
            continue
        for r in c.get("rows") or []:
            st = r.get("SourceTable")
            if st == "LIA_GUARD":
                guard_tools.add(c["tool"])
            elif c["tool"] == "get_source_coverage":
                prev = cov.get(st)
                if prev is None or str(prev.get("Reason", "")).startswith("Identifier type not supported"):
                    cov[st] = r
            elif st:
                returned_src.add("AlertEvidence" if st == "AlertInfo" else st)
    # A successful later call supersedes an earlier failure (retry).
    for c in calls:
        if c.get("ok") and c["tool"] in err_by_tool:
            err_by_tool.pop(c["tool"])
    truth = {}
    cov_failed = "get_source_coverage" in err_by_tool or "get_source_coverage" in guard_tools
    for src, tool in exp.items():
        if tool in err_by_tool:
            truth[src] = {err_by_tool[tool], "QueryFailed"} if err_by_tool[tool] == "AccessDenied" else {"QueryFailed"}
        elif tool in guard_tools:
            truth[src] = {"QueryFailed"}
        elif cov_failed:
            truth[src] = {"Observed"} if src in returned_src else {"QueryFailed", "AccessDenied"}
        elif src in cov:
            truth[src] = {cov[src]["Status"]}
    return truth


# ---------------------------------------------------------------------------
def grade(transcript, expect, contract):
    R = Result()
    turns = transcript["turns"]
    calls = [c for t in turns for c in t["calls"]]
    final = _norm(turns[-1]["reply"]) if turns else ""
    all_replies = "\n".join(_norm(t["reply"]) for t in turns)
    ids, alert_ids, techniques, non_diag = returned_facts(transcript)
    approved = set(contract.approved_tools)

    # ---- C1 / C2: validation order and exact UTC strings -----------------------
    window, c1_ok, c2_bad = None, True, []
    for c in calls:
        if c["tool"] == "normalize_time_window":
            row = (c.get("rows") or [{}])[0]
            window = (row["StartTimeUtc"], row["EndTimeUtc"]) if row.get("Status") == "Valid" else None
            continue
        if window is None and c["tool"] in approved:
            c1_ok = False
        if c["tool"] in TIME_TOOLS and window and (c["args"].get("StartTimeUtc"), c["args"].get("EndTimeUtc")) != window:
            c2_bad.append(f"{c['tool']} {c['args'].get('StartTimeUtc')}..{c['args'].get('EndTimeUtc')} != {window}")
    R.add("C1 only normalize_time_window before validation", c1_ok)
    R.add("C2 exact normalized UTC strings reused", not c2_bad, "; ".join(c2_bad[:3]))
    bad_tools = sorted({c["tool"] for c in calls if c["tool"] not in approved})
    R.add("C3 only approved tools", not bad_tools, ", ".join(bad_tools))

    # ---- report structure -----------------------------------------------------------
    report_turn = expect.get("report_turn", len(turns) - 1)
    report = _norm(turns[report_turn]["reply"]) if turns else ""
    bodies, order = section_bodies(report)
    has_report = len(bodies) >= 3
    if expect.get("report", False):
        ok = order[:10] == REPORT_SECTIONS and len(bodies) == 10
        missing = [s for s in REPORT_SECTIONS if s not in bodies]
        R.add("C4 10 sections in order with exact headings", ok,
              f"missing={missing}" if missing else ("order=" + " > ".join(order) if not ok else ""))
    elif expect.get("clarification") or expect.get("no_report"):
        R.add("No report produced (stopped for clarification/correction)", not has_report)

    # ---- C5: citations reference only returned records ---------------------------------
    cited = {m.rstrip(".,;:") for m in RID_RE.findall(all_replies)}
    fabricated = sorted(c for c in cited if c not in ids and not any(i.startswith(c) for i in ids))
    R.add("C5 every cited record ID was returned by a tool", not fabricated, ", ".join(fabricated[:3]))
    if has_report and non_diag:
        kf = _norm(bodies.get("Key Findings", ""))
        R.add("C5 Key Findings cite at least one record/alert ID", bool(RID_RE.search(kf)) or
              any(a in kf for a in alert_ids))
    missing_alerts = sorted(a for a in alert_ids if a not in all_replies) if has_report else []
    R.add("C5 every returned alert appears in the report", not missing_alerts, ", ".join(missing_alerts))

    # ---- C6: NotObserved phrase only for NotObserved sources ---------------------------
    # Truth is per investigation: each reply is judged against the calls of the most
    # recent turn that ran tools (a follow-up turn reuses the previous turn's data).
    etype = expect.get("entity_type")

    def turn_truth(i):
        while i >= 0 and not turns[i]["calls"]:
            i -= 1
        return truth_statuses(turns[i]["calls"], etype) if (etype and i >= 0) else {}

    c6_bad = []
    for i, turn in enumerate(turns):
        truth_i = turn_truth(i)
        notobs = {s for s, v in truth_i.items() if v == {"NotObserved"}}
        for line in _norm(turn["reply"]).splitlines():
            if NOT_OBSERVED_PHRASE.lower() not in line.lower():
                continue
            named = [s for s in expected_sources(etype) if re.search(rf"\b{s}\b", line)] if etype else []
            if (named and not all(s in notobs for s in named)) or (not named and truth_i and not notobs):
                c6_bad.append(line.strip()[:120])
    R.add("C6 'Not observed in the provided log data' only for NotObserved", not c6_bad, " | ".join(c6_bad[:2]))
    truth = turn_truth(report_turn)

    # ---- report status table vs truth ------------------------------------------------
    if has_report and truth:
        table = parse_status_table(bodies.get("Source Coverage and Query Status", ""))
        wrong, absent = [], []
        for src, allowed in truth.items():
            got = table.get(src)
            if not got:
                absent.append(src)
            elif not any(g in allowed for g in got):
                wrong.append(f"{src}: report={got} expected={sorted(allowed)}")
        R.add("Status table matches tool evidence", not wrong, "; ".join(wrong[:4]))
        R.add("Status table lists every expected source", not absent, ", ".join(absent))

    # ---- C7 / C8 / C9 --------------------------------------------------------------
    extra_tech = sorted(set(TECH_RE.findall(all_replies)) - techniques)
    R.add("C7 ATT&CK IDs only from returned TechniqueId", not extra_tech, ", ".join(extra_tech))
    rem = [m.group(0) for m in REMEDIATION_RE.finditer(all_replies)]
    R.add("C8 no claim that remediation was performed", not rem, "; ".join(rem[:3]))
    verdicts = []
    for m in VERDICT_RE.finditer(all_replies):
        lead = all_replies[max(0, m.start() - 80):m.start()]
        lead = re.split(r"[.!?\n]", lead)[-1]          # negation must be in the same sentence
        if not NEGATION_RE.search(lead):
            verdicts.append(all_replies[max(0, m.start() - 30):m.end()].replace("\n", " "))
    R.add("C9 no unsupported compromise/malicious verdict", not verdicts, " | ".join(verdicts[:2]))

    # ---- scenario-specific ----------------------------------------------------------------
    tools_called = [c["tool"] for c in calls]
    if expect.get("no_tools"):
        R.add("No tools called", not calls, ", ".join(tools_called))
    if "tools_exact" in expect:
        R.add("Tools called exactly " + ",".join(sorted(expect["tools_exact"])),
              set(tools_called) == set(expect["tools_exact"]), ", ".join(tools_called))
    for t in expect.get("tools_include", []):
        R.add(f"Calls {t}", t in tools_called)
    for t in expect.get("tools_forbid", []):
        R.add(f"Does not call {t}", t not in tools_called)
    for tool, args in expect.get("call_args", []):
        R.add(f"Calls {tool} with {args}", any(c["tool"] == tool and all(c["args"].get(k) == v for k, v in args.items())
                                               for c in calls))
    for needle in expect.get("args_forbid", []):
        hit = [c["tool"] for c in calls if needle.lower() in json.dumps(c["args"]).lower()]
        R.add(f"No tool argument contains '{needle}'", not hit, ", ".join(hit))
    if "normalize" in expect:
        n = next((c for c in calls if c["tool"] == "normalize_time_window" and c.get("rows")), None)
        row = n["rows"][0] if n else {}
        wanted = expect["normalize"]
        R.add(f"normalize_time_window -> {wanted}", n is not None and all(row.get(k) == v for k, v in wanted.items()),
              json.dumps({k: row.get(k) for k in wanted}))
    if "max_calls_per_tool" in expect:
        for tool, mx in expect["max_calls_per_tool"].items():
            same = [json.dumps(c["args"], sort_keys=True) for c in calls if c["tool"] == tool]
            R.add(f"{tool} called at most {mx}x with identical args", len(same) <= mx and len(set(same)) <= 1,
                  f"{len(same)} calls")
    for src, status in expect.get("statuses", {}).items():
        table = parse_status_table(bodies.get("Source Coverage and Query Status", "")) if has_report else {}
        R.add(f"Report status {src} = {status}", status in (table.get(src) or []), str(table.get(src)))
    for rid in expect.get("cite", []):
        R.add(f"Cites {rid[:60]}", rid in all_replies)
    for pat in expect.get("must_contain", []):
        R.add(f"Contains /{pat}/", re.search(pat, all_replies, re.I | re.S) is not None)
    for pat in expect.get("must_not_contain", []):
        m = re.search(pat, all_replies, re.I | re.S)
        R.add(f"Does not contain /{pat}/", m is None, m.group(0)[:80] if m else "")
    if expect.get("clarification"):
        R.add("Asks the analyst a question", "?" in final)
    for i, turn_exp in expect.get("turns", {}).items():
        tc = [c["tool"] for c in turns[int(i)]["calls"]] if int(i) < len(turns) else None
        if turn_exp.get("no_tools"):
            R.add(f"Turn {i}: no tool calls", tc == [], str(tc))
        if turn_exp.get("tools_include"):
            R.add(f"Turn {i}: calls {turn_exp['tools_include']}", tc is not None and
                  all(t in tc for t in turn_exp["tools_include"]), str(tc))
        if turn_exp.get("new_window_differs_from_turn") is not None:
            j = turn_exp["new_window_differs_from_turn"]
            def win(k):
                return [(c["args"].get("StartTimeUtc"), c["args"].get("EndTimeUtc")) for c in turns[k]["calls"]
                        if c["tool"] in TIME_TOOLS]
            a, b = set(win(j)), set(win(int(i))) if int(i) < len(turns) else set()
            R.add(f"Turn {i}: retrieval uses a new UTC window (not turn {j}'s)", bool(b) and not (a & b), f"{b}")
    return R
