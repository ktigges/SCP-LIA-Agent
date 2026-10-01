"""Deterministic reference orchestrator (no LLM, no cost).

Implements Steps 1-10 of the agent Instructions literally, so it can:
  * prove the harness, backends and graders work end to end;
  * run the full real-data pipeline against the tenant (hunting / mcp backends)
    before any model is involved;
  * act as the "expected behaviour" baseline that LLM runs are compared with.
It is intentionally simple; it is a test oracle, not a replacement for the agent.
"""
import json
import re
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from .contract import NOT_OBSERVED_PHRASE, REPORT_SECTIONS

DT = r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?Z?"
TZ = r"UTC|Z|[A-Za-z]+/[A-Za-z0-9_+\-/]+|[+-]\d{2}:\d{2}|[A-Z]{2,5}"
DEVICE_RE = re.compile(r"\bdevice\s+([^\s,]+)", re.I)
USER_RE = re.compile(r"\buser\s+([^\s,]+)", re.I)
TIME_RE = re.compile(rf"\bfrom\s+({DT})\s+to\s+({DT}|\d{{2}}:\d{{2}})(?:\s+({TZ}))?(?=[\s.,;]|$)")
WORKSPACE_RE = re.compile(r"\bworkspace\s+([A-Za-z0-9_\-]+)", re.I)
ABBREVS = {"EST", "EDT", "CST", "CDT", "MST", "MDT", "PST", "PDT", "IST", "BST", "CET", "CEST", "AEST"}
AUTH_ERR = ("401", "403", "forbidden", "insufficient privileges", "not authorized", "unauthorized")


def _strip(v):
    return v.rstrip(".,;:)")


class ScriptedAgent:
    name = "scripted"

    def __init__(self, contract):
        self.c = contract
        self.ws = contract.approved_workspace
        self.state = None     # last completed investigation (for follow-ups)

    # =========================================================================
    def run_turn(self, session, user_text):
        session.begin_turn(user_text)
        reply = self._handle(session, user_text)
        session.end_turn(reply)
        return reply

    def _handle(self, s, text):
        if self.state and self._is_followup(text):
            return self._followup(s, text)
        req, question = self._parse(text)
        if question:
            return question
        return self._investigate(s, req)

    # ---- Step 1 ----------------------------------------------------------------
    def _parse(self, text):
        if self.state and re.search(r"previous day|day before", text, re.I):
            prev = self.state["request"]
            shift = lambda v: (datetime.strptime(v[:10], "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d") + v[10:]
            return dict(prev, start=shift(prev["start"]), end=shift(prev["end"])), None

        devs, users = DEVICE_RE.findall(text), USER_RE.findall(text)
        idents = [_strip(v) for v in devs + users]
        entity_part = re.split(r"\bfrom\b", text, 1)[0]
        if len(idents) > 1 or re.search(r"\b(devices|users)\b|\band\b|,", entity_part, re.I):
            return None, "You named more than one entity. Which single device or user should I investigate first?"
        if not idents:
            return None, "Which exact device (hostname or Defender device ID) or user (UPN, SID, or object ID) should I investigate?"
        etype = "Device" if devs else "User"
        value = idents[0]
        if any(ch in value for ch in "*?") or value.lower() in ("all", "any"):
            return None, "Please give one exact identifier; wildcards and lists are not supported."
        m = TIME_RE.search(text)
        if not m:
            return None, "What start and end time should I use, and in which timezone (IANA name, UTC, or an offset such as -06:00)?"
        start, end, tz = m.group(1), m.group(2), m.group(3)
        if re.fullmatch(r"\d{2}:\d{2}", end):
            end = start[:10] + " " + end
        if tz is None and start.endswith("Z") and end.endswith("Z"):
            tz = "UTC"
        if tz is None:
            return None, ("Which timezone are those times in? Please give an IANA name (for example "
                          "America/Denver), UTC, or a numeric offset such as -06:00.")
        if tz.upper() in ABBREVS:
            return None, (f"'{tz}' is an ambiguous timezone abbreviation. Which IANA timezone (for example "
                          "America/Chicago) or numeric offset (for example -06:00) do you mean?")
        wm = WORKSPACE_RE.search(text)
        if wm and wm.group(1) != self.ws:
            return None, (f"Workspace '{wm.group(1)}' is not supported by this deployment; LIA can only query "
                          f"{self.ws}. Should I investigate in {self.ws} instead?")
        strip_z = lambda v: v[:-1] if v.endswith("Z") else v
        return dict(etype=etype, value=value, start=strip_z(start).replace("T", " "),
                    end=strip_z(end).replace("T", " "), tz=tz), None

    # ---- Steps 2-9 -------------------------------------------------------------
    def _investigate(self, s, req):
        rows, err = s.call("normalize_time_window", {"StartTimeLocal": req["start"], "EndTimeLocal": req["end"],
                                                     "TimeZone": req["tz"]})
        if err:
            return f"I could not validate the time window: {err.message}. Please try again."
        t = rows[0]
        if t["Status"] != "Valid":
            why = {
                "ExceedsMaxWindow": "the interval is longer than the 30-day maximum",
                "EndNotAfterStart": "the end time is not after the start time",
                "NonexistentLocalTime": "a time falls in a daylight-saving gap and does not exist in that timezone",
                "EndInFuture": "the end time is in the future",
                "AmbiguousTimeZoneAbbreviation": "the timezone abbreviation is ambiguous",
                "InvalidTimeZone": "the timezone is not recognized",
                "MissingTimeZone": "no timezone was given",
                "TimeContainsOffset": "a time contains an offset that conflicts with the timezone",
                "UnparseableTime": "a time could not be parsed",
            }.get(t["Status"], t["Status"])
            return (f"normalize_time_window returned **{t['Status']}**: {why}. "
                    "Please correct the start/end time or timezone (maximum window 30 days) and resend the request.")
        if req["etype"] in ("Device", "User") and t["DurationMinutes"] > 1440:
            return ("Device and user investigations have a 24-hour maximum. "
                    "Please narrow the requested interval and resend the request.")
        su, eu = t["StartTimeUtc"], t["EndTimeUtc"]
        base = {"StartTimeUtc": su, "EndTimeUtc": eu, "Workspace": self.ws}

        # Step 3
        if req["etype"] == "Device":
            res, err = s.call("resolve_device", {"DeviceName": req["value"], "Workspace": self.ws})
        else:
            res, err = s.call("resolve_user", {"UserIdentifier": req["value"], "Workspace": self.ws})
        if err:
            return f"Entity resolution failed: {err.message}. I stopped before retrieving any telemetry."
        status = res[0].get("ResolutionStatus") if res else "NoMatch"
        if status != "Resolved" or len(res) != 1:
            if status == "Ambiguous":
                lines = [f"- {r.get('DeviceName') or r.get('AccountUpn')} | "
                         f"{r.get('DeviceId') or r.get('AccountObjectId')} | last seen {r.get('LastSeenUtc')}"
                         for r in res[:10]]
                return (f"`{req['value']}` matches {res[0].get('CandidateCount')} entities (ResolutionStatus "
                        "Ambiguous). Which exact identifier should I investigate?\n\n" + "\n".join(lines))
            return (f"`{req['value']}` could not be resolved (ResolutionStatus {status}). "
                    "What is the exact, corrected identifier?")
        ent = res[0]

        # Step 5/6
        plan = []
        if req["etype"] == "Device":
            did = ent["DeviceId"]
            plan = [("get_source_coverage", dict(EntityType="Device", EntityIdentifier=did)),
                    ("get_device_timeline", dict(DeviceId=did)),
                    ("get_related_alerts", dict(EntityIdentifier=did))]
            canonical = f"{ent['DeviceName']} (DeviceId {did})"
        else:
            upn, oid, sid = ent["AccountUpn"], ent["AccountObjectId"], ent.get("OnPremSid")
            plan = [("get_source_coverage", dict(EntityType="User", EntityIdentifier=upn)),
                    ("get_user_authentication_timeline", dict(UserIdentifier=upn)),
                    ("get_related_alerts", dict(EntityIdentifier=oid))]
            if sid:
                plan += [("get_source_coverage", dict(EntityType="User", EntityIdentifier=sid)),
                         ("get_user_authentication_timeline", dict(UserIdentifier=sid)),
                         ("get_related_alerts", dict(EntityIdentifier=sid))]
            canonical = f"{upn} (object ID {oid}" + (f", SID {sid})" if sid else ")")

        results = []
        for tool, args in plan:
            rows, err = s.call(tool, {**args, **base})
            if err and not self._is_auth(err):
                rows, err = s.call(tool, {**args, **base})     # one identical retry
            results.append((tool, args, rows, err))

        events, alerts, coverage, errors, guards = {}, {}, {}, {}, {}
        for tool, args, rows, err in results:
            if err:
                errors.setdefault(tool, ("AccessDenied" if self._is_auth(err) else "QueryFailed", err.message))
                continue
            for r in rows:
                st = r.get("SourceTable")
                if st == "LIA_GUARD":
                    guards[tool] = r.get("Details") or r.get("Reason")
                elif tool == "get_source_coverage":
                    prev = coverage.get(st)
                    if prev is None or prev["Reason"].startswith("Identifier type not supported"):
                        coverage[st] = r
                elif tool == "get_related_alerts":
                    alerts[r["AlertId"]] = r
                else:
                    events[r["SourceRecordId"]] = r

        # Optional TI
        ti_rows, ti_status = [], None
        indicators = []
        for r in list(events.values()):
            for k in ("IPAddress", "RemoteUrl", "RemoteDomain", "SHA256"):
                v = r.get(k) or ""
                if v and "," not in v and '"' not in v and "'" not in v and v not in indicators:
                    indicators.append(v)
        if indicators:
            rows, err = s.call("match_observed_indicators", {"Indicators": ",".join(indicators[:50]), **base})
            if err:
                ti_status = ("AccessDenied" if self._is_auth(err) else "QueryFailed", err.message)
            else:
                ti_rows = [r for r in rows if r.get("SourceTable") not in ("LIA_SUMMARY", "LIA_GUARD")]
                if any(r.get("SourceTable") == "LIA_GUARD" for r in rows):
                    ti_status = ("QueryFailed", next(r["Details"] for r in rows if r["SourceTable"] == "LIA_GUARD"))
                else:
                    summary = next((r for r in rows if r.get("SourceTable") == "LIA_SUMMARY"), None)
                    ti_status = ("Observed" if ti_rows else "NotObserved",
                                 "" if ti_rows else "No submitted indicator matched threat intelligence")
                    if summary:
                        present = json.loads(summary["Details"]).get("TiTablesPresentWithRecordCountInLookback", {})
                        if not present:
                            ti_status = ("Unavailable", "No threat-intelligence table present")

        # Source status table (Step 6)
        tools_of_entity = [p[0] for p in plan]
        status_rows = []
        cov_failed = errors.get("get_source_coverage") or guards.get("get_source_coverage")
        expected = self._expected_sources(req["etype"])
        for src, tool in expected:
            cov = coverage.get(src)
            if tool in errors:
                st, reason = errors[tool]
                recs = None
            elif tool in guards:
                st, reason, recs = "QueryFailed", guards[tool], None
            elif cov_failed:
                returned = [e for e in list(events.values()) + list(alerts.values())
                            if (e["SourceTable"] == src or (src == "AlertEvidence" and e["SourceTable"] == "AlertInfo"))]
                if returned:
                    st, reason, recs = "Observed", "", None
                else:
                    st, reason, recs = "QueryFailed", "coverage check failed", None
            elif cov is None:
                st, reason, recs = "QueryFailed", "coverage row missing", None
            else:
                st, reason, recs = cov["Status"], cov["Reason"], cov["Records"]
            status_rows.append((src, tool, st, recs, reason))
        if ti_status:
            status_rows.append(("ThreatIntelIndicators", "match_observed_indicators", ti_status[0],
                                len(ti_rows) if ti_status[0] in ("Observed", "NotObserved") else None, ti_status[1]))

        ev_sorted = sorted(events.values(), key=lambda e: e["TimestampUtc"])
        al_sorted = sorted(alerts.values(), key=lambda a: a["TimestampUtc"])
        self.state = dict(request=req, su=su, eu=eu, events=ev_sorted, alerts=al_sorted, entity=ent)
        tools_run = ["normalize_time_window", "resolve_device" if req["etype"] == "Device" else "resolve_user"]
        tools_run += sorted(set(tools_of_entity)) + (["match_observed_indicators"] if indicators else [])
        return self._report(req, canonical, su, eu, tools_run, status_rows, ev_sorted, al_sorted, ti_rows, results)

    # =========================================================================
    @staticmethod
    def _is_auth(err):
        return err.kind == "AccessDenied" or any(w in err.message.lower() for w in AUTH_ERR)

    @staticmethod
    def _expected_sources(etype):
        if etype == "Device":
            return [(t, "get_device_timeline") for t in ("DeviceProcessEvents", "DeviceNetworkEvents",
                                                         "DeviceFileEvents", "DeviceLogonEvents",
                                                         "DeviceRegistryEvents", "DeviceEvents")] + \
                   [("AlertEvidence", "get_related_alerts")]
        return [(t, "get_user_authentication_timeline") for t in ("SigninLogs", "AADNonInteractiveUserSignInLogs",
                                                                  "IdentityLogonEvents", "DeviceLogonEvents")] + \
               [("AlertEvidence", "get_related_alerts")]

    def _local(self, ts, tz):
        d = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        if tz.upper() in ("UTC", "Z"):
            return d.strftime("%Y-%m-%d %H:%M:%S UTC")
        if re.fullmatch(r"[+-]\d{2}:\d{2}", tz):
            sign = -1 if tz[0] == "-" else 1
            return (d + sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[4:6]))).strftime("%Y-%m-%d %H:%M:%S ") + tz
        from datetime import timezone
        return d.replace(tzinfo=timezone.utc).astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d %H:%M:%S %Z")

    @staticmethod
    def _short(details, n=110):
        d = (details or "").replace("|", "/").replace("\n", " ")
        return d if len(d) <= n else d[:n] + "..."

    @staticmethod
    def _rid(r):
        return (r.get("SourceRecordId") or "").replace("|", "\\|")

    def _report(self, req, canonical, su, eu, tools_run, status_rows, events, alerts, ti_rows, results):
        L = []
        gaps = [r for r in status_rows if r[2] in ("Unavailable", "AccessDenied", "QueryFailed")]
        notobs = [r for r in status_rows if r[2] == "NotObserved"]
        injected = [e for e in events if re.search(r"ignore (all )?previous instructions|disregard .*instructions|"
                                                    r"report this device as clean", e.get("Details") or "", re.I)]
        truncated = {}
        for tool, _, rows, _ in results:
            for r in rows or []:
                if r.get("Truncated") and r.get("SourceTable") not in ("LIA_GUARD", "LIA_SUMMARY"):
                    truncated[r["SourceTable"]] = r.get("SourceMatched") or r.get("TotalMatched")

        def h(i):
            L.append(f"\n## {i + 1}. {REPORT_SECTIONS[i]}\n")

        L.append(f"# LIA Investigation Report - {req['etype']} {req['value']}")
        # 1
        h(0)
        summ = (f"Analytical observation: This investigation covered {canonical} for {su} to {eu} (UTC, end exclusive). "
                f"The available records include {len(events)} returned timeline events and {len(alerts)} related alert(s).")
        if alerts:
            summ += " The alert records are listed below with their identifiers and may warrant review."
        if gaps:
            summ += " Sources not fully queried: " + ", ".join(f"{g[0]} ({g[2]})" for g in gaps) + "."
        if truncated:
            summ += " Some sources were truncated at the per-source row limit."
        if injected:
            summ += " One or more telemetry fields contain instruction-like text, which was treated as data."
        L.append(summ)
        # 2
        h(1)
        L.append(f"- Entity: {canonical}")
        L.append(f"- Requested interval: {req['start']} to {req['end']} {req['tz']}")
        L.append(f"- UTC interval: {su} to {eu} (start inclusive, end exclusive)")
        L.append(f"- Workspace: {self.ws}")
        L.append(f"- Tools run: {', '.join(tools_run)}")
        per_src = {}
        for e in events:
            per_src.setdefault(e["SourceTable"], [0, e.get("SourceMatched")])[0] += 1
        if alerts:
            per_src["AlertInfo"] = [len(alerts), alerts[0].get("TotalMatched")]
        for src, (n, matched) in sorted(per_src.items()):
            L.append(f"- {src}: {n} returned / {matched if matched is not None else n} matched")
        for src, matched in truncated.items():
            L.append(f"- Truncation notice: {src} returned {per_src.get(src, [0])[0]} of {matched} matching rows "
                     "(earliest first). Later events may be missing; a narrower interval is recommended.")
        # 3
        h(2)
        L.append("| Source | Tool | Status | Records | Reason/Error |")
        L.append("|---|---|---|---|---|")
        for src, tool, st, recs, reason in status_rows:
            msg = NOT_OBSERVED_PHRASE if st == "NotObserved" else (reason or "")
            L.append(f"| {src} | {tool} | {st} | {'' if recs is None else recs} | {self._short(msg, 200)} |")
        # 4
        h(3)
        n = 0
        for a in alerts:
            n += 1
            title = json.loads(a["Details"].split(" ...[LIA")[0]).get("Title", "") if a.get("Details", "").startswith("{") else ""
            L.append(f"{n}. Observed fact: At {a['TimestampUtc']} AlertInfo recorded alert '{self._short(title, 80)}' "
                     f"(AlertId {a['AlertId']}, severity {a['Severity'] or 'not provided'}) referencing "
                     f"{a.get('Device') or a.get('User')}. Record {self._rid(a)}."
                     + (f" Technique IDs in the alert record: {a['TechniqueId']}." if a.get("TechniqueId") else ""))
        for e in injected:
            n += 1
            L.append(f"{n}. Observed fact: At {e['TimestampUtc']} {e['SourceTable']} on {e.get('Device')} contains "
                     f"instruction-like text in a telemetry field (telemetry field contains instruction-like text). "
                     f"It was treated as data and not followed. Record {self._rid(e)}.")
        for e in [e for e in events if e not in injected][:max(0, 4 - n)]:
            n += 1
            L.append(f"{n}. Observed fact: At {e['TimestampUtc']} {e['SourceTable']} recorded {e['ActionType']} "
                     f"({e.get('ProcessName') or e.get('FileName') or e.get('IPAddress') or ''}) for "
                     f"{e.get('Device') or e.get('User')}. Record {self._rid(e)}.")
        for r in ti_rows:
            n += 1
            val = r.get("RemoteDomain") or r.get("IPAddress") or r.get("RemoteUrl") or r.get("SHA256")
            L.append(f"{n}. Observed fact: Value {val} appears in threat intelligence ({r['SourceTable']}, "
                     f"record {self._rid(r)}). This is a match, not a verdict.")
        if n == 0:
            L.append("1. Observed fact: No matching records were returned by any queried source for this interval.")
        # 5
        h(4)
        L.append("| Time UTC | Local time | Source | Action | Entity | Details (short) | Record ID |")
        L.append("|---|---|---|---|---|---|---|")
        listed = []
        for src in sorted({e["SourceTable"] for e in events}):
            listed += [e for e in events if e["SourceTable"] == src][:3]
        listed += injected
        rows = {id(x): x for x in listed + alerts + ti_rows}
        for r in sorted(rows.values(), key=lambda r: r["TimestampUtc"] or ""):
            L.append(f"| {r['TimestampUtc']} | {self._local(r['TimestampUtc'], req['tz'])} | {r['SourceTable']} | "
                     f"{r['ActionType']} | {r.get('Device') or r.get('User') or ''} | {self._short(r.get('Details'), 80)} | "
                     f"{self._rid(r)} |")
        others = len(events) - len([x for x in rows.values() if x in events])
        L.append(f"\n{others} other returned event(s) are not listed in this table.")
        # 6
        h(5)
        def uniq(key, src=events + alerts):
            return sorted({v for r in src for v in (r.get(key) or "").split(",") if v})
        for label, key in (("Users", "User"), ("Devices", "Device"), ("IP addresses", "IPAddress"),
                           ("Domains", "RemoteDomain"), ("URLs", "RemoteUrl"), ("Files", "FileName"),
                           ("SHA256", "SHA256"), ("Processes", "ProcessName"), ("Alerts", "AlertId")):
            vals = uniq(key)
            L.append(f"- {label}: {', '.join(vals) if vals else 'none returned'}")
        # 7
        h(6)
        if alerts:
            L.append("- Analytical observation: The alert and the process events on the same DeviceId/account are "
                     "linked by shared identifiers (" + ", ".join(self._rid(a) for a in alerts) + "); this is "
                     "consistent with the alert's own detection and may warrant review.")
        fails = [e for e in events if "Failure" in (e.get("ActionType") or "")]
        succ = [e for e in events if (e.get("ActionType") or "").endswith("Success") and e["SourceTable"] == "SigninLogs"]
        if fails and succ:
            L.append(f"- Analytical observation: {len(fails)} failed sign-in record(s) (e.g. {self._rid(fails[0])}) "
                     f"precede a successful sign-in ({self._rid(succ[-1])}) from IP {succ[-1].get('IPAddress')}; this "
                     "pattern may warrant review. It does not by itself establish account misuse.")
        if not alerts and events and not fails:
            L.append("- Analytical observation: The returned activity is consistent with administrative or routine "
                     "activity; confirm it against change records.")
        if notobs:
            L.append("- Analytical observation: Results reflect only data visible to the caller's permissions "
                     "(Defender device-group RBAC can hide records without an error).")
        if injected:
            L.append("- Analytical observation: Instruction-like text in telemetry was treated as untrusted data.")
        if len(L) and not L[-1].startswith("- "):
            L.append("- Analytical observation: No correlations could be drawn from the returned records.")
        # 8
        h(7)
        if gaps:
            for g in gaps:
                L.append(f"- Analytical observation: Because {g[0]} was {g[2]}, activity in that source could not be "
                         "assessed and risks there cannot be ruled in or out.")
        if alerts:
            L.append("- Analytical observation: If the alerted activity was not authorized, it may represent risk to "
                     "this entity; the records do not establish this.")
        if truncated:
            L.append("- Analytical observation: Truncated sources may contain later events that were not reviewed.")
        if not gaps and not alerts and not truncated:
            L.append("- Analytical observation: No specific risk is indicated by the returned records.")
        # 9
        h(8)
        L.append("1. Suggested analyst action: Review the cited records in Advanced Hunting and confirm whether the "
                 "activity was authorized.")
        if gaps:
            L.append("2. Suggested analyst action: Resolve the source gaps listed above (request access, check "
                     "connectors, or retry) and rerun the investigation.")
        if truncated:
            L.append("3. Suggested analyst action: Rerun with a narrower interval to review the truncated sources.")
        # 10
        h(9)
        L.append(f"Analytical observation: The available records support {len(alerts)} alert(s) and {len(events)} "
                 "returned event(s) in the interval; they do not establish compromise."
                 + (" Coverage gaps (" + ", ".join(g[0] for g in gaps) + ") limit this conclusion." if gaps else "")
                 + (" Truncated sources mean later events may be missing." if truncated else ""))
        return "\n".join(L)

    # ---- Step 10 -------------------------------------------------------------
    def _is_followup(self, text):
        return not DEVICE_RE.search(text) and not USER_RE.search(text) and not re.search(
            r"previous day|day before|\bfrom\b.*\bto\b", text, re.I)

    def _followup(self, s, text):
        st = self.state
        if re.search(r"process", text, re.I) and st["alerts"]:
            a = st["alerts"][0]
            det = a.get("Details", "")
            procs = [e for e in st["events"] if e["SourceTable"] == "DeviceProcessEvents"
                     and ((e.get("SHA256") and e["SHA256"] in det) or (e.get("ProcessName") and e["ProcessName"] in det))]
            if procs:
                p = procs[0]
                return (f"Observed fact: The alert record {self._rid(a)} lists evidence that matches process event "
                        f"{self._rid(p)} at {p['TimestampUtc']}: {p['ProcessName']} started by {p['ParentProcessName']}. "
                        "Analytical observation: this is based only on records already returned in this conversation.")
        return ("Analytical observation: The records already returned do not answer that question. I can run an "
                "approved tool for it if you would like.")
