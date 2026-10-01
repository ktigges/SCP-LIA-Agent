"""Mock tool backend: Python reference implementations of the kql/*.kql tools.

Each function mirrors its KQL file's guard, filters, projection, per-source cap,
Details truncation and truncation metadata over the synthetic world in world.py.

Faults (per scenario):
  missing_tables   tables absent from Advanced Hunting. Every KQL uses a strict
                   union, so a tool that references a missing table FAILS with a
                   semantic error, exactly as it would in the tenant.
  access_denied    {tool: message}   -> ToolError(kind="AccessDenied")
  query_failed     {tool: message}   -> ToolError(kind="QueryFailed")
"""
import json
import re
from datetime import datetime, timedelta

from . import timewin
from .world import dumps


class ToolError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind          # "AccessDenied" | "QueryFailed"
        self.message = message


MAX_WINDOW = timedelta(hours=24)
MAX_PER_SOURCE = 10
MAX_DETAILS = 512
MAX_ALERTS = 25
MAX_TI = 25
MAX_INDICATORS = 50
TI_LOOKBACK = timedelta(days=30)
LOOKBACK = timedelta(days=30)
DEFENDER_RETENTION = timedelta(days=30)
SENTINEL_RETENTION = timedelta(days=30)

UPN_RE = re.compile(r"^[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z][A-Za-z]+$")
SID_RE = re.compile(r"^S-1-[0-9]+(-[0-9]+)+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]*(\.[A-Za-z0-9][A-Za-z0-9\-]*)*$")

TOOL_TABLES = {
    "normalize_time_window": [],
    "resolve_device": ["DeviceInfo"],
    "resolve_user": ["IdentityInfo"],
    "get_device_timeline": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
                            "DeviceLogonEvents", "DeviceRegistryEvents", "DeviceEvents"],
    "get_user_authentication_timeline": ["SigninLogs", "AADNonInteractiveUserSignInLogs",
                                         "IdentityLogonEvents", "DeviceLogonEvents"],
    "get_related_alerts": ["AlertEvidence", "AlertInfo"],
    "match_observed_indicators": ["ThreatIntelIndicators", "ThreatIntelligenceIndicator"],
    "get_source_coverage": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
                            "DeviceRegistryEvents", "DeviceEvents", "DeviceLogonEvents", "AlertEvidence",
                            "SigninLogs", "AADNonInteractiveUserSignInLogs", "IdentityLogonEvents"],
}


def _is_devid(s):
    return len(s) == 40 and bool(HEX_RE.match(s))


def _is_upn(s):
    return 5 <= len(s) <= 256 and bool(UPN_RE.match(s))


def _is_sid(s):
    return 3 <= len(s.split("-")) <= 16 and bool(SID_RE.match(s))


def _is_guid(s):
    return (len(s) == 36 and s[8] == s[13] == s[18] == s[23] == "-" and bool(re.match(r"^[0-9a-fA-F-]+$", s)))


def _todatetime(s):
    s = (s or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%MZ", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def _ieq(a, b):
    return bool(a) and bool(b) and str(a).lower() == str(b).lower()


def _fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _details(obj):
    s = dumps(obj)
    if len(s) > MAX_DETAILS:
        s = s[:MAX_DETAILS] + " ...[LIA: Details truncated]"
    return s


def _user(upn, domain, name):
    if upn:
        return upn
    if name and domain:
        return f"{domain}\\{name}"
    return name or ""


def _domain_of(url):
    m = re.match(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*://)?(?:[^@/]*@)?([^/:?#\[\]]+)", url or "")
    return m.group(1).lower() if m and url else ""


EMPTY_EVENT = dict(User="", Device="", IPAddress="", RemoteUrl="", RemoteDomain="", FileName="", SHA256="",
                   ProcessName="", ParentProcessName="", AlertId="", Severity="", TechniqueId="")


def _guard_row(msg):
    return dict(TimestampUtc=None, SourceTable="LIA_GUARD", EventCategory="Diagnostic", ActionType="",
                **EMPTY_EVENT, SourceRecordId="", Details=msg)


class MockBackend:
    name = "mock"

    def __init__(self, world, faults=None):
        self.world = world
        self.faults = faults or {}
        self.world["missing_tables"] = set(self.faults.get("missing_tables", []))

    # ---- dispatch -------------------------------------------------------------
    def call(self, tool, args):
        if tool in self.faults.get("access_denied", {}):
            raise ToolError("AccessDenied", self.faults["access_denied"][tool])
        if tool in self.faults.get("query_failed", {}):
            raise ToolError("QueryFailed", self.faults["query_failed"][tool])
        missing = [t for t in TOOL_TABLES.get(tool, []) if t in self.world["missing_tables"]]
        if missing:
            raise ToolError("QueryFailed",
                            f"Semantic error: 'union' operator: Failed to resolve table expression named "
                            f"'{missing[0]}'")
        fn = getattr(self, tool, None)
        if fn is None:
            raise ToolError("QueryFailed", f"Tool '{tool}' is not in the collection")
        rows = fn(**{k: ("" if v is None else str(v)) for k, v in args.items()})
        return json.loads(dumps(rows))

    def _rows(self, table):
        return self.world["tables"][table]

    @property
    def now(self):
        return self.world["now"]

    # ---- normalize_time_window -----------------------------------------------
    def normalize_time_window(self, StartTimeLocal="", EndTimeLocal="", TimeZone="", **_):
        return timewin.normalize_time_window(StartTimeLocal, EndTimeLocal, TimeZone, self.now)

    # ---- resolvers ----------------------------------------------------------
    def resolve_device(self, DeviceName="", Workspace="", **_):
        raw = DeviceName.strip()
        is_id = _is_devid(raw)
        guard = 1 <= len(raw) <= 255 and (is_id or bool(HOST_RE.match(raw)))
        low = raw.lower()
        by_id = {}
        if guard:
            for r in self._rows("DeviceInfo"):
                if r["TimeGenerated"] < self.now - LOOKBACK:
                    continue
                name = r["DeviceName"].lower()
                short = name.split(".")[0]
                if is_id and _ieq(r["DeviceId"], raw):
                    mt = "DeviceId"
                elif not is_id and name == low:
                    mt = "ExactName"
                elif not is_id and short == low:
                    mt = "ShortName"
                else:
                    continue
                cur = by_id.get(r["DeviceId"])
                first = min(cur["FirstSeenInLookback"], r["TimeGenerated"]) if cur else r["TimeGenerated"]
                if not cur or r["TimeGenerated"] > cur["LastSeenUtc"]:
                    by_id[r["DeviceId"]] = dict(
                        DeviceId=r["DeviceId"], DeviceName=r["DeviceName"], OSPlatform=r["OSPlatform"],
                        OSVersion=r["OSVersion"], MachineGroup=r["MachineGroup"],
                        OnboardingStatus=r["OnboardingStatus"], PublicIP=r["PublicIP"], MatchType=mt,
                        LastSeenUtc=r["TimeGenerated"])
                by_id[r["DeviceId"]]["FirstSeenInLookback"] = first
        cands = sorted(by_id.values(), key=lambda c: c["LastSeenUtc"], reverse=True)
        n = len(cands)
        rows = cands[:10]
        if not guard or n == 0:
            rows.append(dict(DeviceId="", DeviceName="", OSPlatform="", OSVersion="", MachineGroup="",
                             OnboardingStatus="", PublicIP="", MatchType="None" if guard else "LIA_GUARD",
                             LastSeenUtc=None, FirstSeenInLookback=None))
        status = ("LIA guard: identifier failed format validation" if not guard else
                  "NoMatch" if n == 0 else "Resolved" if n == 1 else "Ambiguous")
        for r in rows:
            r.update(CandidateCount=n, ResolutionStatus=status, Workspace=Workspace, SourceTable="DeviceInfo")
        return rows

    def resolve_user(self, UserIdentifier="", Workspace="", **_):
        raw = UserIdentifier.strip()
        upn, sid, guid = _is_upn(raw), _is_sid(raw), _is_guid(raw)
        guard = 1 <= len(raw) <= 256 and (upn or sid or guid)
        by_id = {}
        if guard:
            for r in self._rows("IdentityInfo"):
                if r["TimeGenerated"] < self.now - LOOKBACK:
                    continue
                if not ((upn and _ieq(r["AccountUpn"], raw)) or (sid and _ieq(r["OnPremSid"], raw))
                        or (guid and _ieq(r["AccountObjectId"], raw))):
                    continue
                cur = by_id.get(r["AccountObjectId"])
                if not cur or r["TimeGenerated"] > cur["LastSeenUtc"]:
                    by_id[r["AccountObjectId"]] = dict(
                        AccountObjectId=r["AccountObjectId"], AccountUpn=r["AccountUpn"], OnPremSid=r["OnPremSid"],
                        AccountDisplayName=r["AccountDisplayName"], AccountName=r["AccountName"],
                        AccountDomain=r["AccountDomain"], MatchType="UPN" if upn else "SID" if sid else "ObjectId",
                        LastSeenUtc=r["TimeGenerated"])
        cands = sorted(by_id.values(), key=lambda c: c["LastSeenUtc"], reverse=True)
        n = len(cands)
        rows = cands[:10]
        if not guard or n == 0:
            rows.append(dict(AccountObjectId="", AccountUpn="", OnPremSid="", AccountDisplayName="", AccountName="",
                             AccountDomain="", MatchType="None" if guard else "LIA_GUARD", LastSeenUtc=None))
        status = ("LIA guard: identifier failed format validation" if not guard else
                  "NoMatch" if n == 0 else "Resolved" if n == 1 else "Ambiguous")
        for r in rows:
            r.update(CandidateCount=n, ResolutionStatus=status, Workspace=Workspace, SourceTable="IdentityInfo")
        return rows

    # ---- shared helpers --------------------------------------------------------
    def _window(self, s, e):
        start, end = _todatetime(s), _todatetime(e)
        ok = start is not None and end is not None and end > start and end - start <= MAX_WINDOW
        return ok, start, end

    def _in(self, table, start, end):
        return [r for r in self._rows(table) if start <= r["TimeGenerated"] < end]

    def _cap_per_source(self, events, workspace):
        total = len(events)
        per = {}
        for e in events:
            per[e["SourceTable"]] = per.get(e["SourceTable"], 0) + 1
        capped = []
        for src in sorted(per):
            rows = sorted([e for e in events if e["SourceTable"] == src], key=lambda e: e["TimestampUtc"])
            for e in rows[:MAX_PER_SOURCE]:
                e["SourceMatched"] = per[src]
                capped.append(e)
        returned = len(capped)
        for e in capped:
            e.update(TotalMatched=total, ReturnedCount=returned, ReturnedLimit=MAX_PER_SOURCE,
                     Truncated=e["SourceMatched"] > MAX_PER_SOURCE, AnyTruncated=total > returned,
                     Workspace=workspace)
        return sorted(capped, key=lambda e: e["TimestampUtc"])

    def _guarded(self, msg, workspace, limit, extra=None):
        row = _guard_row(msg)
        row.update(TotalMatched=0, ReturnedLimit=limit, Truncated=False, Workspace=workspace, **(extra or {}))
        return [row]

    # ---- get_device_timeline -------------------------------------------------
    def get_device_timeline(self, DeviceId="", StartTimeUtc="", EndTimeUtc="", Workspace="", **_):
        dev = DeviceId.strip().lower()
        ok, s, e = self._window(StartTimeUtc, EndTimeUtc)
        if not (ok and len(dev) == 40 and re.match(r"^[0-9a-f]+$", dev)):
            return self._guarded("LIA guard: invalid DeviceId, unparseable time, EndTimeUtc not after "
                                 "StartTimeUtc, or interval exceeds MaxWindow", Workspace, MAX_PER_SOURCE,
                                 dict(ReturnedCount=0, AnyTruncated=False, SourceMatched=None))
        ev = []
        for r in self._in("DeviceProcessEvents", s, e):
            if _ieq(r["DeviceId"], dev):
                ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="DeviceProcessEvents",
                               EventCategory="Process", ActionType=r["ActionType"],
                               User=_user(r["AccountUpn"], r["AccountDomain"], r["AccountName"]),
                               Device=r["DeviceName"], FileName=r["FileName"], SHA256=r["SHA256"],
                               ProcessName=r["FileName"], ParentProcessName=r["InitiatingProcessFileName"],
                               SourceRecordId=f"DeviceProcessEvents|{r['DeviceId']}|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                               Details=_details(dict(ProcessCommandLine=r["ProcessCommandLine"],
                                                     FolderPath=r["FolderPath"],
                                                     InitiatingProcessCommandLine=r["InitiatingProcessCommandLine"],
                                                     InitiatingProcessParentFileName=r["InitiatingProcessParentFileName"]))))
        for r in self._in("DeviceNetworkEvents", s, e):
            if _ieq(r["DeviceId"], dev):
                ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="DeviceNetworkEvents",
                               EventCategory="Network", ActionType=r["ActionType"],
                               User=_user(r["InitiatingProcessAccountUpn"], r["InitiatingProcessAccountDomain"],
                                          r["InitiatingProcessAccountName"]),
                               Device=r["DeviceName"], IPAddress=r["RemoteIP"], RemoteUrl=r["RemoteUrl"],
                               RemoteDomain=_domain_of(r["RemoteUrl"]), SHA256=r["InitiatingProcessSHA256"],
                               ProcessName=r["InitiatingProcessFileName"],
                               ParentProcessName=r["InitiatingProcessParentFileName"],
                               SourceRecordId=f"DeviceNetworkEvents|{r['DeviceId']}|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                               Details=_details(dict(RemotePort=r["RemotePort"], LocalIP=r["LocalIP"],
                                                     Protocol=r["Protocol"],
                                                     InitiatingProcessCommandLine=r["InitiatingProcessCommandLine"]))))
        for r in self._in("DeviceFileEvents", s, e):
            if _ieq(r["DeviceId"], dev):
                ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="DeviceFileEvents",
                               EventCategory="File", ActionType=r["ActionType"],
                               User=_user(r["InitiatingProcessAccountUpn"], r["InitiatingProcessAccountDomain"],
                                          r["InitiatingProcessAccountName"]),
                               Device=r["DeviceName"], IPAddress=r["RequestSourceIP"], RemoteUrl=r["FileOriginUrl"],
                               RemoteDomain=_domain_of(r["FileOriginUrl"]), FileName=r["FileName"], SHA256=r["SHA256"],
                               ProcessName=r["InitiatingProcessFileName"],
                               ParentProcessName=r["InitiatingProcessParentFileName"],
                               SourceRecordId=f"DeviceFileEvents|{r['DeviceId']}|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                               Details=_details(dict(FolderPath=r["FolderPath"], PreviousFileName=r["PreviousFileName"],
                                                     InitiatingProcessCommandLine=r["InitiatingProcessCommandLine"]))))
        for r in self._in("DeviceLogonEvents", s, e):
            if _ieq(r["DeviceId"], dev):
                ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="DeviceLogonEvents",
                               EventCategory="Logon", ActionType=r["ActionType"],
                               User=_user("", r["AccountDomain"], r["AccountName"]), Device=r["DeviceName"],
                               IPAddress=r["RemoteIP"], ProcessName=r["InitiatingProcessFileName"],
                               ParentProcessName=r["InitiatingProcessParentFileName"],
                               SourceRecordId=f"DeviceLogonEvents|{r['DeviceId']}|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                               Details=_details(dict(LogonType=r["LogonType"], AccountSid=r["AccountSid"],
                                                     RemoteDeviceName=r["RemoteDeviceName"],
                                                     FailureReason=r["FailureReason"], Protocol=r["Protocol"]))))
        # DeviceRegistryEvents / DeviceEvents: no seeded rows; the table is present.
        return self._cap_per_source(ev, Workspace)

    # ---- get_user_authentication_timeline ---------------------------------------
    def get_user_authentication_timeline(self, UserIdentifier="", StartTimeUtc="", EndTimeUtc="", Workspace="", **_):
        raw = UserIdentifier.strip()
        upn, sid, guid = _is_upn(raw), _is_sid(raw), _is_guid(raw)
        ok, s, e = self._window(StartTimeUtc, EndTimeUtc)
        if not (ok and (upn or sid or guid)):
            return self._guarded("LIA guard: invalid UserIdentifier, unparseable time, EndTimeUtc not after "
                                 "StartTimeUtc, or interval exceeds MaxWindow", Workspace, MAX_PER_SOURCE,
                                 dict(ReturnedCount=0, AnyTruncated=False, SourceMatched=None))
        ev = []
        for table, ok_act, bad_act in (("SigninLogs", "SignInSuccess", "SignInFailure"),
                                       ("AADNonInteractiveUserSignInLogs", "NonInteractiveSignInSuccess",
                                        "NonInteractiveSignInFailure")):
            for r in self._in(table, s, e):
                if not ((upn and _ieq(r["UserPrincipalName"], raw)) or (guid and _ieq(r["UserId"], raw))):
                    continue
                det = dict(AppDisplayName=r["AppDisplayName"], ResultType=r["ResultType"],
                           ResultDescription=r["ResultDescription"],
                           ConditionalAccessStatus=r["ConditionalAccessStatus"])
                if table == "SigninLogs":
                    det["AuthenticationRequirement"] = r["AuthenticationRequirement"]
                det.update(Location=r["Location"], UserAgent=r["UserAgent"])
                if table == "SigninLogs":
                    det["RiskLevelDuringSignIn"] = r["RiskLevelDuringSignIn"]
                det["CorrelationId"] = r["CorrelationId"]
                ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable=table,
                               EventCategory="Authentication",
                               ActionType=ok_act if str(r["ResultType"]) == "0" else bad_act,
                               User=r["UserPrincipalName"],
                               Device=(r.get("DeviceDetail") or {}).get("displayName", "") if table == "SigninLogs" else "",
                               IPAddress=r["IPAddress"], SourceRecordId=f"{table}|{r['Id']}", Details=_details(det)))
        for r in self._in("IdentityLogonEvents", s, e):
            if not ((upn and _ieq(r["AccountUpn"], raw)) or (guid and _ieq(r["AccountObjectId"], raw))
                    or (sid and _ieq(r["AccountSid"], raw))):
                continue
            ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="IdentityLogonEvents",
                           EventCategory="Authentication", ActionType=r["ActionType"],
                           User=r["AccountUpn"] or f"{r['AccountDomain']}\\{r['AccountName']}",
                           Device=r["DeviceName"], IPAddress=r["IPAddress"],
                           SourceRecordId=f"IdentityLogonEvents|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                           Details=_details(dict(Application=r["Application"], LogonType=r["LogonType"],
                                                 Protocol=r["Protocol"], FailureReason=r["FailureReason"],
                                                 DestinationDeviceName=r["DestinationDeviceName"]))))
        if sid:
            for r in self._in("DeviceLogonEvents", s, e):
                if _ieq(r["AccountSid"], raw):
                    ev.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="DeviceLogonEvents",
                                   EventCategory="Logon", ActionType=r["ActionType"],
                                   User=f"{r['AccountDomain']}\\{r['AccountName']}", Device=r["DeviceName"],
                                   IPAddress=r["RemoteIP"], ProcessName=r["InitiatingProcessFileName"],
                                   ParentProcessName=r["InitiatingProcessParentFileName"],
                                   SourceRecordId=f"DeviceLogonEvents|{r['DeviceId']}|{r['ReportId']}|{_fmt(r['TimeGenerated'])}",
                                   Details=_details(dict(LogonType=r["LogonType"], FailureReason=r["FailureReason"],
                                                         RemoteDeviceName=r["RemoteDeviceName"],
                                                         DeviceId=r["DeviceId"]))))
        return self._cap_per_source(ev, Workspace)

    # ---- get_related_alerts ----------------------------------------------------
    def get_related_alerts(self, EntityIdentifier="", StartTimeUtc="", EndTimeUtc="", Workspace="", **_):
        raw = EntityIdentifier.strip()
        dev, upn, sid, guid = _is_devid(raw), _is_upn(raw), _is_sid(raw), _is_guid(raw)
        ok, s, e = self._window(StartTimeUtc, EndTimeUtc)
        if not (ok and (dev or upn or sid or guid)):
            return self._guarded("LIA guard: invalid EntityIdentifier, unparseable time, EndTimeUtc not after "
                                 "StartTimeUtc, or interval exceeds MaxWindow", Workspace, MAX_ALERTS)
        evidence = {}
        for r in self._in("AlertEvidence", s, e):
            if not ((dev and _ieq(r.get("DeviceId"), raw)) or (upn and _ieq(r.get("AccountUpn"), raw))
                    or (sid and _ieq(r.get("AccountSid"), raw)) or (guid and _ieq(r.get("AccountObjectId"), raw))):
                continue
            ev = evidence.setdefault(r["AlertId"], dict(roles=[], types=[], devs=[], accts=[], ips=[], urls=[],
                                                        files=[], shas=[]))
            for k, col in (("roles", "EvidenceRole"), ("types", "EntityType"), ("devs", "DeviceName"),
                           ("accts", "AccountUpn"), ("ips", "RemoteIP"), ("urls", "RemoteUrl"),
                           ("files", "FileName"), ("shas", "SHA256")):
                v = r.get(col)
                if v and v not in ev[k]:
                    ev[k].append(v)
        # Evidence for the same alert may reference other entities; gather all evidence rows per AlertId
        # is NOT done by the KQL (it filters evidence by entity first), so neither is it here.
        alerts = []
        for r in self._in("AlertInfo", s, e):
            if r["AlertId"] not in evidence:
                continue
            ev = evidence[r["AlertId"]]
            techs = sorted(set(re.findall(r"\b(T[0-9]{4}(?:\.[0-9]{3})?)\b", r["AttackTechniques"] or "")))
            alerts.append(dict(EMPTY_EVENT, TimestampUtc=r["TimeGenerated"], SourceTable="AlertInfo",
                               EventCategory="Alert", ActionType="AlertGenerated", User=",".join(ev["accts"]),
                               Device=",".join(ev["devs"]), AlertId=r["AlertId"], Severity=r["Severity"],
                               TechniqueId=",".join(techs), SourceRecordId=f"AlertInfo|{r['AlertId']}",
                               Details=_details(dict(Title=r["Title"], Category=r["Category"],
                                                     ServiceSource=r["ServiceSource"],
                                                     DetectionSource=r["DetectionSource"],
                                                     AttackTechniques=r["AttackTechniques"],
                                                     EvidenceRoles=ev["roles"], EvidenceEntityTypes=ev["types"],
                                                     EvidenceIPs=ev["ips"], EvidenceUrls=ev["urls"],
                                                     EvidenceFiles=ev["files"], EvidenceSHA256=ev["shas"]))))
        total = len(alerts)
        alerts = sorted(alerts, key=lambda a: a["TimestampUtc"])[:MAX_ALERTS]
        for a in alerts:
            a.update(TotalMatched=total, ReturnedLimit=MAX_ALERTS, Truncated=total > MAX_ALERTS, Workspace=Workspace)
        return alerts

    # ---- match_observed_indicators ---------------------------------------------
    def match_observed_indicators(self, Indicators="", StartTimeUtc="", EndTimeUtc="", Workspace="", **_):
        parsed = {}
        for v in Indicators.split(","):
            v = v.strip()
            if not v:
                continue
            if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", v):
                kind = "IPv4"
            elif 2 <= len(v) <= 39 and re.match(r"^[0-9A-Fa-f:]+$", v) and ":" in v:
                kind = "IPv6"
            elif len(v) == 64 and HEX_RE.match(v):
                kind = "SHA256"
            elif 1 <= len(v) <= 2048 and re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"']+$", v):
                kind = "URL"
            elif 4 <= len(v) <= 253 and re.match(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z]+$", v):
                kind = "Domain"
            else:
                kind = "Invalid"
            parsed.setdefault(v.lower(), kind)
        valid = {k: v for k, v in parsed.items() if v != "Invalid"}
        valid = dict(list(valid.items())[:MAX_INDICATORS])
        ok, s, e = self._window(StartTimeUtc, EndTimeUtc)
        ok = ok and len(valid) > 0
        common = dict(IndicatorsSubmitted=len(parsed),
                      IndicatorsInvalid=sum(1 for v in parsed.values() if v == "Invalid"),
                      IndicatorsEvaluated=len(valid), Workspace=Workspace, ReturnedLimit=MAX_TI)
        if not ok:
            row = _guard_row("LIA guard: no valid indicators, unparseable time, EndTimeUtc not after StartTimeUtc, "
                             "or interval exceeds MaxWindow")
            row.update(TotalMatched=0, Truncated=False, **common)
            return [row]
        lo = s - TI_LOOKBACK
        matches, presence = [], {}
        for r in self._rows("ThreatIntelIndicators"):
            if not (lo <= r["TimeGenerated"] < e):
                continue
            presence["ThreatIntelIndicators"] = presence.get("ThreatIntelIndicators", 0) + 1
            val = r["ObservableValue"].lower()
            if val in valid and (r["ValidFrom"] is None or r["ValidFrom"] < e) and (
                    r["ValidUntil"] is None or r["ValidUntil"] >= s):
                matches.append(dict(TimeGenerated=r["TimeGenerated"], SourceTable="ThreatIntelIndicators",
                                    MatchedValue=val, TiRecordId=r["Id"],
                                    TiDetails=dict(ObservableKey=r["ObservableKey"], Confidence=r["Confidence"],
                                                   IsActive=r["IsActive"], ValidFrom=r["ValidFrom"],
                                                   ValidUntil=r["ValidUntil"], SourceSystem=r["SourceSystem"])))
        for r in self._rows("ThreatIntelligenceIndicator"):
            if not (lo <= r["TimeGenerated"] < e):
                continue
            presence["ThreatIntelligenceIndicator"] = presence.get("ThreatIntelligenceIndicator", 0) + 1
            cand = next((x for x in (r["NetworkIP"], r["NetworkDestinationIP"], r["NetworkSourceIP"],
                                     r["DomainName"], r["Url"], r["FileHashValue"]) if x), "").lower()
            if cand in valid and (r["ExpirationDateTime"] is None or r["ExpirationDateTime"] >= s):
                matches.append(dict(TimeGenerated=r["TimeGenerated"], SourceTable="ThreatIntelligenceIndicator",
                                    MatchedValue=cand, TiRecordId=r["IndicatorId"],
                                    TiDetails=dict(ThreatType=r["ThreatType"], ConfidenceScore=r["ConfidenceScore"],
                                                   Active=r["Active"], ExpirationDateTime=r["ExpirationDateTime"],
                                                   SourceSystem=r["SourceSystem"], Description=r["Description"])))
        total = len(matches)
        out = []
        for m in sorted(matches, key=lambda m: m["TimeGenerated"], reverse=True)[:MAX_TI]:
            kind = valid[m["MatchedValue"]]
            out.append(dict(EMPTY_EVENT, TimestampUtc=m["TimeGenerated"], SourceTable=m["SourceTable"],
                            EventCategory="ThreatIntelMatch", ActionType="IndicatorMatched",
                            IPAddress=m["MatchedValue"] if kind in ("IPv4", "IPv6") else "",
                            RemoteUrl=m["MatchedValue"] if kind == "URL" else "",
                            RemoteDomain=m["MatchedValue"] if kind == "Domain" else "",
                            SHA256=m["MatchedValue"] if kind == "SHA256" else "",
                            SourceRecordId=f"{m['SourceTable']}|{m['TiRecordId']}",
                            Details=dumps(dict(m["TiDetails"], IndicatorType=kind))))
        present = {t: presence.get(t, 0) for t in ("ThreatIntelIndicators", "ThreatIntelligenceIndicator")}
        out.append(dict(EMPTY_EVENT, TimestampUtc=None, SourceTable="LIA_SUMMARY", EventCategory="Diagnostic",
                        ActionType="IndicatorMatchSummary", SourceRecordId="",
                        Details=dumps(dict(TiTablesPresentWithRecordCountInLookback=present, TiLookbackDays=30))))
        for r in out:
            r.update(TotalMatched=total, Truncated=total > MAX_TI, **common)
        return sorted(out, key=lambda r: (r["TimestampUtc"] is not None, r["TimestampUtc"] or datetime.min))

    # ---- get_source_coverage ---------------------------------------------------
    EXPECTED = [
        ("DeviceProcessEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("DeviceNetworkEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("DeviceFileEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("DeviceLogonEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("DeviceRegistryEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("DeviceEvents", "Device", "Defender", "get_device_timeline", "DeviceId"),
        ("AlertEvidence", "Device", "Defender", "get_related_alerts", "DeviceId"),
        ("SigninLogs", "User", "Sentinel", "get_user_authentication_timeline", "UpnOrGuid"),
        ("AADNonInteractiveUserSignInLogs", "User", "Sentinel", "get_user_authentication_timeline", "UpnOrGuid"),
        ("IdentityLogonEvents", "User", "Defender", "get_user_authentication_timeline", "Any"),
        ("DeviceLogonEvents", "User", "Defender", "get_user_authentication_timeline", "Sid"),
        ("AlertEvidence", "User", "Defender", "get_related_alerts", "Any"),
    ]

    def get_source_coverage(self, EntityType="", EntityIdentifier="", StartTimeUtc="", EndTimeUtc="", Workspace="", **_):
        et, raw = EntityType.strip(), EntityIdentifier.strip()
        is_dev_t, is_user_t = et.lower() == "device", et.lower() == "user"
        dev, upn, sid, guid = _is_devid(raw), _is_upn(raw), _is_sid(raw), _is_guid(raw)
        ok, s, e = self._window(StartTimeUtc, EndTimeUtc)
        guard = ok and ((is_dev_t and dev) or (is_user_t and (upn or sid or guid)))
        tail = dict(EntityType=et, EntityIdentifier=raw, StartTimeUtc=_fmt(s), EndTimeUtc=_fmt(e), Workspace=Workspace)
        if not guard:
            return [dict(SourceTable="LIA_GUARD", Tool="get_source_coverage", Tier="", Status="QueryFailed",
                         Records=None, Reason="LIA guard: invalid EntityType/EntityIdentifier combination, "
                         "unparseable time, EndTimeUtc not after StartTimeUtc, or interval exceeds MaxWindow",
                         RetentionStartUtc=None, **tail)]

        def count(table):
            rows = self._in(table, s, e)
            if table in ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents",
                         "DeviceEvents"):
                return sum(1 for r in rows if is_dev_t and _ieq(r["DeviceId"], raw))
            if table == "DeviceLogonEvents":
                return sum(1 for r in rows if (is_dev_t and _ieq(r["DeviceId"], raw))
                           or (is_user_t and sid and _ieq(r["AccountSid"], raw)))
            if table == "AlertEvidence":
                return len({r["AlertId"] for r in rows if (is_dev_t and _ieq(r.get("DeviceId"), raw)) or (
                    is_user_t and (_ieq(r.get("AccountUpn"), raw) or _ieq(r.get("AccountSid"), raw)
                                   or _ieq(r.get("AccountObjectId"), raw)))})
            if table in ("SigninLogs", "AADNonInteractiveUserSignInLogs"):
                return sum(1 for r in rows if is_user_t and (_ieq(r["UserPrincipalName"], raw) or _ieq(r["UserId"], raw)))
            if table == "IdentityLogonEvents":
                return sum(1 for r in rows if is_user_t and (_ieq(r["AccountUpn"], raw) or _ieq(r["AccountObjectId"], raw)
                                                             or _ieq(r["AccountSid"], raw)))
            return 0

        out = []
        for src, for_ent, tier, tool, needs in self.EXPECTED:
            if (for_ent == "Device") != is_dev_t:
                continue
            applicable = {"DeviceId": dev, "UpnOrGuid": upn or guid, "Sid": sid}.get(needs, True)
            records = count(src)
            retention = DEFENDER_RETENTION if tier == "Defender" else SENTINEL_RETENTION
            outside = s < self.now - retention
            if not applicable:
                status, reason = "Unavailable", f"Identifier type not supported by this table (requires {needs})"
            elif records > 0:
                status = "Observed"
                reason = "Records returned; part of the interval is outside retention" if outside else ""
            elif outside:
                status, reason = "Unavailable", "Requested interval is outside the table's retention"
            else:
                status, reason = "NotObserved", "Query succeeded with zero matching records visible to the caller"
            out.append(dict(SourceTable=src, Tool=tool, Tier=tier, Status=status,
                            Records=records if applicable else None, Reason=reason,
                            RetentionStartUtc=self.now - retention, **tail))
        return sorted(out, key=lambda r: (r["Tool"], r["SourceTable"]))
