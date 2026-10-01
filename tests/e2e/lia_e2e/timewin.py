"""Python reference implementation of kql/normalize-time-window.kql.

Mirrors the KQL status precedence exactly so mock runs exercise the same
Valid / MissingTimeZone / ... / EndInFuture branches the agent sees in the tenant.
Keep in sync with the KQL; the hunting backend's `kql-smoke` command runs the real
query with the same cases so any drift shows up as a mismatch.
"""
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_WINDOW = timedelta(days=30)
FUTURE_TOLERANCE = timedelta(minutes=5)

_UTC_NAMES = {"utc", "z", "etc/utc", "+00:00", "-00:00"}
_OFFSET_RE = re.compile(r"^[+-](0[0-9]|1[0-4]):[0-5][0-9]$")
_IANA_RE = re.compile(r"^[A-Za-z]+(/[A-Za-z0-9_+\-]+)+$")
_ABBREV_RE = re.compile(r"^[A-Za-z]+$")
_EMBEDDED_OFFSET_RE = re.compile(r"T?[0-9:]+[+-][0-9][0-9]:?[0-9][0-9]$")


def _parse_local(raw):
    s = raw.strip()
    if s.endswith("Z"):
        s = s[:-1]
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def fmt_utc(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_time_window(start_local, end_local, tz, now):
    start_raw, end_raw, tz_raw = start_local.strip(), end_local.strip(), tz.strip()
    is_utc = tz_raw.lower() in _UTC_NAMES
    is_offset = not is_utc and bool(_OFFSET_RE.match(tz_raw))
    is_iana = (not is_utc and not is_offset and 2 <= len(tz_raw.split("/")) <= 3
               and bool(_IANA_RE.match(tz_raw)))
    is_abbrev = 2 <= len(tz_raw) <= 5 and bool(_ABBREV_RE.match(tz_raw)) and not is_utc

    start, end = _parse_local(start_raw), _parse_local(end_raw)

    zone = None
    if is_iana:
        try:
            zone = ZoneInfo(tz_raw)
        except (ZoneInfoNotFoundError, ValueError):
            zone = None

    def to_utc(local):
        if local is None:
            return None
        if is_utc:
            return local
        if is_offset:
            sign = -1 if tz_raw[0] == "-" else 1
            hh, mm = int(tz_raw[1:3]), int(tz_raw[4:6])
            return local - sign * timedelta(hours=hh, minutes=mm)
        if is_iana and zone is not None:
            return local.replace(tzinfo=zone).astimezone(timezone.utc).replace(tzinfo=None)
        return None

    def to_local(utc):
        return utc.replace(tzinfo=timezone.utc).astimezone(zone).replace(tzinfo=None)

    start_utc, end_utc = to_utc(start), to_utc(end)
    round_trip_ok = (not is_iana or zone is None or start_utc is None or end_utc is None
                     or (to_local(start_utc) == start and to_local(end_utc) == end))

    if not tz_raw:
        status = "MissingTimeZone"
    elif is_abbrev:
        status = "AmbiguousTimeZoneAbbreviation"
    elif not (is_utc or is_offset or is_iana):
        status = "InvalidTimeZone"
    elif ((not is_utc and (start_raw.endswith("Z") or end_raw.endswith("Z")))
          or _EMBEDDED_OFFSET_RE.search(start_raw) or _EMBEDDED_OFFSET_RE.search(end_raw)):
        status = "TimeContainsOffset"
    elif start is None or end is None:
        status = "UnparseableTime"
    elif start_utc is None or end_utc is None:
        status = "InvalidTimeZone"
    elif not round_trip_ok:
        status = "NonexistentLocalTime"
    elif end_utc <= start_utc:
        status = "EndNotAfterStart"
    elif end_utc - start_utc > MAX_WINDOW:
        status = "ExceedsMaxWindow"
    elif end_utc > now + FUTURE_TOLERANCE:
        status = "EndInFuture"
    else:
        status = "Valid"

    valid = status == "Valid"
    duration = int((end_utc - start_utc).total_seconds() // 60) if start_utc and end_utc else None
    return [{
        "Status": status,
        "StartTimeUtc": fmt_utc(start_utc) if valid else "",
        "EndTimeUtc": fmt_utc(end_utc) if valid else "",
        "DurationMinutes": duration,
        "MaxWindowHours": 720,
        "StartTimeLocal": start_raw,
        "EndTimeLocal": end_raw,
        "TimeZone": tz_raw,
        "SourceTable": "LIA_TIME",
    }]
