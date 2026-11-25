"""Turn raw log lines and Windows event XML into AuthEvent objects.

Everything here is a pure function: no I/O, no clock reads (the caller passes ``now``), so it is
easy to test and safe to run on attacker-controlled text.
"""

from __future__ import annotations

import ipaddress
import re
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from .models import AuthEvent

MAX_LINE = 4096
MAX_USER = 64

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s")
_ISO_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\S+)\s")
_IP = r"([0-9A-Fa-f:.]+)"
# sshd logs both "Invalid user X" and "Failed password for invalid user X" for one attempt, so
# only the "Failed ..." line counts. That keeps one attempt from being counted twice.
_FAILED = re.compile(
    r"sshd(?:\[\d+\])?: Failed (?:password|publickey|keyboard-interactive/pam|none) "
    r"for (?:invalid user )?(\S+) from " + _IP + r" port \d+")
_ACCEPTED = re.compile(
    r"sshd(?:\[\d+\])?: Accepted \S+ for (\S+) from " + _IP + r" port \d+")


def _clean_ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _clean_user(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable())[:MAX_USER]


def _line_timestamp(line: str, now: float) -> float:
    match = _ISO_TS.match(line)
    if match:
        try:
            parsed = datetime.fromisoformat(match.group(1))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.timestamp()
        except ValueError:
            return now
    match = _SYSLOG_TS.match(line)
    if match and match.group(1) in _MONTHS:
        mon, day, hh, mm, ss = (_MONTHS[match.group(1)], *map(int, match.groups()[1:]))
        year = datetime.fromtimestamp(now, UTC).year
        try:
            ts = datetime(year, mon, day, hh, mm, ss, tzinfo=UTC)
            if ts.timestamp() > now + 86400:  # syslog has no year: a "future" date is last year
                ts = ts.replace(year=year - 1)
            return ts.timestamp()
        except ValueError:
            return now
    return now


def parse_ssh_line(line: str, now: float | None = None) -> AuthEvent | None:
    """Parse one sshd log line. Returns None for anything that is not a login result."""
    if not line or len(line) > MAX_LINE:
        return None
    now = time.time() if now is None else now
    for pattern, success in ((_FAILED, False), (_ACCEPTED, True)):
        match = pattern.search(line)
        if match:
            ip = _clean_ip(match.group(2))
            if ip is None:
                return None
            return AuthEvent(
                ts=_line_timestamp(line, now), ip=ip, user=_clean_user(match.group(1)),
                service="ssh", success=success)
    return None


# ---------------------------------------------------------------- Windows


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _windows_time(text: str) -> float | None:
    fixed = re.sub(r"(\.\d{6})\d+", r"\1", text.strip()).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(fixed)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _one_windows_event(node: ET.Element) -> AuthEvent | None:
    event_id = uid = when = None
    data: dict[str, str] = {}
    for child in node.iter():
        name = _local(child.tag)
        if name == "EventID":
            event_id = (child.text or "").strip()
        elif name == "EventRecordID":
            uid = (child.text or "").strip()
        elif name == "TimeCreated":
            when = child.get("SystemTime")
        elif name == "Data" and child.get("Name"):
            data[child.get("Name", "")] = (child.text or "").strip()
    if event_id not in ("4624", "4625") or not when:
        return None
    logon_type = data.get("LogonType", "")
    if event_id == "4625" and logon_type not in ("3", "10"):
        return None
    if event_id == "4624" and logon_type != "10":
        return None
    ip = _clean_ip(data.get("IpAddress", ""))
    if ip is None or ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_unspecified:
        return None
    ts = _windows_time(when)
    if ts is None:
        return None
    return AuthEvent(
        ts=ts, ip=ip, user=_clean_user(data.get("TargetUserName", "")), service="rdp",
        success=event_id == "4624", uid=uid or "")


def parse_windows_events(blob: str) -> list[AuthEvent]:
    """Parse the XML that ``wevtutil qe Security /f:xml`` prints (several <Event> elements)."""
    if not blob or not blob.strip():
        return []
    if "<!DOCTYPE" in blob or "<!ENTITY" in blob:  # refuse entity tricks outright
        return []
    body = re.sub(r"<\?xml[^>]*\?>", "", blob)
    try:
        root = ET.fromstring(f"<Events>{body}</Events>")  # noqa: S314 (DOCTYPE rejected above)
    except ET.ParseError:
        return []
    events = []
    for node in root:
        if _local(node.tag) == "Event":
            parsed = _one_windows_event(node)
            if parsed is not None:
                events.append(parsed)
    return events
