from datetime import UTC, datetime

from portcullis.parsers import parse_ssh_line, parse_windows_events

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=UTC).timestamp()


def test_ssh_failed_password_for_valid_user():
    line = ("Nov 25 03:14:07 web1 sshd[991]: Failed password for root "
            "from 203.0.113.5 port 4242 ssh2")
    ev = parse_ssh_line(line, now=NOW)
    assert ev is not None
    assert (ev.ip, ev.user, ev.service, ev.success) == ("203.0.113.5", "root", "ssh", False)
    assert datetime.fromtimestamp(ev.ts, UTC) == datetime(2026, 11, 25, 3, 14, 7, tzinfo=UTC)


def test_ssh_failed_password_for_invalid_user():
    line = ("Nov 25 03:14:09 web1 sshd[991]: Failed password for invalid user admin "
            "from 198.51.100.7 port 5000 ssh2")
    ev = parse_ssh_line(line, now=NOW)
    assert ev is not None and ev.user == "admin" and ev.ip == "198.51.100.7"
    assert ev.success is False


def test_ssh_accepted_login_is_success():
    line = ("Nov 25 03:15:00 web1 sshd[995]: Accepted publickey for deploy "
            "from 192.0.2.10 port 6000 ssh2: RSA SHA256:abc")
    ev = parse_ssh_line(line, now=NOW)
    assert ev is not None and ev.success is True and ev.user == "deploy"


def test_ssh_iso_timestamp_line():
    line = ("2026-11-25T03:14:07.123456+00:00 web1 sshd[991]: Failed password for root "
            "from 203.0.113.5 port 4242 ssh2")
    ev = parse_ssh_line(line, now=NOW)
    assert ev is not None
    assert abs(ev.ts - datetime(2026, 11, 25, 3, 14, 7, 123456, tzinfo=UTC).timestamp()) < 1


def test_ssh_ipv6_address():
    line = ("Nov 25 03:14:07 web1 sshd[991]: Failed password for root "
            "from 2001:db8::1 port 4242 ssh2")
    ev = parse_ssh_line(line, now=NOW)
    assert ev is not None and ev.ip == "2001:db8::1"


def test_ssh_invalid_user_line_is_ignored_to_avoid_double_counting():
    line = "Nov 25 03:14:07 web1 sshd[991]: Invalid user admin from 203.0.113.5 port 4242"
    assert parse_ssh_line(line, now=NOW) is None


def test_ssh_unrelated_and_garbage_lines_return_none():
    assert parse_ssh_line("", now=NOW) is None
    assert parse_ssh_line("Nov 25 03:14:07 web1 cron[1]: job done", now=NOW) is None
    assert parse_ssh_line("\x00\xff garbage Failed password", now=NOW) is None


def test_ssh_rejects_lines_whose_address_is_not_an_ip():
    line = ("Nov 25 03:14:07 web1 sshd[991]: Failed password for root "
            "from 999.1.1.1 port 4242 ssh2")
    assert parse_ssh_line(line, now=NOW) is None


def test_ssh_december_log_read_in_january_belongs_to_previous_year():
    jan = datetime(2027, 1, 2, 0, 0, 0, tzinfo=UTC).timestamp()
    line = ("Dec 31 23:59:00 web1 sshd[991]: Failed password for root "
            "from 203.0.113.5 port 4242 ssh2")
    ev = parse_ssh_line(line, now=jan)
    assert ev is not None
    assert datetime.fromtimestamp(ev.ts, UTC).year == 2026


def _event(record_id, event_id, ip, user, logon_type, when="2026-11-25T03:14:07.1234567Z"):
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>{event_id}</EventID><TimeCreated SystemTime='{when}'/>
<EventRecordID>{record_id}</EventRecordID></System>
<EventData>
<Data Name='TargetUserName'>{user}</Data>
<Data Name='LogonType'>{logon_type}</Data>
<Data Name='IpAddress'>{ip}</Data>
</EventData></Event>"""


def test_windows_failed_rdp_logon():
    events = parse_windows_events(_event(77, 4625, "203.0.113.9", "Administrator", 3))
    assert len(events) == 1
    ev = events[0]
    assert (ev.ip, ev.user, ev.service, ev.success, ev.uid) == (
        "203.0.113.9", "Administrator", "rdp", False, "77")
    assert datetime.fromtimestamp(ev.ts, UTC) == datetime(2026, 11, 25, 3, 14, 7, 123456, tzinfo=UTC)


def test_windows_successful_remote_interactive_logon():
    events = parse_windows_events(_event(78, 4624, "198.51.100.2", "alice", 10))
    assert len(events) == 1 and events[0].success is True


def test_windows_console_logon_and_local_addresses_are_ignored():
    blob = (_event(1, 4624, "198.51.100.2", "alice", 2)
            + _event(2, 4625, "-", "bob", 3)
            + _event(3, 4625, "::1", "bob", 3)
            + _event(4, 4625, "127.0.0.1", "bob", 3))
    assert parse_windows_events(blob) == []


def test_windows_multiple_events_and_xml_declaration():
    blob = ('<?xml version="1.0" encoding="UTF-8"?>'
            + _event(5, 4625, "203.0.113.9", "a", 3)
            + _event(6, 4625, "203.0.113.10", "b", 10))
    assert [e.uid for e in parse_windows_events(blob)] == ["5", "6"]


def test_windows_malformed_xml_returns_empty_list():
    assert parse_windows_events("<Event><broken") == []
    assert parse_windows_events("") == []
