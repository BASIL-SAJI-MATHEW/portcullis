from portcullis.sources import LogTail, WindowsEventSource, resolve_ssh_source

WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System><EventID>4625</EventID><TimeCreated SystemTime='2026-11-25T03:14:07.1234567Z'/>
<EventRecordID>{rid}</EventRecordID></System>
<EventData><Data Name='TargetUserName'>admin</Data><Data Name='LogonType'>3</Data>
<Data Name='IpAddress'>203.0.113.9</Data></EventData></Event>"""


def test_tail_reads_only_new_lines_after_start(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    got = []
    tail = LogTail(str(log), got.append)
    tail.poll_once()  # opens the file at the end
    with log.open("a") as fh:
        fh.write("new one\nnew two\n")
    tail.poll_once()
    assert got == ["new one", "new two"]


def test_tail_waits_for_a_file_that_does_not_exist_yet_and_then_reads_it_from_the_start(tmp_path):
    path = tmp_path / "later.log"
    got = []
    tail = LogTail(str(path), got.append)
    assert tail.poll_once() == 0
    path.write_text("first\nsecond\n")
    tail.poll_once()
    assert got == ["first", "second"]


def test_tail_does_not_emit_a_half_written_line_until_it_is_finished(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    got = []
    tail = LogTail(str(log), got.append)
    tail.poll_once()
    with log.open("a") as fh:
        fh.write("partial")
    tail.poll_once()
    assert got == []
    with log.open("a") as fh:
        fh.write(" line\n")
    tail.poll_once()
    assert got == ["partial line"]


def test_tail_survives_log_rotation_by_truncation(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("x\n" * 10)
    got = []
    tail = LogTail(str(log), got.append)
    tail.poll_once()
    log.write_text("after rotate\n")  # shorter than before: the file was replaced
    tail.poll_once()
    assert got == ["after rotate"]


def test_tail_drops_absurdly_long_lines(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    got = []
    tail = LogTail(str(log), got.append)
    tail.poll_once()
    with log.open("a") as fh:
        fh.write("A" * 200_000 + "\nok\n")
    tail.poll_once()
    assert got == ["ok"]


def test_a_crashing_callback_does_not_stop_the_tail(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    seen = []

    def cb(line):
        seen.append(line)
        if line == "bad":
            raise RuntimeError("boom")

    tail = LogTail(str(log), cb)
    tail.poll_once()
    with log.open("a") as fh:
        fh.write("bad\ngood\n")
    tail.poll_once()
    assert seen == ["bad", "good"]


def test_windows_source_reports_each_event_once():
    out = []
    xml = WIN_XML.format(rid=11)
    src = WindowsEventSource(out.append, runner=lambda cmd: (0, xml, ""))
    assert src.poll_once() == 1
    assert src.poll_once() == 0  # same EventRecordID: already seen
    assert [e.uid for e in out] == ["11"]


def test_windows_source_asks_wevtutil_for_security_events_4624_and_4625():
    captured = []

    def runner(cmd):
        captured.append(cmd)
        return 0, "", ""

    WindowsEventSource(lambda e: None, runner=runner, poll_seconds=5).poll_once()
    cmd = captured[0]
    assert cmd[:3] == ["wevtutil", "qe", "Security"] and "/f:xml" in cmd
    assert any("EventID=4625" in part and "EventID=4624" in part for part in cmd)


def test_windows_source_explains_missing_permissions_without_crashing(caplog):
    src = WindowsEventSource(lambda e: None, runner=lambda cmd: (5, "", "Access is denied."))
    assert src.poll_once() == 0
    assert "administrator" in caplog.text.lower()


def test_resolve_ssh_source_prefers_auth_log_then_secure_then_journal():
    have = {"/var/log/secure"}
    assert resolve_ssh_source("auto", exists=lambda p: p in have, which=lambda n: None,
                              is_windows=False) == ("file", "/var/log/secure")
    assert resolve_ssh_source("auto", exists=lambda p: p == "/var/log/auth.log",
                              which=lambda n: "/bin/journalctl",
                              is_windows=False) == ("file", "/var/log/auth.log")
    assert resolve_ssh_source("auto", exists=lambda p: False, which=lambda n: "/bin/journalctl",
                              is_windows=False) == ("journal", "")
    assert resolve_ssh_source("auto", exists=lambda p: False, which=lambda n: None,
                              is_windows=False) == ("off", "")


def test_resolve_ssh_source_explicit_choices_and_windows():
    assert resolve_ssh_source("off", is_windows=False) == ("off", "")
    assert resolve_ssh_source("journal", is_windows=False) == ("journal", "")
    assert resolve_ssh_source("/tmp/x.log", is_windows=False) == ("file", "/tmp/x.log")
    assert resolve_ssh_source("auto", is_windows=True) == ("off", "")
