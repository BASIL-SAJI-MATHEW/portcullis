import pytest

from portcullis.config import Config
from portcullis.engine import Engine
from portcullis.firewall import DryRunFirewall
from portcullis.models import AuthEvent
from portcullis.store import Store

T0 = 1_800_000_000.0
BAD = "8.8.4.4"  # a real public address: documentation ranges count as private


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


class Notes:
    def __init__(self):
        self.messages = []

    def __call__(self, text, ip=None):
        self.messages.append((text, ip))


class RefusingFirewall(DryRunFirewall):
    def block(self, ip):
        self.log.append(("block", ip))
        return False


def make(max_failures=3, firewall=None, ban_seconds=3600, dry_run=False):
    cfg = Config()
    cfg.detection.max_failures = max_failures
    cfg.detection.ban_seconds = ban_seconds
    cfg.firewall.dry_run = dry_run
    clock, notes = Clock(), Notes()
    fw = firewall or DryRunFirewall()
    eng = Engine(cfg, Store(), fw, notify=notes, clock=clock)
    return eng, fw, notes, clock


def fail(ip=BAD, user="root", ts=T0):
    return AuthEvent(ts=ts, ip=ip, user=user, service="ssh", success=False)


def test_repeated_failures_ban_block_store_and_notify():
    eng, fw, notes, clock = make()
    assert eng.handle_event(fail()) is None
    assert eng.handle_event(fail()) is None
    verdict = eng.handle_event(fail())
    assert verdict is not None and verdict.kind == "ban"
    assert fw.log == [("block", BAD)]
    bans = eng.store.active_bans(clock())
    assert [b.ip for b in bans] == [BAD] and bans[0].expires == T0 + 3600
    assert BAD in notes.messages[0][0] and notes.messages[0][1] == BAD


def test_every_event_is_recorded_even_when_nothing_is_banned():
    eng, _, _, _ = make()
    eng.handle_event(fail())
    assert len(eng.store.recent_events(10)) == 1


def test_private_and_allow_listed_addresses_are_never_banned():
    eng, fw, notes, _ = make()
    eng.cfg.allowlist.addresses = ["9.9.9.0/24"]
    for ip in ("10.0.0.5", "127.0.0.1", "9.9.9.9"):
        for _ in range(10):
            eng.handle_event(fail(ip=ip))
    assert fw.log == [] and notes.messages == []
    assert eng.store.active_bans(T0) == []


def test_runtime_allow_list_from_the_dashboard_is_respected_and_lifts_an_existing_ban():
    eng, fw, _, clock = make()
    for _ in range(3):
        eng.handle_event(fail())
    eng.allow(BAD, "my office")
    assert eng.store.active_bans(clock()) == []
    assert ("unblock", BAD) in fw.log
    for _ in range(10):
        eng.handle_event(fail())
    assert eng.store.active_bans(clock()) == []


def test_an_already_banned_address_is_not_banned_twice():
    eng, fw, _, _ = make()
    for _ in range(12):
        eng.handle_event(fail())
    assert [e for e in fw.log if e[0] == "block"] == [("block", BAD)]
    assert len(eng.store.active_bans(T0)) == 1


def test_zero_ban_seconds_means_permanent():
    eng, _, _, _ = make(ban_seconds=0)
    for _ in range(3):
        eng.handle_event(fail())
    assert eng.store.active_bans(T0)[0].expires is None


def test_a_failed_firewall_call_is_reported_and_not_recorded_as_a_ban():
    eng, fw, notes, clock = make(firewall=RefusingFirewall())
    for _ in range(3):
        eng.handle_event(fail())
    assert eng.store.active_bans(clock()) == []
    assert "could not block" in notes.messages[0][0].lower()


def test_sweep_unblocks_expired_bans_and_tells_you():
    eng, fw, notes, clock = make()
    for _ in range(3):
        eng.handle_event(fail())
    clock.now = T0 + 3601
    expired = eng.sweep()
    assert [b.ip for b in expired] == [BAD]
    assert ("unblock", BAD) in fw.log
    assert eng.store.active_bans(clock()) == []
    assert any("expired" in m[0].lower() for m in notes.messages)


def test_manual_ban_and_unban():
    eng, fw, _, clock = make()
    ban = eng.ban(BAD, "seen scanning", seconds=600)
    assert ban.source == "manual" and ban.expires == T0 + 600
    assert ("block", BAD) in fw.log
    assert eng.unban(BAD) is True
    assert eng.unban(BAD) is False
    assert eng.store.active_bans(clock()) == []


def test_manual_ban_refuses_protected_and_invalid_addresses():
    eng, _, _, _ = make()
    with pytest.raises(ValueError):
        eng.ban("10.1.2.3", "oops")
    with pytest.raises(ValueError):
        eng.ban("1.2.3.4; reboot", "x")
    eng.cfg.allowlist.addresses = ["9.9.9.9"]
    with pytest.raises(ValueError):
        eng.ban("9.9.9.9", "x")


def test_a_successful_login_after_failures_alerts_but_does_not_ban():
    eng, fw, notes, _ = make(max_failures=10)
    for _ in range(3):
        eng.handle_event(fail())
    verdict = eng.handle_event(AuthEvent(T0, BAD, "root", "ssh", True))
    assert verdict is not None and verdict.kind == "suspicious_success"
    assert fw.log == []
    assert "succeeded" in notes.messages[0][0].lower()


def test_observe_mode_says_so_in_the_alert():
    eng, _, notes, _ = make(dry_run=True)
    for _ in range(3):
        eng.handle_event(fail())
    assert "observe mode" in notes.messages[0][0].lower()


def test_restore_reapplies_active_bans_after_a_restart():
    eng, fw, _, _ = make()
    eng.ban(BAD, "x", seconds=600)
    fw.log.clear()
    assert eng.restore() == 1
    assert fw.log == [("block", BAD)]
