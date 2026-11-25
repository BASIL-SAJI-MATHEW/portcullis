from portcullis.detector import Detector, Rules
from portcullis.models import AuthEvent


def fail(ts, ip="203.0.113.5", user="root"):
    return AuthEvent(ts=ts, ip=ip, user=user, service="ssh", success=False)


def ok(ts, ip="203.0.113.5", user="root"):
    return AuthEvent(ts=ts, ip=ip, user=user, service="ssh", success=True)


def test_bans_when_failures_reach_the_limit_inside_the_window():
    d = Detector(Rules(max_failures=5, window_seconds=300, spray_users=99))
    verdicts = [d.feed(fail(t)) for t in range(0, 5)]
    assert verdicts[:4] == [None] * 4
    assert verdicts[4] is not None
    assert (verdicts[4].kind, verdicts[4].ip, verdicts[4].failures) == ("ban", "203.0.113.5", 5)


def test_failures_outside_the_window_do_not_add_up():
    d = Detector(Rules(max_failures=3, window_seconds=60, spray_users=99))
    assert d.feed(fail(0)) is None
    assert d.feed(fail(70)) is None  # the failure at t=0 has expired, so this is the first
    assert d.feed(fail(80)) is None
    assert d.feed(fail(90)) is not None  # 70, 80, 90 are three inside the window


def test_each_ip_is_counted_separately():
    d = Detector(Rules(max_failures=3, window_seconds=300, spray_users=99))
    for t in range(2):
        assert d.feed(fail(t, ip="203.0.113.5")) is None
        assert d.feed(fail(t, ip="203.0.113.6")) is None


def test_password_spray_across_many_usernames_is_banned_early():
    d = Detector(Rules(max_failures=50, window_seconds=300, spray_users=4))
    users = ["admin", "root", "test", "oracle"]
    verdicts = [d.feed(fail(i, user=u)) for i, u in enumerate(users)]
    assert verdicts[:3] == [None, None, None]
    assert verdicts[3] is not None and "spray" in verdicts[3].reason.lower()
    assert set(verdicts[3].users) == set(users)


def test_state_is_cleared_after_a_ban_so_it_is_not_repeated_on_every_line():
    d = Detector(Rules(max_failures=2, window_seconds=300, spray_users=99))
    assert d.feed(fail(0)) is None
    assert d.feed(fail(1)) is not None
    assert d.feed(fail(2)) is None


def test_success_after_several_failures_is_flagged_but_not_banned():
    d = Detector(Rules(max_failures=10, window_seconds=300, spray_users=99, suspicious_after=3))
    for t in range(3):
        assert d.feed(fail(t)) is None
    verdict = d.feed(ok(4))
    assert verdict is not None and verdict.kind == "suspicious_success"
    assert verdict.failures == 3


def test_normal_success_with_no_failures_is_quiet():
    assert Detector(Rules()).feed(ok(1)) is None


def test_old_state_is_pruned_so_memory_does_not_grow_forever():
    d = Detector(Rules(max_failures=100, window_seconds=10, spray_users=999, max_tracked_ips=50))
    for i in range(500):
        d.feed(fail(float(i), ip=f"10.0.{i // 250}.{i % 250 + 1}"))
    assert d.tracked_ips() <= 60
