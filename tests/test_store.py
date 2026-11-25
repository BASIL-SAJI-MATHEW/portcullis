from portcullis.models import AuthEvent, Ban
from portcullis.store import Store

NOW = 1_800_000_000.0


def ev(ts, ip="203.0.113.5", user="root", success=False):
    return AuthEvent(ts=ts, ip=ip, user=user, service="ssh", success=success)


def test_recent_events_are_newest_first_and_limited():
    s = Store()
    for i in range(5):
        s.add_event(ev(NOW + i))
    got = s.recent_events(limit=3)
    assert [e.ts for e in got] == [NOW + 4, NOW + 3, NOW + 2]


def test_ban_lifecycle_active_expire_and_unban():
    s = Store()
    timed = s.add_ban(Ban("203.0.113.5", "too many", NOW, NOW + 100))
    perm = s.add_ban(Ban("203.0.113.6", "manual", NOW, None, source="manual"))
    assert timed.id is not None and perm.id is not None
    assert {b.ip for b in s.active_bans(NOW + 1)} == {"203.0.113.5", "203.0.113.6"}
    assert s.is_banned("203.0.113.5", NOW + 1)

    expired = s.expire_due(NOW + 101)
    assert [b.ip for b in expired] == ["203.0.113.5"]
    assert not s.is_banned("203.0.113.5", NOW + 101)
    assert s.is_banned("203.0.113.6", NOW + 10_000_000)  # permanent bans never expire

    assert s.deactivate("203.0.113.6", NOW + 200) is True
    assert s.deactivate("203.0.113.6", NOW + 200) is False  # already off


def test_stats_count_only_the_last_24_hours_and_rank_attackers():
    s = Store()
    s.add_event(ev(NOW - 100, ip="203.0.113.5", user="root"))
    s.add_event(ev(NOW - 200, ip="203.0.113.5", user="admin"))
    s.add_event(ev(NOW - 300, ip="203.0.113.6", user="root"))
    s.add_event(ev(NOW - 3700, ip="203.0.113.5", user="root"))
    s.add_event(ev(NOW - 90_000, ip="203.0.113.9"))  # older than a day: excluded
    s.add_event(ev(NOW - 50, ip="192.0.2.1", user="alice", success=True))
    s.add_ban(Ban("203.0.113.5", "x", NOW, NOW + 60))
    st = s.stats(NOW)
    assert st["failures_24h"] == 4
    assert st["successes_24h"] == 1
    assert st["unique_attackers_24h"] == 2
    assert st["active_bans"] == 1 and st["total_bans"] == 1
    assert st["top_ips"][0] == {"name": "203.0.113.5", "count": 3}
    assert st["top_users"][0] == {"name": "root", "count": 3}
    assert len(st["hourly"]) == 24
    assert st["hourly"][-1]["failures"] == 3  # the newest hour
    assert st["hourly"][-2]["failures"] == 1


def test_allow_list_add_list_remove():
    s = Store()
    s.add_allow("198.51.100.1", "office", NOW)
    assert s.allowed() == {"198.51.100.1": "office"}
    assert s.remove_allow("198.51.100.1") is True
    assert s.allowed() == {}


def test_old_events_are_trimmed_to_the_retention_limit():
    s = Store(max_events=100)
    for i in range(1500):
        s.add_event(ev(NOW + i))
    assert s.event_count() <= 1100  # trimmed in batches, never unbounded
    assert s.recent_events(1)[0].ts == NOW + 1499


def test_data_survives_closing_and_reopening(tmp_path):
    path = tmp_path / "p.db"
    s = Store(str(path))
    s.add_ban(Ban("203.0.113.5", "x", NOW, None))
    s.close()
    again = Store(str(path))
    assert [b.ip for b in again.active_bans(NOW)] == ["203.0.113.5"]
