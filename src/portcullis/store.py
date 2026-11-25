"""SQLite storage for events, bans and the allow list. Thread-safe, bounded, standard library only."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace

from .models import AuthEvent, Ban

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, ip TEXT NOT NULL,
  user TEXT NOT NULL, service TEXT NOT NULL, success INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS bans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, reason TEXT NOT NULL,
  created REAL NOT NULL, expires REAL, source TEXT NOT NULL, failures INTEGER NOT NULL,
  active INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS bans_ip ON bans(ip, active);
CREATE TABLE IF NOT EXISTS allow (
  ip TEXT PRIMARY KEY, note TEXT NOT NULL, created REAL NOT NULL);
"""

DAY = 86_400


def _ban(row: sqlite3.Row) -> Ban:
    return Ban(ip=row["ip"], reason=row["reason"], created=row["created"], expires=row["expires"],
               source=row["source"], failures=row["failures"], active=bool(row["active"]),
               id=row["id"])


class Store:
    def __init__(self, path: str = ":memory:", max_events: int = 100_000) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._max_events = max_events
        self._inserts = 0
        with self._lock:
            if path != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- events

    def add_event(self, ev: AuthEvent) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO events(ts, ip, user, service, success) VALUES (?,?,?,?,?)",
                (ev.ts, ev.ip, ev.user, ev.service, int(ev.success)))
            self._inserts += 1
            if self._inserts % 500 == 0:
                self._db.execute(
                    "DELETE FROM events WHERE id <= "
                    "(SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)", (self._max_events,))
            self._db.commit()

    def event_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def recent_events(self, limit: int = 100) -> list[AuthEvent]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
        return [AuthEvent(r["ts"], r["ip"], r["user"], r["service"], bool(r["success"]))
                for r in rows]

    # ---- bans

    def add_ban(self, ban: Ban) -> Ban:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO bans(ip, reason, created, expires, source, failures, active) "
                "VALUES (?,?,?,?,?,?,1)",
                (ban.ip, ban.reason, ban.created, ban.expires, ban.source, ban.failures))
            self._db.commit()
            return replace(ban, id=cur.lastrowid, active=True)

    def active_bans(self, now: float) -> list[Ban]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM bans WHERE active=1 AND (expires IS NULL OR expires > ?) "
                "ORDER BY created DESC", (now,)).fetchall()
        return [_ban(r) for r in rows]

    def is_banned(self, ip: str, now: float) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM bans WHERE ip=? AND active=1 AND (expires IS NULL OR expires > ?) "
                "LIMIT 1", (ip, now)).fetchone()
        return row is not None

    def expire_due(self, now: float) -> list[Ban]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM bans WHERE active=1 AND expires IS NOT NULL AND expires <= ?",
                (now,)).fetchall()
            self._db.execute(
                "UPDATE bans SET active=0 WHERE active=1 AND expires IS NOT NULL AND expires <= ?",
                (now,))
            self._db.commit()
        return [_ban(r) for r in rows]

    def deactivate(self, ip: str, now: float) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE bans SET active=0 WHERE ip=? AND active=1", (ip,))
            self._db.commit()
            return cur.rowcount > 0

    # ---- allow list

    def add_allow(self, ip: str, note: str, now: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO allow(ip, note, created) VALUES (?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET note=excluded.note", (ip, note, now))
            self._db.commit()

    def remove_allow(self, ip: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM allow WHERE ip=?", (ip,))
            self._db.commit()
            return cur.rowcount > 0

    def allowed(self) -> dict[str, str]:
        with self._lock:
            rows = self._db.execute("SELECT ip, note FROM allow ORDER BY ip").fetchall()
        return {r["ip"]: r["note"] for r in rows}

    # ---- numbers for the dashboard

    def stats(self, now: float) -> dict:
        since = now - DAY
        with self._lock:
            one = self._db.execute

            def count(sql: str, *args: float) -> int:
                return one(sql, args).fetchone()[0]

            fails = count("SELECT COUNT(*) FROM events WHERE success=0 AND ts>=?", since)
            wins = count("SELECT COUNT(*) FROM events WHERE success=1 AND ts>=?", since)
            attackers = count(
                "SELECT COUNT(DISTINCT ip) FROM events WHERE success=0 AND ts>=?", since)
            active = count(
                "SELECT COUNT(*) FROM bans WHERE active=1 AND (expires IS NULL OR expires > ?)",
                now)
            total = count("SELECT COUNT(*) FROM bans")
            top_ips = one(
                "SELECT ip AS name, COUNT(*) AS count FROM events WHERE success=0 AND ts>=? "
                "GROUP BY ip ORDER BY count DESC, name LIMIT 10", (since,)).fetchall()
            top_users = one(
                "SELECT user AS name, COUNT(*) AS count FROM events WHERE success=0 AND ts>=? "
                "GROUP BY user ORDER BY count DESC, name LIMIT 10", (since,)).fetchall()
            stamps = [r[0] for r in one(
                "SELECT ts FROM events WHERE success=0 AND ts>=? AND ts<=?", (since, now))]
        buckets = [0] * 24
        for ts in stamps:
            buckets[23 - int((now - ts) // 3600)] += 1
        return {
            "failures_24h": fails, "successes_24h": wins, "unique_attackers_24h": attackers,
            "active_bans": active, "total_bans": total,
            "top_ips": [dict(r) for r in top_ips], "top_users": [dict(r) for r in top_users],
            "hourly": [{"hour_start": now - (24 - i) * 3600, "failures": n}
                       for i, n in enumerate(buckets)],
        }
