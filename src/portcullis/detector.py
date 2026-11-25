"""Decide which IP addresses are attacking, using a sliding window per address."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .models import AuthEvent, Verdict


@dataclass(frozen=True)
class Rules:
    max_failures: int = 5  # failures inside the window that trigger a ban
    window_seconds: int = 300
    spray_users: int = 4  # distinct usernames tried inside the window that trigger a ban
    suspicious_after: int = 3  # a success after this many failures is reported
    max_tracked_ips: int = 50_000  # memory cap


class Detector:
    def __init__(self, rules: Rules | None = None) -> None:
        self.rules = rules or Rules()
        self._seen: dict[str, deque[tuple[float, str]]] = {}

    def tracked_ips(self) -> int:
        return len(self._seen)

    def feed(self, ev: AuthEvent) -> Verdict | None:
        rules = self.rules
        window = self._recent(ev.ip, ev.ts)
        if ev.success:
            failures = len(window)
            if failures >= rules.suspicious_after:
                users = tuple(sorted({u for _, u in window}))
                self._seen.pop(ev.ip, None)
                return Verdict(
                    "suspicious_success", ev.ip,
                    f"Login succeeded as '{ev.user}' after {failures} failed attempts",
                    failures, users)
            return None

        window.append((ev.ts, ev.user))
        self._seen[ev.ip] = window
        self._enforce_cap(ev.ts)
        users = tuple(sorted({u for _, u in window}))
        if len(window) >= rules.max_failures:
            reason = f"{len(window)} failed logins in {rules.window_seconds}s"
        elif len(users) >= rules.spray_users:
            reason = f"Password spray: {len(users)} different usernames tried"
        else:
            return None
        failures = len(window)
        del self._seen[ev.ip]
        return Verdict("ban", ev.ip, reason, failures, users)

    def _recent(self, ip: str, now: float) -> deque[tuple[float, str]]:
        window = self._seen.get(ip, deque())
        cutoff = now - self.rules.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        return window

    def _enforce_cap(self, now: float) -> None:
        cap = self.rules.max_tracked_ips
        if len(self._seen) <= cap:
            return
        cutoff = now - self.rules.window_seconds
        for ip in [ip for ip, dq in self._seen.items() if not dq or dq[-1][0] < cutoff]:
            del self._seen[ip]
        if len(self._seen) > cap:  # still too many fresh ones: drop the stalest tenth
            ordered = sorted(self._seen, key=lambda ip: self._seen[ip][-1][0])
            for ip in ordered[: len(self._seen) - cap + max(1, cap // 10)]:
                del self._seen[ip]
