"""The engine: events in, decisions out. Ties detection, blocking, storage and alerts together."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import replace

from .config import Config
from .detector import Detector
from .firewall import validate_ip
from .models import AuthEvent, Ban, Verdict
from .notify import humanize, safe_text
from .store import Store

log = logging.getLogger("portcullis.engine")

Notify = Callable[..., object]


class Engine:
    def __init__(self, cfg: Config, store: Store, firewall, notify: Notify | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.store = store
        self.firewall = firewall
        self.notify: Notify = notify or (lambda text, ip=None: None)
        self.clock = clock
        self.detector = Detector(cfg.rules())
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ helpers

    def _protected(self, ip: str) -> bool:
        return self.cfg.is_allowed(ip) or ip in self.store.allowed()

    def _expiry(self, seconds: int | None) -> float | None:
        seconds = self.cfg.detection.ban_seconds if seconds is None else seconds
        return None if seconds == 0 else self.clock() + seconds

    @property
    def _observing(self) -> bool:
        return self.cfg.firewall.dry_run

    # ------------------------------------------------------------------ events

    def handle_event(self, ev: AuthEvent) -> Verdict | None:
        with self._lock:
            self.store.add_event(ev)
            if self._protected(ev.ip):
                return None
            verdict = self.detector.feed(ev)
            if verdict is None:
                return None
            if verdict.kind == "ban":
                if self.store.is_banned(ev.ip, self.clock()):
                    return None
                self._auto_ban(verdict)
            else:
                self.notify(f"ALERT: {safe_text(verdict.reason)} from {ev.ip}. "
                            "This address may have guessed a password.", ip=ev.ip)
            return verdict

    def _auto_ban(self, verdict: Verdict) -> None:
        ip = verdict.ip
        if not self.firewall.block(ip):
            self.notify(f"Portcullis could not block {ip} ({safe_text(verdict.reason)}). "
                        "Check that it is running with firewall permissions.", ip=ip)
            return
        seconds = self.cfg.detection.ban_seconds
        self.store.add_ban(Ban(ip, verdict.reason, self.clock(), self._expiry(seconds), "auto",
                               verdict.failures))
        users = ", ".join(safe_text(u, 24) for u in verdict.users[:5])
        verb = "[Observe mode] Would block" if self._observing else "Blocked"
        tail = "" if self._observing else f" Block lasts {humanize(seconds or None)}."
        self.notify(f"{verb} {ip}: {safe_text(verdict.reason)}. Users tried: {users or 'n/a'}.{tail}",
                    ip=ip)

    # ------------------------------------------------------------------ manual control

    def ban(self, ip: str, reason: str = "Manual ban", seconds: int | None = None,
            source: str = "manual") -> Ban:
        ip = validate_ip(ip)
        with self._lock:
            if self._protected(ip):
                raise ValueError(f"{ip} is protected (private or on the allow list)")
            for existing in self.store.active_bans(self.clock()):
                if existing.ip == ip:
                    return existing
            if not self.firewall.block(ip):
                raise RuntimeError(f"the firewall refused to block {ip}")
            ban = self.store.add_ban(Ban(ip, safe_text(reason, 200), self.clock(),
                                         self._expiry(seconds), source, 0))
            self.notify(f"{'[Observe mode] Would block' if self._observing else 'Blocked'} {ip}: "
                        f"{safe_text(reason)}", ip=ip)
            return replace(ban)

    def unban(self, ip: str) -> bool:
        ip = validate_ip(ip)
        with self._lock:
            changed = self.store.deactivate(ip, self.clock())
            self.firewall.unblock(ip)
            return changed

    def allow(self, ip: str, note: str = "") -> None:
        ip = validate_ip(ip)
        with self._lock:
            self.store.add_allow(ip, safe_text(note, 100), self.clock())
            self.unban(ip)

    # ------------------------------------------------------------------ housekeeping

    def sweep(self) -> list[Ban]:
        """Lift bans that have run out. Call this every few seconds."""
        with self._lock:
            expired = self.store.expire_due(self.clock())
            for ban in expired:
                self.firewall.unblock(ban.ip)
                self.notify(f"Block expired for {ban.ip}; it can try again.", ip=None)
            return expired

    def restore(self) -> int:
        """Re-apply active bans after a restart (firewall rules may not have survived)."""
        with self._lock:
            bans = self.store.active_bans(self.clock())
            for ban in bans:
                self.firewall.block(ban.ip)
            return len(bans)
