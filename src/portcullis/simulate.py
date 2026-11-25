"""A fake attack generator for demos and screenshots (``portcullis simulate``).

It only ever feeds invented addresses from the documentation ranges into an in-memory engine that
uses the observe-only firewall, so it can never touch a real firewall.
"""

from __future__ import annotations

import random
import threading

from .engine import Engine
from .models import AuthEvent, Verdict

USERS = ["root", "admin", "administrator", "test", "ubuntu", "oracle", "postgres", "user", "guest",
         "pi", "ftpuser", "support", "git", "deploy", "backup"]


class Simulator:
    def __init__(self, engine: Engine, rng: random.Random | None = None) -> None:
        self.engine = engine
        self.rng = rng or random.Random()
        self.pool: list[tuple[str, str]] = []  # (ip, service)
        while len(self.pool) < 14:
            self.pool.append(self._new_attacker())

    def _new_attacker(self) -> tuple[str, str]:
        net = self.rng.choice(["203.0.113", "198.51.100"])
        return f"{net}.{self.rng.randint(2, 250)}", self.rng.choice(["ssh", "rdp"])

    def seed_history(self) -> None:
        """Back-fill a day of past failed logins so the demo chart looks like a real server's."""
        now = self.engine.clock()
        for hours_ago in range(24):
            for _ in range(self.rng.randint(4, 70)):
                ip, service = self._new_attacker()
                ts = now - hours_ago * 3600 - self.rng.random() * 3500 - 1
                user = self.rng.choice(USERS)
                self.engine.store.add_event(AuthEvent(ts, ip, user, service, False))

    def step(self) -> list[Verdict]:
        """One tick of the simulation. Returns anything the detector decided."""
        now = self.engine.clock()
        verdicts: list[Verdict] = []
        roll = self.rng.random()
        if roll < 0.06:
            verdict = self.engine.handle_event(
                AuthEvent(now, "192.0.2.10", "alice", "ssh", True))
            if verdict:
                verdicts.append(verdict)
        elif roll < 0.88:
            ip, service = self.rng.choice(self.pool)
            for _ in range(self.rng.randint(1, 3)):
                user = self.rng.choice(USERS if self.rng.random() < 0.7 else USERS[:3])
                verdict = self.engine.handle_event(AuthEvent(now, ip, user, service, False))
                if verdict:
                    verdicts.append(verdict)
                    if verdict.kind == "ban":
                        self.pool.remove((ip, service))
                        self.pool.append(self._new_attacker())
                        break
        return verdicts

    def run(self, stop: threading.Event, per_second: float = 3.0) -> None:
        while not stop.is_set():
            self.step()
            stop.wait(1.0 / per_second)
