"""Where login events come from: a log file, journald, or the Windows Security event log."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from collections import deque
from collections.abc import Callable

from .models import AuthEvent
from .parsers import MAX_LINE, parse_windows_events

log = logging.getLogger("portcullis.sources")

MAX_BUFFER = 64 * 1024


class LogTail:
    """Follows a text log like ``tail -F``: copes with rotation, truncation and partial lines."""

    def __init__(self, path: str, on_line: Callable[[str], object], poll: float = 0.5,
                 from_end: bool = True) -> None:
        self.path = path
        self.on_line = on_line
        self.poll = poll
        self.from_end = from_end
        self._fh = None
        self._pos = 0
        self._buf = b""
        self._discard = False
        self._first = True
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _open(self, at_end: bool) -> bool:
        try:
            fh = open(self.path, "rb")  # noqa: SIM115 (kept open between polls)
        except OSError:
            return False
        self._fh = fh
        self._buf, self._discard = b"", False
        self._pos = fh.seek(0, os.SEEK_END) if at_end else 0
        if not at_end:
            fh.seek(0)
        return True

    def _rotated(self) -> bool:
        try:
            on_disk = os.stat(self.path)
            mine = os.fstat(self._fh.fileno())  # type: ignore[union-attr]
        except OSError:
            return True
        return bool(on_disk.st_ino and mine.st_ino and on_disk.st_ino != mine.st_ino)

    def poll_once(self) -> int:
        """Read whatever is new. Returns the number of lines handed to the callback."""
        if self._fh is None:
            start_at_end = self._first and self.from_end
            self._first = False
            if not self._open(start_at_end):
                return 0
        elif self._rotated():
            self._fh.close()
            self._fh = None
            if not self._open(False):
                return 0
        assert self._fh is not None
        size = os.fstat(self._fh.fileno()).st_size
        if size < self._pos:  # truncated in place
            self._fh.seek(0)
            self._pos, self._buf, self._discard = 0, b"", False
        emitted = 0
        while True:
            chunk = self._fh.read(65_536)
            if not chunk:
                break
            self._pos += len(chunk)
            emitted += self._consume(chunk)
        return emitted

    def _consume(self, chunk: bytes) -> int:
        self._buf += chunk
        parts = self._buf.split(b"\n")
        self._buf = parts.pop()  # the unfinished tail
        emitted = 0
        for raw in parts:
            if self._discard:  # still inside a line we gave up on
                self._discard = False
                continue
            if len(raw) > MAX_LINE:
                continue
            try:
                self.on_line(raw.decode("utf-8", errors="replace").rstrip("\r"))
            except Exception:  # noqa: BLE001 (a bad line must never stop the watcher)
                log.exception("error while handling a log line")
            emitted += 1
        if len(self._buf) > MAX_BUFFER:
            self._buf, self._discard = b"", True
        return emitted

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.is_set():
                try:
                    self.poll_once()
                except Exception:  # noqa: BLE001
                    log.exception("log tail error")
                self._stop.wait(self.poll)

        self._thread = threading.Thread(target=loop, daemon=True, name="portcullis-tail")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def run_text(cmd: list[str]) -> tuple[int, str, str]:
    done = subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=45, check=False)
    return done.returncode, done.stdout, done.stderr


class WindowsEventSource:
    """Polls the Windows Security log with ``wevtutil`` (needs an administrator account)."""

    def __init__(self, on_event: Callable[[AuthEvent], object], runner=None,
                 poll_seconds: int = 5) -> None:
        self.on_event = on_event
        self.runner = runner or run_text
        self.poll_seconds = poll_seconds
        self._seen: set[str] = set()
        self._order: deque[str] = deque()
        self._warned = False
        self._stop = threading.Event()

    def _query(self) -> list[str]:
        window_ms = max(self.poll_seconds * 3, 30) * 1000
        xpath = ("*[System[(EventID=4624 or EventID=4625) and "
                 f"TimeCreated[timediff(@SystemTime) <= {window_ms}]]]")
        return ["wevtutil", "qe", "Security", f"/q:{xpath}", "/f:xml"]

    def _remember(self, key: str) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        self._order.append(key)
        if len(self._order) > 10_000:
            self._seen.discard(self._order.popleft())
        return True

    def poll_once(self) -> int:
        try:
            code, out, err = self.runner(self._query())
        except (OSError, subprocess.SubprocessError) as exc:
            code, out, err = 1, "", str(exc)
        if code != 0:
            if not self._warned:
                self._warned = True
                log.error("cannot read the Windows Security log (%s). Run Portcullis from an "
                          "Administrator account.", (err or "no details").strip()[:200])
            return 0
        fresh = 0
        for ev in parse_windows_events(out):
            key = ev.uid or f"{ev.ts}|{ev.ip}|{ev.user}|{ev.success}"
            if self._remember(key):
                fresh += 1
                try:
                    self.on_event(ev)
                except Exception:  # noqa: BLE001
                    log.exception("error while handling a Windows event")
        return fresh

    def start(self) -> None:
        def loop() -> None:
            while not self._stop.is_set():
                self.poll_once()
                self._stop.wait(self.poll_seconds)

        threading.Thread(target=loop, daemon=True, name="portcullis-wevt").start()

    def stop(self) -> None:
        self._stop.set()


class JournalSource:
    """Follows sshd messages through systemd-journald (for distributions without auth.log)."""

    COMMAND = ["journalctl", "-f", "-n", "0", "-o", "short-iso", "-t", "sshd"]

    def __init__(self, on_line: Callable[[str], object]) -> None:
        self.on_line = on_line
        self._proc: subprocess.Popen | None = None

    def start(self) -> None:
        self._proc = subprocess.Popen(  # noqa: S603
            self.COMMAND, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            encoding="utf-8", errors="replace")

        def loop() -> None:
            assert self._proc and self._proc.stdout
            for line in self._proc.stdout:
                try:
                    self.on_line(line.rstrip("\n"))
                except Exception:  # noqa: BLE001
                    log.exception("error while handling a journal line")

        threading.Thread(target=loop, daemon=True, name="portcullis-journal").start()

    def stop(self) -> None:
        if self._proc:
            self._proc.terminate()


def resolve_ssh_source(value: str, exists: Callable[[str], bool] = os.path.exists,
                       which: Callable[[str], str | None] = shutil.which,
                       is_windows: bool | None = None) -> tuple[str, str]:
    """Decide how to read SSH logins: ("file", path), ("journal", "") or ("off", "")."""
    if is_windows is None:
        is_windows = os.name == "nt"
    if value in ("off", "journal"):
        return value, ""
    if value not in ("auto", ""):
        return "file", value
    if is_windows:
        return "off", ""
    for path in ("/var/log/auth.log", "/var/log/secure"):
        if exists(path):
            return "file", path
    if which("journalctl"):
        return "journal", ""
    return "off", ""
