"""Plain data types shared by every part of Portcullis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEvent:
    """One login attempt seen in a log source."""

    ts: float  # seconds since the epoch, UTC
    ip: str
    user: str
    service: str  # "ssh" or "rdp"
    success: bool
    uid: str = ""  # stable id from the source (e.g. a Windows EventRecordID) for de-duplication


@dataclass(frozen=True)
class Verdict:
    """What the detector decided about an IP address."""

    kind: str  # "ban" or "suspicious_success"
    ip: str
    reason: str
    failures: int
    users: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ban:
    """A block placed on an IP address."""

    ip: str
    reason: str
    created: float
    expires: float | None  # None means permanent
    source: str = "auto"  # "auto" or "manual"
    failures: int = 0
    active: bool = True
    id: int | None = None
