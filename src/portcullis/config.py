"""Configuration: a TOML file, validated strictly (a typo in a security config must not be silent)."""

from __future__ import annotations

import difflib
import ipaddress
import os
import tomllib
from dataclasses import dataclass, field, fields

from .detector import Rules


class ConfigError(ValueError):
    """The configuration file is wrong. The message says what and where."""


@dataclass
class Detection:
    max_failures: int = 5
    window_seconds: int = 300
    ban_seconds: int = 3600  # 0 means ban forever
    spray_users: int = 4
    suspicious_after: int = 3
    ignore_private: bool = True


@dataclass
class Sources:
    ssh_log: str = "auto"  # "auto", "journal", "off", or a log file path
    windows: bool = True  # read the Windows Security log (only used on Windows)
    poll_seconds: int = 5


@dataclass
class FirewallConfig:
    backend: str = "auto"  # "auto", "windows" or "iptables"
    dry_run: bool = True  # observe only: report what would be blocked, block nothing


@dataclass
class Notify:
    discord_webhook: str = ""
    slack_webhook: str = ""
    telegram_token: str = ""
    telegram_chat_id: str = ""


@dataclass
class AbuseIPDB:
    api_key: str = ""


@dataclass
class Dashboard:
    host: str = "127.0.0.1"
    port: int = 8787
    token: str = ""


@dataclass
class Storage:
    path: str = "portcullis.db"
    max_events: int = 100_000


@dataclass
class Allowlist:
    addresses: list[str] = field(default_factory=list)


@dataclass
class Config:
    detection: Detection = field(default_factory=Detection)
    sources: Sources = field(default_factory=Sources)
    firewall: FirewallConfig = field(default_factory=FirewallConfig)
    notify: Notify = field(default_factory=Notify)
    abuseipdb: AbuseIPDB = field(default_factory=AbuseIPDB)
    dashboard: Dashboard = field(default_factory=Dashboard)
    storage: Storage = field(default_factory=Storage)
    allowlist: Allowlist = field(default_factory=Allowlist)

    def rules(self) -> Rules:
        d = self.detection
        return Rules(
            max_failures=d.max_failures, window_seconds=d.window_seconds,
            spray_users=d.spray_users, suspicious_after=d.suspicious_after)

    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(a, strict=False) for a in self.allowlist.addresses]

    def is_allowed(self, ip: str) -> bool:
        """True if this address must never be blocked."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.detection.ignore_private and (
                addr.is_private or addr.is_loopback or addr.is_link_local):
            return True
        return any(addr in net for net in self.networks())


_RANGES = {
    ("detection", "max_failures"): (1, 1000),
    ("detection", "window_seconds"): (10, 86_400),
    ("detection", "ban_seconds"): (0, 31_536_000),
    ("detection", "spray_users"): (2, 1000),
    ("detection", "suspicious_after"): (1, 1000),
    ("sources", "poll_seconds"): (1, 3600),
    ("dashboard", "port"): (1, 65_535),
    ("storage", "max_events"): (100, 10_000_000),
}


def _fill(section_name: str, instance: object, data: dict) -> None:
    known = {f.name: f for f in fields(instance)}  # type: ignore[arg-type]
    for key, value in data.items():
        if key not in known:
            hint = difflib.get_close_matches(key, known, n=1)
            more = f" Did you mean '{hint[0]}'?" if hint else ""
            raise ConfigError(f"Unknown setting '{key}' in [{section_name}].{more}")
        current = getattr(instance, key)
        if isinstance(current, bool):
            ok = isinstance(value, bool)
        elif isinstance(current, int):
            ok = isinstance(value, int) and not isinstance(value, bool)
        elif isinstance(current, list):
            ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
        else:
            ok = isinstance(value, str)
        if not ok:
            raise ConfigError(
                f"[{section_name}] {key} has the wrong type: expected "
                f"{type(current).__name__}, got {type(value).__name__}.")
        bounds = _RANGES.get((section_name, key))
        if bounds and not bounds[0] <= value <= bounds[1]:
            raise ConfigError(
                f"[{section_name}] {key} must be between {bounds[0]} and {bounds[1]} (got {value}).")
        setattr(instance, key, value)


def _validate(cfg: Config) -> None:
    for entry in cfg.allowlist.addresses:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"[allowlist] '{entry}' is not an IP address or network (e.g. 203.0.113.0/24)."
            ) from exc
    if cfg.firewall.backend not in ("auto", "windows", "iptables"):
        raise ConfigError("[firewall] backend must be 'auto', 'windows' or 'iptables'.")
    token = cfg.dashboard.token
    if token and len(token) < 12:
        raise ConfigError("[dashboard] token must be at least 12 characters.")
    if cfg.dashboard.host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise ConfigError(
            "[dashboard] a token is required when the dashboard listens on a non-local address "
            "(set [dashboard] token or the PORTCULLIS_TOKEN environment variable).")


def load_config(path: str | None) -> Config:
    cfg = Config()
    if path:
        try:
            with open(path, encoding="utf-8-sig") as fh:  # utf-8-sig: Notepad adds a BOM
                raw = tomllib.loads(fh.read())
        except FileNotFoundError as exc:
            raise ConfigError(f"Config file not found: {path}") from exc
        except UnicodeDecodeError as exc:
            raise ConfigError(f"Config file must be UTF-8 text: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"Config file is not valid TOML: {exc}") from exc
        sections = {f.name for f in fields(cfg)}
        for name, data in raw.items():
            if name not in sections:
                hint = difflib.get_close_matches(name, sections, n=1)
                more = f" Did you mean [{hint[0]}]?" if hint else ""
                raise ConfigError(f"Unknown section [{name}].{more}")
            if not isinstance(data, dict):
                raise ConfigError(f"[{name}] must be a table of settings.")
            _fill(name, getattr(cfg, name), data)
    env_token = os.environ.get("PORTCULLIS_TOKEN")
    if env_token:
        cfg.dashboard.token = env_token
    _validate(cfg)
    return cfg
