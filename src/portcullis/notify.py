"""Chat alerts (Discord, Slack, Telegram) and optional AbuseIPDB reputation lookups.

Alert text includes attacker-controlled strings (usernames), so every message is cleaned first and
never allowed to ping or inject links.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import queue
import re
import threading
import urllib.parse
import urllib.request
from collections.abc import Callable

log = logging.getLogger("portcullis.notify")

Post = Callable[[str, dict], bool]
Get = Callable[[str, dict], dict]

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def safe_text(text: str, limit: int = 120) -> str:
    """One line, no control characters, bounded length."""
    cleaned = re.sub(r"\s+", " ", _CONTROL.sub(" ", str(text))).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def humanize(seconds: int | None) -> str:
    if seconds is None:
        return "permanently"
    for unit, size in (("day", 86_400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = int(seconds // size)
            return f"{n} {unit}{'s' if n != 1 else ''}"
    return f"{int(seconds)} seconds"


def default_post(url: str, payload: dict) -> bool:
    req = urllib.request.Request(  # noqa: S310 (https is enforced when channels are built)
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "portcullis"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return 200 <= resp.status < 300


def default_get(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers={**headers, "User-Agent": "portcullis"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def abuse_lookup(ip: str, key: str, get: Get = default_get) -> dict | None:
    """Reputation for one address, or None if there is no key or the lookup fails."""
    if not key:
        return None
    try:
        ipaddress.ip_address(ip)
        url = ("https://api.abuseipdb.com/api/v2/check?ipAddress="
               f"{urllib.parse.quote(ip)}&maxAgeInDays=90")
        data = get(url, {"Key": key, "Accept": "application/json"})["data"]
        return {"score": int(data["abuseConfidenceScore"]),
                "country": str(data.get("countryCode") or "?"),
                "reports": int(data.get("totalReports", 0))}
    except (OSError, KeyError, ValueError, TypeError) as exc:
        log.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


Channel = tuple[str, str, str]  # (kind, url, extra)


def _payload(kind: str, extra: str, text: str) -> dict:
    if kind == "discord":
        return {"content": text[:1900], "allowed_mentions": {"parse": []}}
    if kind == "slack":
        escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return {"text": escaped}
    return {"chat_id": extra, "text": text}


class Notifiers:
    def __init__(self, channels: list[Channel], post: Post | None = None, sync: bool = False,
                 abuse_key: str = "", get: Get | None = None) -> None:
        self.channels = channels
        self.post = post or default_post
        self.get = get or default_get
        self.abuse_key = abuse_key
        self.sync = sync
        self._queue: queue.Queue[tuple[str, str | None]] = queue.Queue(maxsize=200)
        self._worker: threading.Thread | None = None

    def send(self, text: str, ip: str | None = None) -> int:
        """Deliver now. Returns how many channels accepted the message. Never raises."""
        if not self.channels:
            return 0
        if ip:
            info = abuse_lookup(ip, self.abuse_key, self.get)
            if info:
                text += (f"\nAbuseIPDB: score {info['score']}/100, country {info['country']}, "
                         f"{info['reports']} reports")
        delivered = 0
        for kind, url, extra in self.channels:
            try:
                if self.post(url, _payload(kind, extra, text)):
                    delivered += 1
            except Exception as exc:  # noqa: BLE001 (one broken channel must not stop the rest)
                log.warning("%s alert failed: %s", kind, exc)
        return delivered

    def __call__(self, text: str, ip: str | None = None) -> None:
        if self.sync:
            self.send(text, ip)
            return
        if self._worker is None:
            self._worker = threading.Thread(target=self._run, daemon=True, name="portcullis-alerts")
            self._worker.start()
        try:
            self._queue.put_nowait((text, ip))
        except queue.Full:
            log.warning("alert queue full; dropping a message")

    def _run(self) -> None:
        while True:
            text, ip = self._queue.get()
            self.send(text, ip)


def make_notifiers(cfg, post: Post | None = None, sync: bool = False,
                   get: Get | None = None) -> Notifiers:
    n = cfg.notify
    channels: list[Channel] = []
    for kind, url in (("discord", n.discord_webhook), ("slack", n.slack_webhook)):
        if not url:
            continue
        if not url.startswith("https://"):
            log.warning("ignoring %s webhook: it must start with https://", kind)
            continue
        channels.append((kind, url, ""))
    if n.telegram_token and n.telegram_chat_id:
        channels.append(
            ("telegram", f"https://api.telegram.org/bot{n.telegram_token}/sendMessage",
             n.telegram_chat_id))
    return Notifiers(channels, post=post, sync=sync, abuse_key=cfg.abuseipdb.api_key, get=get)
