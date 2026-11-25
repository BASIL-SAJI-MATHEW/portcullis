"""Firewall backends. Commands are built as argument lists (never a shell string) from a validated IP."""

from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
from collections.abc import Callable

log = logging.getLogger("portcullis.firewall")

Runner = Callable[[list[str]], int]


def validate_ip(text: str) -> str:
    """Return the normalised address, or raise ValueError. Only a single plain IP is accepted."""
    if not isinstance(text, str) or text != text.strip() or not text:
        raise ValueError(f"not a plain IP address: {text!r}")
    addr = ipaddress.ip_address(text)  # raises ValueError for anything else
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast:
        raise ValueError(f"refusing to block {addr}")
    return str(addr)


def build_commands(backend: str, ip: str) -> dict[str, list[str]]:
    """The check / add / delete commands for one backend. Raises ValueError for a bad IP."""
    ip = validate_ip(ip)
    if backend == "windows":
        name = f"name=Portcullis {ip}"
        return {
            "check": ["netsh", "advfirewall", "firewall", "show", "rule", name],
            "add": ["netsh", "advfirewall", "firewall", "add", "rule", name, "dir=in",
                    "action=block", f"remoteip={ip}", "enable=yes"],
            "delete": ["netsh", "advfirewall", "firewall", "delete", "rule", name],
        }
    if backend == "iptables":
        tool = "ip6tables" if ":" in ip else "iptables"
        tail = ["INPUT", "-s", ip, "-m", "comment", "--comment", "portcullis", "-j", "DROP"]
        return {
            "check": [tool, "-C", *tail],
            "add": [tool, "-I", *tail],
            "delete": [tool, "-D", *tail],
        }
    raise ValueError(f"unknown firewall backend: {backend}")


def _run(cmd: list[str]) -> int:
    return subprocess.run(cmd, capture_output=True, timeout=15, check=False).returncode


class CommandFirewall:
    """Blocks addresses with the operating system's own firewall tool."""

    def __init__(self, backend: str, runner: Runner = _run) -> None:
        self.backend = backend
        self.runner = runner

    def block(self, ip: str) -> bool:
        try:
            cmds = build_commands(self.backend, ip)
            if self.runner(cmds["check"]) == 0:
                return True  # already blocked
            return self.runner(cmds["add"]) == 0
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            log.error("could not block %s: %s", ip, exc)
            return False

    def unblock(self, ip: str) -> bool:
        try:
            cmds = build_commands(self.backend, ip)
            if self.runner(cmds["check"]) != 0:
                return True  # nothing to remove
            return self.runner(cmds["delete"]) == 0
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            log.error("could not unblock %s: %s", ip, exc)
            return False


class DryRunFirewall:
    """Observe-only mode: remembers what it would do and changes nothing."""

    def __init__(self) -> None:
        self.log: list[tuple[str, str]] = []

    def block(self, ip: str) -> bool:
        self.log.append(("block", ip))
        return True

    def unblock(self, ip: str) -> bool:
        self.log.append(("unblock", ip))
        return True


def make_firewall(cfg) -> CommandFirewall | DryRunFirewall:
    if cfg.firewall.dry_run:
        return DryRunFirewall()
    backend = cfg.firewall.backend
    if backend == "auto":
        backend = "windows" if os.name == "nt" else "iptables"
    return CommandFirewall(backend)
