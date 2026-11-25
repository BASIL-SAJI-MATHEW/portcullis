"""The ``portcullis`` command."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from datetime import UTC, datetime

from . import __version__
from .config import Config, ConfigError, load_config
from .engine import Engine
from .firewall import DryRunFirewall, make_firewall
from .notify import make_notifiers
from .parsers import parse_ssh_line
from .server import make_server
from .simulate import Simulator
from .sources import JournalSource, LogTail, WindowsEventSource, resolve_ssh_source
from .store import Store

log = logging.getLogger("portcullis")

DEFAULT_CONFIG = "portcullis.toml"

TEMPLATE = """# Portcullis configuration. Every setting is optional; these are the defaults.

[detection]
max_failures = 5          # failed logins from one address inside the window that cause a block
window_seconds = 300      # the window, in seconds
ban_seconds = 3600        # how long a block lasts (0 = forever)
spray_users = 4           # also block an address that tries this many different usernames
ignore_private = true     # never block private (LAN) and loopback addresses

[firewall]
dry_run = true            # START HERE: observe only. Set to false to really block.
backend = "auto"          # "auto", "windows" (netsh) or "iptables"

[sources]
ssh_log = "auto"          # "auto", "journal", "off" or a log file path (Linux)
windows = true            # read the Windows Security log for RDP (Windows, needs Administrator)

[allowlist]
addresses = []            # addresses or networks that must never be blocked, e.g. "203.0.113.0/24"

[notify]
discord_webhook = ""
slack_webhook = ""
telegram_token = ""
telegram_chat_id = ""

[abuseipdb]
api_key = ""              # optional: adds a reputation line to alerts

[dashboard]
host = "127.0.0.1"        # use "0.0.0.0" only together with a token
port = 8787
token = ""                # required when the host is not 127.0.0.1 (at least 12 characters)

[storage]
path = "portcullis.db"
"""


def _config(path: str | None) -> Config:
    if path is None and os.path.exists(DEFAULT_CONFIG):
        path = DEFAULT_CONFIG
    return load_config(path)


def _offline_engine(cfg: Config) -> tuple[Engine, Store]:
    store = Store(cfg.storage.path, cfg.storage.max_events)
    return Engine(cfg, store, make_firewall(cfg)), store


def _fmt_time(ts: float | None) -> str:
    return "never" if ts is None else datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


# ------------------------------------------------------------------ commands


def cmd_init(args: argparse.Namespace) -> int:
    if os.path.exists(args.path) and not args.force:
        print(f"error: {args.path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    with open(args.path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(TEMPLATE)
    print(f"Wrote {args.path}. It starts in observe mode: nothing is blocked yet.")
    print("Next: portcullis run   (then open http://127.0.0.1:8787)")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    mode = "observe only" if cfg.firewall.dry_run else "blocking on"
    kind, target = resolve_ssh_source(cfg.sources.ssh_log)
    print(f"Config OK. Mode: {mode}. SSH source: {kind} {target}".rstrip())
    print(f"Windows Security log: {'on' if cfg.sources.windows and os.name == 'nt' else 'off'}")
    print(f"Dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    return 0


def cmd_bans(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    _, store = _offline_engine(cfg)
    bans = store.active_bans(time.time())
    if not bans:
        print("No active blocks.")
    for ban in bans:
        print(f"{ban.ip:<40} {ban.source:<7} until {_fmt_time(ban.expires):<22} {ban.reason}")
    return 0


def cmd_ban(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    engine, _ = _offline_engine(cfg)
    seconds = None if args.hours is None else int(args.hours * 3600)
    try:
        ban = engine.ban(args.ip, args.reason, seconds=seconds)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    note = " (observe mode: not actually blocked)" if cfg.firewall.dry_run else ""
    print(f"Blocked {ban.ip} until {_fmt_time(ban.expires)}{note}")
    return 0


def cmd_unban(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    engine, _ = _offline_engine(cfg)
    try:
        changed = engine.unban(args.ip)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Unblocked {args.ip}" if changed else f"{args.ip} was not blocked")
    return 0


def _banner(cfg: Config) -> None:
    mode = ("OBSERVE MODE: nothing will be blocked. Set dry_run = false (or use --enforce) to block."
            if cfg.firewall.dry_run else "BLOCKING ON: attackers will be blocked in the firewall.")
    print(f"Portcullis {__version__}\n{mode}\n"
          f"Dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}\nPress Ctrl+C to stop.")


def _start_sources(cfg: Config, engine: Engine) -> list:
    started = []

    def on_line(line: str) -> None:
        ev = parse_ssh_line(line)
        if ev is not None:
            engine.handle_event(ev)

    kind, target = resolve_ssh_source(cfg.sources.ssh_log)
    if kind == "file":
        src = LogTail(target, on_line)
        src.start()
        started.append(src)
        log.info("watching SSH logins in %s", target)
    elif kind == "journal":
        src = JournalSource(on_line)
        src.start()
        started.append(src)
        log.info("watching SSH logins through journald")
    if os.name == "nt" and cfg.sources.windows:
        win = WindowsEventSource(engine.handle_event, poll_seconds=cfg.sources.poll_seconds)
        win.start()
        started.append(win)
        log.info("watching RDP logins in the Windows Security log")
    if not started:
        log.warning("no login source is active; check [sources] in your config")
    return started


def _sweeper(engine: Engine, stop: threading.Event) -> None:
    while not stop.wait(5):
        try:
            engine.sweep()
        except Exception:  # noqa: BLE001
            log.exception("expiry sweep failed")


def _serve(cfg: Config, engine: Engine, stop: threading.Event) -> None:
    server = make_server(engine, cfg.dashboard.host, cfg.dashboard.port, cfg.dashboard.token)
    threading.Thread(target=_sweeper, args=(engine, stop), daemon=True).start()

    def shutdown(*_: object) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _config(args.config)
    if args.enforce:
        cfg.firewall.dry_run = False
    if args.observe:
        cfg.firewall.dry_run = True
    store = Store(cfg.storage.path, cfg.storage.max_events)
    engine = Engine(cfg, store, make_firewall(cfg), notify=make_notifiers(cfg))
    session_ip = (os.environ.get("SSH_CONNECTION") or "").split(" ")[0]
    if session_ip:
        try:
            engine.allow(session_ip, "your SSH session when Portcullis started")
            log.info("protected your current SSH address %s", session_ip)
        except ValueError:
            pass
    restored = engine.restore()
    if restored:
        log.info("re-applied %d active block(s)", restored)
    stop = threading.Event()
    _banner(cfg)
    sources = _start_sources(cfg, engine)
    try:
        _serve(cfg, engine, stop)
    finally:
        for src in sources:
            src.stop()
    print("Stopped.")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    cfg = load_config(args.config) if args.config else Config()
    cfg.detection.ignore_private = False  # the fake attackers use documentation ranges
    cfg.firewall.dry_run = True
    cfg.storage.path = ":memory:"
    engine = Engine(cfg, Store(":memory:"), DryRunFirewall(), notify=make_notifiers(cfg))
    sim = Simulator(engine)
    sim.seed_history()
    stop = threading.Event()
    threading.Thread(target=sim.run, args=(stop, args.rate), daemon=True).start()
    print("DEMO: fake attackers from documentation address ranges. Nothing real is blocked.")
    _banner(cfg)
    _serve(cfg, engine, stop)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portcullis", description="Stop brute-force logins on Windows RDP and Linux SSH.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_text: str, config: bool = True) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=func)
        if config:
            p.add_argument("-c", "--config", help=f"config file (default: ./{DEFAULT_CONFIG})")
        return p

    p = add("init", cmd_init, "write a starter config file", config=False)
    p.add_argument("--path", default=DEFAULT_CONFIG)
    p.add_argument("--force", action="store_true")
    add("check", cmd_check, "validate the config")
    p = add("run", cmd_run, "start watching and serve the dashboard")
    p.add_argument("--enforce", action="store_true", help="really block attackers")
    p.add_argument("--observe", action="store_true", help="observe only (the default)")
    add("bans", cmd_bans, "list active blocks")
    p = add("ban", cmd_ban, "block an address now")
    p.add_argument("ip")
    p.add_argument("--hours", type=float, default=None, help="0 means forever")
    p.add_argument("--reason", default="Manual ban")
    p = add("unban", cmd_unban, "remove a block")
    p.add_argument("ip")
    p = add("simulate", cmd_simulate, "demo mode with fake attackers (nothing real is touched)")
    p.add_argument("--rate", type=float, default=3.0, help="fake events per second")
    p = sub.add_parser("version", help="print the version")
    p.set_defaults(func=lambda a: print(__version__) or 0)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        datefmt="%H:%M:%S")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
