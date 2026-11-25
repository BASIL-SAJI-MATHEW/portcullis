"""Starts the real `portcullis run` process and drives it through a log file."""

import json
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime

ATTACKER = "8.8.4.4"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as resp:
        return json.loads(resp.read())


def wait_for(fn, seconds=15):
    end = time.time() + seconds
    last = None
    while time.time() < end:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting ({last})")


def ssh_line(ip, user="root"):
    stamp = datetime.now(UTC).isoformat()
    return f"{stamp} web1 sshd[1]: Failed password for {user} from {ip} port 5000 ssh2\n"


def test_failed_logins_in_a_log_file_become_a_recorded_block(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    port = free_port()
    cfg = tmp_path / "portcullis.toml"
    cfg.write_text(
        f'[sources]\nssh_log = "{log.as_posix()}"\nwindows = false\n'
        f'[storage]\npath = "{(tmp_path / "p.db").as_posix()}"\n'
        f"[dashboard]\nport = {port}\n"
        "[detection]\nmax_failures = 5\n"
        "[firewall]\ndry_run = true\n",
        encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "portcullis", "run", "-c", str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        wait_for(lambda: get(port, "/api/health")["ok"])
        time.sleep(1.0)  # let the tail open the (empty) file at its end
        with log.open("a", encoding="utf-8") as fh:
            for _ in range(6):
                fh.write(ssh_line(ATTACKER))
            fh.write(ssh_line("10.1.2.3"))  # private address: must never be blocked
            fh.write("garbage that is not a log line\n")
        bans = wait_for(lambda: get(port, "/api/bans")["bans"])
        assert [b["ip"] for b in bans] == [ATTACKER]
        summary = get(port, "/api/summary")
        assert summary["mode"] == "observe"
        assert summary["stats"]["failures_24h"] >= 6
        assert summary["stats"]["active_bans"] == 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
