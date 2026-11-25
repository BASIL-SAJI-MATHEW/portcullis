# Implementation plan

Goal: build Portcullis, a self-hosted login-attack shield for Windows RDP and Linux SSH.
Spec: [design.md](design.md). Stack: Python 3.11+, standard library only, SQLite, pytest, ruff.

Every task was done test-first: write the failing test, watch it fail, write the code, watch it pass.

| # | Task | Files | Status |
|---|---|---|---|
| 1 | Log and event parsers | `parsers.py`, `tests/test_parsers.py` | done |
| 2 | Sliding-window detector | `detector.py`, `tests/test_detector.py` | done |
| 3 | SQLite store | `store.py`, `tests/test_store.py` | done |
| 4 | Strict configuration | `config.py`, `tests/test_config.py` | done |
| 5 | Firewall command builders | `firewall.py`, `tests/test_firewall.py` | done |
| 6 | Alerts and AbuseIPDB | `notify.py`, `tests/test_notify.py` | done |
| 7 | Engine | `engine.py`, `tests/test_engine.py` | done |
| 8 | Log sources | `sources.py`, `tests/test_sources.py` | done |
| 9 | Dashboard server and API | `server.py`, `static/`, `tests/test_server.py` | done |
| 10 | CLI and demo simulator | `cli.py`, `simulate.py`, `tests/test_cli.py` | done |
| 11 | End-to-end test of the real service | `tests/test_e2e.py` | done |
| 12 | Installers, Docker, CI, docs | `install.*`, `Dockerfile`, `.github/` | done |

## Review focus (inputs the spec implies but is easy to forget)

- A log line that is huge, binary or not UTF-8 must not crash or stall the watcher.
- The same attempt logged twice by sshd must not be counted twice.
- A config saved by Windows Notepad (with a byte-order mark) must load.
- A client that sends a body the server rejects must still receive the error response.
- An address that is on the allow list, or is private, must never be blocked even by hand.
- A firewall call that fails must not leave a block recorded as if it worked.
