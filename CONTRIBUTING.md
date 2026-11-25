# Contributing to Portcullis

Thanks for helping. This project is small on purpose: standard library only, easy to read, easy to trust.

## Set up

```bash
git clone https://github.com/BASIL-SAJI-MATHEW/portcullis && cd portcullis
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check .
```

## Ground rules

- **Tests first.** A bug fix starts with a failing test that reproduces it. A new feature starts with
  the tests that describe it.
- **No runtime dependencies.** Please do not add one. If you think one is essential, open an issue to
  discuss it first.
- **Treat every log line as hostile.** Anything that comes from a log, a Windows event or a request
  can be controlled by an attacker. Validate it, bound it, and never build a shell string from it.
- **Keep observe mode the default.** A security tool that blocks by default can lock people out.
- Run `pytest` and `ruff check .` before you open a pull request. CI runs both on Linux and Windows.

## Good first contributions

- Real-world log samples (other sshd versions, other languages of Windows) that fail to parse.
- Test results from a real Windows or Linux server, good or bad.
- Documentation fixes and clearer error messages.

## Project layout

```
src/portcullis/
  parsers.py    log lines and Windows event XML into login events
  detector.py   sliding-window attack detection
  engine.py     decisions, blocking, alerts, expiry
  firewall.py   netsh and iptables command builders
  store.py      SQLite history
  server.py     dashboard and JSON API
  static/       the dashboard page
  cli.py        the portcullis command
tests/          one test file per module, plus an end-to-end test
docs/           design and implementation plan
```
