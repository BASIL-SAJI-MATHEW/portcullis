# Portcullis design

## Intent

Make it easy for anyone who runs a Windows or Linux server to stop brute-force login attacks on
RDP and SSH, with a dashboard that shows what is happening. Success looks like: a person installs it
in about a minute, sees attackers appear on the dashboard, and trusts it enough to turn blocking on.

## Goals

- One tool for Windows RDP and Linux SSH.
- Safe by default: observe mode, never block private networks or the admin's own SSH session.
- Zero runtime dependencies (Python standard library only).
- A real dashboard and chat alerts.

## Non-goals

- Replacing fail2ban's breadth of filters, or managing a fleet of servers.
- Machine-learning detection. The rules are simple on purpose so they can be explained.

## Anti-goals (a failure even if it technically works)

- Locking a legitimate admin out of their own server.
- Becoming a way for an attacker to block addresses or run commands (the tool controls a firewall).

## Approaches considered

1. **FastAPI + SQLModel + a JS framework dashboard.** Familiar and quick, but adds compiled
   dependencies, a build step and a bigger attack surface. Rejected. (It also failed on a locked-down
   Windows machine whose application-control policy blocked a compiled dependency.)
2. **A thin wrapper around fail2ban.** Linux only and does not solve Windows. Rejected.
3. **Standard-library Python with a single static dashboard page.** Chosen: trivially installable,
   easy to audit, runs the same on both operating systems.

## Architecture

parsers -> detector -> engine -> (firewall, store, notifiers); server reads the store.
Each unit has one job and a small interface, so each can be tested alone. See the README for a diagram.

## Decisions

- **Only `Failed ...` SSH lines count**, because sshd also logs `Invalid user ...` for the same
  attempt and counting both would halve the threshold.
- **Windows RDP failures are events 4625 with logon type 3 or 10**, because with Network Level
  Authentication failed RDP logons are recorded as type 3. Successes are 4624 with type 10.
- **Documentation address ranges count as private** in Python's `ipaddress`, so the demo turns
  `ignore_private` off.
- **Blocks are only recorded if the firewall call succeeded**, so the dashboard never claims a
  block that did not happen.
- **Unknown config keys are errors**, because a typo in a security setting must not be silent.
- **POSTs must be JSON** and the dashboard sends a strict CSP, so a web page cannot drive it.

## Verification

See "What is and is not tested" in the README.
