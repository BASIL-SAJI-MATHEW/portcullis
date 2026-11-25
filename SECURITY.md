# Security policy

Portcullis is a security tool that edits firewall rules, so security reports are taken seriously.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Include what you found, how to reproduce it, and the version
(`portcullis version`). You will get an acknowledgement within a few days.

## What is in scope

- Anything that lets a remote attacker block an address they should not be able to block, remove a
  block, read data, or run commands through the dashboard, the API, a log line or a Windows event.
- Command injection through usernames, IP addresses or other log content.
- Ways to bypass the allow list or the protection of private addresses.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.

## Design choices that matter for security

- Firewall commands are built as argument lists from an address that has been parsed with Python's
  `ipaddress` module. No shell is used.
- The dashboard listens on `127.0.0.1` unless a token of at least 12 characters is configured.
- Log lines and event XML are treated as hostile: lengths are bounded, DOCTYPE and ENTITY
  declarations in XML are rejected, and usernames are stripped of control characters before they are
  stored or sent in alerts.
