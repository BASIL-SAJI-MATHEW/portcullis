# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - 2026-11-25

First release.

### Added
- Detection of brute-force and password-spray logins for Linux SSH (auth.log, secure, journald) and
  Windows RDP (Security log events 4625 and 4624).
- Automatic blocking with Windows Firewall (`netsh`) and `iptables`/`ip6tables`, with expiring blocks.
- Observe mode (the default): reports what would be blocked and blocks nothing.
- Web dashboard and JSON API with a 24-hour chart, top attackers and usernames, unblock and allow list.
- Alerts to Discord, Telegram and Slack, with optional AbuseIPDB reputation.
- `portcullis simulate` demo mode with fake attackers.
- Installers for Linux (systemd), Windows (startup task) and Docker.
- 118 automated tests, including an end-to-end test of the running service.
