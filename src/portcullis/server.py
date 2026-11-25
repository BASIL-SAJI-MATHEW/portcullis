"""The dashboard and its JSON API, on the standard library's HTTP server (no dependencies).

Hardening: strict Content-Security-Policy, JSON-only POSTs (a web page cannot send those
cross-site), a Host check when there is no token (DNS rebinding), bearer-token auth, constant-time
token comparison, size limits, and no CORS headers at all.
"""

from __future__ import annotations

import hmac
import json
import logging
import socket
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .engine import Engine
from .firewall import validate_ip
from .models import Ban

log = logging.getLogger("portcullis.server")

STATIC_DIR = Path(__file__).parent / "static"
ASSETS = {
    "app.js": "application/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}
MAX_BODY = 8 * 1024
MAX_SECONDS = 31_536_000
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

GET_ROUTES = {"/", "/api/health", "/api/summary", "/api/bans", "/api/events", "/api/allow"}
POST_ROUTES = {"/api/ban", "/api/unban", "/api/allow", "/api/unallow"}


def ban_dict(b: Ban) -> dict:
    return {"id": b.id, "ip": b.ip, "reason": b.reason, "created": b.created,
            "expires": b.expires, "source": b.source, "failures": b.failures}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    engine: Engine
    token: str
    hosts: frozenset[str]


class Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "Portcullis"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---------------------------------------------------------------- plumbing

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: dict, extra: dict | None = None) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json", extra)

    def _error(self, status: int, message: str, extra: dict | None = None) -> None:
        self._json(status, {"error": message}, extra)

    def _host_ok(self) -> bool:
        if self.server.token:  # the token already protects the API
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        name = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return name in self.server.hosts

    def _authorised(self) -> bool:
        token = self.server.token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        return hmac.compare_digest(supplied.encode(), token.encode())

    def _slurp(self) -> None:
        """Read the request body up front, whatever the route.

        If we answered (401, 405, 413...) and closed with unread bytes still arriving, the
        operating system would reset the connection and the client would never see our answer.
        """
        self._raw, self._bad_length, self._too_big = b"", False, False
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._bad_length = True
            return
        if length < 0:
            self._bad_length = True
            return
        if length > MAX_BODY:
            self._too_big = True
            remaining = min(length, 1_000_000)  # drain a bounded amount, then give up
            while remaining > 0:
                got = self.rfile.read(min(65_536, remaining))
                if not got:
                    break
                remaining -= len(got)
            return
        self._raw = self.rfile.read(length) if length else b""

    def _read_json(self) -> dict | None:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._error(415, "Content-Type must be application/json")
            return None
        if self._bad_length:
            self._error(400, "bad Content-Length")
            return None
        if self._too_big:
            self._error(413, "request body too large")
            return None
        try:
            data = json.loads(self._raw or b"null")
        except (ValueError, UnicodeDecodeError):
            self._error(400, "body is not valid JSON")
            return None
        if not isinstance(data, dict):
            self._error(400, "body must be a JSON object")
            return None
        return data

    # ---------------------------------------------------------------- dispatch

    def _dispatch(self, method: str) -> None:
        try:
            self._route(method)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:  # noqa: BLE001
            log.exception("unhandled error in request")
            try:
                self._error(500, "internal error")
            except OSError:
                return

    def _route(self, method: str) -> None:
        self._slurp()
        if not self._host_ok():
            return self._error(403, "unexpected Host header")
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        if path.startswith("/static/"):
            name = urllib.parse.unquote(path[len("/static/"):])
            if method == "GET" and name in ASSETS:
                return self._send(200, (STATIC_DIR / name).read_bytes(), ASSETS[name])
            return self._error(404, "not found")
        known = path in GET_ROUTES or path in POST_ROUTES
        if not known:
            return self._error(404, "not found")
        allowed = ("GET",) if path in GET_ROUTES else ("POST",)
        if path == "/api/allow":
            allowed = ("GET", "POST")
        if method not in allowed:
            return self._error(405, "method not allowed", {"Allow": ", ".join(allowed)})
        if path == "/":
            return self._send(200, (STATIC_DIR / "index.html").read_bytes(),
                              "text/html; charset=utf-8")
        if path == "/api/health":
            return self._json(200, {"ok": True, "version": __version__})
        if not self._authorised():
            return self._error(401, "a valid bearer token is required",
                               {"WWW-Authenticate": "Bearer"})
        if method == "GET":
            return self._get(path, urllib.parse.parse_qs(url.query))
        body = self._read_json()
        if body is not None:
            self._post(path, body)

    do_GET = lambda self: self._dispatch("GET")  # noqa: E731
    do_POST = lambda self: self._dispatch("POST")  # noqa: E731
    do_PUT = lambda self: self._dispatch("PUT")  # noqa: E731
    do_DELETE = lambda self: self._dispatch("DELETE")  # noqa: E731
    do_PATCH = lambda self: self._dispatch("PATCH")  # noqa: E731
    do_HEAD = lambda self: self._dispatch("HEAD")  # noqa: E731

    # ---------------------------------------------------------------- GET

    def _get(self, path: str, query: dict) -> None:
        eng = self.server.engine
        now = eng.clock()
        if path == "/api/summary":
            return self._json(200, {
                "version": __version__, "now": now,
                "mode": "observe" if eng.cfg.firewall.dry_run else "enforce",
                "backend": type(eng.firewall).__name__,
                "stats": eng.store.stats(now), "allowed": eng.store.allowed()})
        if path == "/api/bans":
            return self._json(200, {"bans": [ban_dict(b) for b in eng.store.active_bans(now)]})
        if path == "/api/allow":
            return self._json(200, {"allowed": eng.store.allowed()})
        raw = query.get("limit", ["100"])[0]
        try:
            limit = int(raw)
        except ValueError:
            return self._error(400, "limit must be a number")
        if limit < 1:
            return self._error(400, "limit must be at least 1")
        events = eng.store.recent_events(min(limit, 500))
        self._json(200, {"events": [
            {"ts": e.ts, "ip": e.ip, "user": e.user, "service": e.service, "success": e.success}
            for e in events]})

    # ---------------------------------------------------------------- POST

    def _post(self, path: str, body: dict) -> None:
        eng = self.server.engine
        ip = body.get("ip")
        if not isinstance(ip, str):
            return self._error(400, "'ip' is required")
        try:
            if path == "/api/ban":
                seconds = self._seconds(body.get("hours"))
                reason = body.get("reason", "Manual ban")
                if not isinstance(reason, str):
                    return self._error(400, "'reason' must be text")
                ban = eng.ban(ip, reason, seconds=seconds)
                return self._json(201, {"ban": ban_dict(ban)})
            if path == "/api/unban":
                if eng.unban(ip):
                    return self._json(200, {"unbanned": ip})
                return self._error(404, "that address is not banned")
            if path == "/api/allow":
                note = body.get("note", "")
                if not isinstance(note, str):
                    return self._error(400, "'note' must be text")
                eng.allow(ip, note)
                return self._json(200, {"allowed": eng.store.allowed()})
            if eng.store.remove_allow(validate_ip(ip)):
                return self._json(200, {"allowed": eng.store.allowed()})
            return self._error(404, "that address is not on the allow list")
        except ValueError as exc:
            return self._error(400, str(exc))
        except RuntimeError as exc:
            return self._error(502, str(exc))

    @staticmethod
    def _seconds(hours: object) -> int | None:
        if hours is None:
            return None
        if isinstance(hours, bool) or not isinstance(hours, int | float):
            raise ValueError("'hours' must be a number")
        seconds = int(hours * 3600)
        if hours < 0 or seconds > MAX_SECONDS:
            raise ValueError("'hours' must be between 0 (permanent) and 8760")
        return seconds


def make_server(engine: Engine, host: str, port: int, token: str = "") -> _Server:
    class Server(_Server):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

    srv = Server((host, port), Handler)
    srv.engine = engine
    srv.token = token
    names = {"127.0.0.1", "localhost", "[::1]"}
    if host not in ("0.0.0.0", "::", ""):  # noqa: S104
        names.add(host.lower() if ":" not in host else f"[{host.lower()}]")
    srv.hosts = frozenset(names)
    return srv
