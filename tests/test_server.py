import http.client
import json
import threading

import pytest

from portcullis.config import Config
from portcullis.engine import Engine
from portcullis.firewall import DryRunFirewall
from portcullis.server import make_server
from portcullis.store import Store

BAD = "8.8.4.4"


@pytest.fixture
def api():
    servers = []

    def start(token=""):
        cfg = Config()
        cfg.firewall.dry_run = False
        engine = Engine(cfg, Store(), DryRunFirewall())
        srv = make_server(engine, "127.0.0.1", 0, token=token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return engine, srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def call(port, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = dict(headers or {})
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    payload = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), payload


def test_dashboard_page_and_assets_are_served_with_strict_security_headers(api):
    _, port = api()
    status, headers, body = call(port, "GET", "/")
    assert status == 200 and b"Portcullis" in body
    assert headers["Content-Type"].startswith("text/html")
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in headers
    assert call(port, "GET", "/static/app.js")[0] == 200
    assert call(port, "GET", "/static/style.css")[1]["Content-Type"].startswith("text/css")


def test_static_path_traversal_is_not_possible(api):
    _, port = api()
    for path in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/config.py",
                 "/static/", "/static/nope.js"):
        assert call(port, "GET", path)[0] == 404


def test_summary_reports_mode_version_and_stats(api):
    _, port = api()
    status, _, body = call(port, "GET", "/api/summary")
    data = json.loads(body)
    assert status == 200 and data["mode"] == "enforce" and "version" in data
    assert data["stats"]["active_bans"] == 0 and len(data["stats"]["hourly"]) == 24


def test_health_endpoint_needs_no_token(api):
    _, port = api(token="a-long-enough-token")
    assert call(port, "GET", "/api/health")[0] == 200


def test_token_is_required_when_configured(api):
    _, port = api(token="a-long-enough-token")
    assert call(port, "GET", "/api/summary")[0] == 401
    assert call(port, "GET", "/api/summary", headers={"Authorization": "Bearer nope"})[0] == 401
    ok = call(port, "GET", "/api/summary", headers={"Authorization": "Bearer a-long-enough-token"})
    assert ok[0] == 200
    assert call(port, "POST", "/api/ban", {"ip": BAD})[0] == 401


def test_ban_list_and_unban_round_trip(api):
    engine, port = api()
    status, _, body = call(port, "POST", "/api/ban", {"ip": BAD, "reason": "scanner", "hours": 2})
    assert status == 201 and json.loads(body)["ban"]["ip"] == BAD
    listed = json.loads(call(port, "GET", "/api/bans")[2])["bans"]
    assert [b["ip"] for b in listed] == [BAD]
    assert call(port, "POST", "/api/unban", {"ip": BAD})[0] == 200
    assert json.loads(call(port, "GET", "/api/bans")[2])["bans"] == []
    assert call(port, "POST", "/api/unban", {"ip": BAD})[0] == 404
    assert engine.firewall.log[0] == ("block", BAD)


def test_bad_input_is_rejected_with_clear_errors(api):
    _, port = api()
    assert call(port, "POST", "/api/ban", {"ip": "1.2.3.4; reboot"})[0] == 400
    assert call(port, "POST", "/api/ban", {"ip": "10.0.0.1"})[0] == 400  # protected
    assert call(port, "POST", "/api/ban", {"ip": BAD, "hours": -5})[0] == 400
    assert call(port, "POST", "/api/ban", {"ip": BAD, "hours": "lots"})[0] == 400
    assert call(port, "POST", "/api/ban", {})[0] == 400
    assert call(port, "POST", "/api/ban", raw=b"{not json", headers={
        "Content-Type": "application/json"})[0] == 400
    assert call(port, "POST", "/api/ban", raw=b'["a"]', headers={
        "Content-Type": "application/json"})[0] == 400


def test_posts_must_be_json_so_a_web_page_cannot_trigger_them(api):
    _, port = api()
    status, _, _ = call(port, "POST", "/api/ban", raw=f"ip={BAD}".encode(),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 415


def test_oversized_bodies_are_refused(api):
    _, port = api()
    status, _, _ = call(port, "POST", "/api/ban", raw=b"x" * 100_000,
                        headers={"Content-Type": "application/json"})
    assert status == 413


def test_unexpected_host_header_is_refused_to_stop_dns_rebinding(api):
    _, port = api()
    assert call(port, "GET", "/api/summary", headers={"Host": "evil.example.com"})[0] == 403
    assert call(port, "GET", "/api/summary", headers={"Host": f"localhost:{port}"})[0] == 200


def test_allow_list_endpoints(api):
    _, port = api()
    assert call(port, "POST", "/api/allow", {"ip": "9.9.9.9", "note": "office"})[0] == 200
    allowed = json.loads(call(port, "GET", "/api/allow")[2])["allowed"]
    assert allowed == {"9.9.9.9": "office"}
    assert call(port, "POST", "/api/unallow", {"ip": "9.9.9.9"})[0] == 200
    assert call(port, "POST", "/api/unallow", {"ip": "9.9.9.9"})[0] == 404


def test_events_endpoint_limits_and_clamps(api):
    engine, port = api()
    from portcullis.models import AuthEvent
    for i in range(5):
        engine.handle_event(AuthEvent(1_800_000_000.0 + i, BAD, "root", "ssh", False))
    got = json.loads(call(port, "GET", "/api/events?limit=3")[2])["events"]
    assert len(got) == 3
    assert call(port, "GET", "/api/events?limit=abc")[0] == 400
    assert len(json.loads(call(port, "GET", "/api/events?limit=99999")[2])["events"]) == 5


def test_unknown_routes_and_methods(api):
    _, port = api()
    assert call(port, "GET", "/nope")[0] == 404
    assert call(port, "DELETE", "/api/bans")[0] == 405
    assert call(port, "PUT", "/api/ban", {"ip": BAD})[0] == 405
