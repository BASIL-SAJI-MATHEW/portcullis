from portcullis.config import Config
from portcullis.notify import Notifiers, abuse_lookup, humanize, make_notifiers, safe_text


class Recorder:
    def __init__(self, ok=True):
        self.sent, self.ok = [], ok

    def __call__(self, url, payload):
        self.sent.append((url, payload))
        return self.ok


def cfg_with(**kw):
    cfg = Config()
    for key, value in kw.items():
        setattr(cfg.notify, key, value)
    return cfg


def test_nothing_is_sent_when_no_channel_is_configured():
    rec = Recorder()
    n = make_notifiers(Config(), post=rec, sync=True)
    assert n.send("hello") == 0 and rec.sent == []


def test_discord_payload_blocks_all_mentions():
    rec = Recorder()
    n = make_notifiers(cfg_with(discord_webhook="https://discord.com/api/webhooks/1/x"),
                       post=rec, sync=True)
    assert n.send("user @everyone tried root") == 1
    url, payload = rec.sent[0]
    assert url == "https://discord.com/api/webhooks/1/x"
    assert payload["allowed_mentions"] == {"parse": []}
    assert "@everyone" in payload["content"]  # shown as text, but cannot ping because of parse=[]


def test_slack_payload_escapes_markup_that_could_inject_links_or_mentions():
    rec = Recorder()
    n = make_notifiers(cfg_with(slack_webhook="https://hooks.slack.com/services/T/B/x"),
                       post=rec, sync=True)
    n.send("user <!channel> & <http://evil|click>")
    text = rec.sent[0][1]["text"]
    assert "<!channel>" not in text and "<http" not in text
    assert "&lt;!channel&gt;" in text and "&amp;" in text


def test_telegram_payload_and_url():
    rec = Recorder()
    n = make_notifiers(cfg_with(telegram_token="123:ABC", telegram_chat_id="-100500"),
                       post=rec, sync=True)
    n.send("hi")
    url, payload = rec.sent[0]
    assert url == "https://api.telegram.org/bot123:ABC/sendMessage"
    assert payload["chat_id"] == "-100500" and payload["text"] == "hi"


def test_a_failing_channel_never_raises_and_other_channels_still_get_the_message():
    class Boom:
        def __call__(self, url, payload):
            if "discord" in url:
                raise RuntimeError("network down")
            return True

    cfg = cfg_with(discord_webhook="https://discord.com/api/webhooks/1/x",
                   slack_webhook="https://hooks.slack.com/services/T/B/x")
    assert make_notifiers(cfg, post=Boom(), sync=True).send("x") == 1


def test_plain_http_webhooks_are_refused():
    rec = Recorder()
    cfg = cfg_with(discord_webhook="http://insecure.example/hook")
    assert make_notifiers(cfg, post=rec, sync=True).send("x") == 0
    assert rec.sent == []


def test_safe_text_strips_control_characters_and_newline_tricks():
    assert safe_text("root\r\nSYSTEM: do bad") == "root SYSTEM: do bad"
    assert safe_text("a" * 500).endswith("...") and len(safe_text("a" * 500)) <= 120


def test_humanize_durations():
    assert humanize(None) == "permanently"
    assert humanize(3600) == "1 hour"
    assert humanize(90) == "1 minute"
    assert humanize(86_400 * 2) == "2 days"
    assert humanize(7200) == "2 hours"


def test_abuse_lookup_returns_score_country_and_reports():
    def get(url, headers):
        assert headers["Key"] == "k" and "ipAddress=203.0.113.5" in url
        return {"data": {"abuseConfidenceScore": 97, "countryCode": "CN", "totalReports": 41}}

    assert abuse_lookup("203.0.113.5", "k", get) == {"score": 97, "country": "CN", "reports": 41}


def test_abuse_lookup_is_quiet_without_a_key_or_on_errors():
    assert abuse_lookup("203.0.113.5", "", lambda u, h: {}) is None

    def broken(url, headers):
        raise OSError("timeout")

    assert abuse_lookup("203.0.113.5", "k", broken) is None
    assert abuse_lookup("203.0.113.5", "k", lambda u, h: {"nope": 1}) is None


def test_send_appends_reputation_when_an_ip_is_given():
    rec = Recorder()
    cfg = cfg_with(discord_webhook="https://discord.com/api/webhooks/1/x")
    cfg.abuseipdb.api_key = "k"
    n = make_notifiers(
        cfg, post=rec, sync=True,
        get=lambda u, h: {"data": {"abuseConfidenceScore": 88, "countryCode": "RU",
                                   "totalReports": 5}})
    n.send("blocked", ip="203.0.113.5")
    assert "AbuseIPDB" in rec.sent[0][1]["content"] and "88" in rec.sent[0][1]["content"]


def test_notifiers_object_is_constructible_directly():
    assert Notifiers([], sync=True).send("x") == 0
