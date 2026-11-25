import pytest

from portcullis.config import Config, ConfigError, load_config


def write(tmp_path, text):
    p = tmp_path / "portcullis.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_defaults_are_safe_observe_only_and_localhost():
    cfg = Config()
    assert cfg.firewall.dry_run is True
    assert cfg.dashboard.host == "127.0.0.1"
    assert cfg.detection.max_failures == 5
    assert cfg.detection.ignore_private is True


def test_load_overrides_values(tmp_path):
    cfg = load_config(write(tmp_path, """
[detection]
max_failures = 8
ban_seconds = 7200
[firewall]
dry_run = false
[allowlist]
addresses = ["203.0.113.0/24"]
"""))
    assert cfg.detection.max_failures == 8
    assert cfg.detection.ban_seconds == 7200
    assert cfg.firewall.dry_run is False
    assert cfg.is_allowed("203.0.113.77") is True
    assert cfg.is_allowed("8.8.8.8") is False  # a real public address, not in the allow list


def test_config_saved_by_windows_notepad_with_a_utf8_bom_still_loads(tmp_path):
    p = tmp_path / "portcullis.toml"
    p.write_bytes(b"\xef\xbb\xbf" + b"[detection]\nmax_failures = 7\n")
    assert load_config(str(p)).detection.max_failures == 7


def test_missing_file_gives_defaults():
    assert load_config(None).detection.max_failures == 5


def test_unknown_key_is_an_error_because_typos_in_security_config_are_dangerous(tmp_path):
    with pytest.raises(ConfigError, match="dry_runn"):
        load_config(write(tmp_path, "[firewall]\ndry_runn = false\n"))


def test_unknown_section_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="firewal"):
        load_config(write(tmp_path, "[firewal]\ndry_run = false\n"))


def test_wrong_type_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="max_failures"):
        load_config(write(tmp_path, '[detection]\nmax_failures = "five"\n'))


def test_out_of_range_value_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="max_failures"):
        load_config(write(tmp_path, "[detection]\nmax_failures = 0\n"))


def test_bad_allowlist_entry_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not-an-ip"):
        load_config(write(tmp_path, '[allowlist]\naddresses = ["not-an-ip"]\n'))


def test_public_dashboard_requires_a_token(tmp_path):
    with pytest.raises(ConfigError, match="token"):
        load_config(write(tmp_path, '[dashboard]\nhost = "0.0.0.0"\n'))
    cfg = load_config(write(tmp_path, '[dashboard]\nhost = "0.0.0.0"\ntoken = "s3cret-token-value"\n'))
    assert cfg.dashboard.host == "0.0.0.0"


def test_token_can_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PORTCULLIS_TOKEN", "from-env-token")
    cfg = load_config(write(tmp_path, '[dashboard]\nhost = "0.0.0.0"\n'))
    assert cfg.dashboard.token == "from-env-token"


def test_private_and_loopback_addresses_are_ignored_by_default():
    cfg = Config()
    assert cfg.is_allowed("127.0.0.1") and cfg.is_allowed("10.1.2.3") and cfg.is_allowed("::1")
    assert not cfg.is_allowed("8.8.8.8")


def test_private_addresses_can_be_included_when_asked():
    cfg = Config()
    cfg.detection.ignore_private = False
    assert not cfg.is_allowed("10.1.2.3")


def test_rules_reflect_detection_settings():
    cfg = Config()
    cfg.detection.max_failures = 9
    assert cfg.rules().max_failures == 9
