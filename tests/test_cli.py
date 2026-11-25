import random

from portcullis import __version__
from portcullis.cli import main
from portcullis.config import Config
from portcullis.engine import Engine
from portcullis.firewall import DryRunFirewall
from portcullis.simulate import Simulator
from portcullis.store import Store


def test_version(capsys):
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_init_writes_a_valid_observe_mode_config_and_refuses_to_overwrite(tmp_path, capsys):
    path = tmp_path / "portcullis.toml"
    assert main(["init", "--path", str(path)]) == 0
    text = path.read_text(encoding="utf-8")
    assert "dry_run = true" in text and "max_failures" in text
    assert main(["check", "-c", str(path)]) == 0
    assert main(["init", "--path", str(path)]) == 1  # would overwrite
    assert main(["init", "--path", str(path), "--force"]) == 0


def test_check_reports_config_errors_and_exits_nonzero(tmp_path, capsys):
    path = tmp_path / "bad.toml"
    path.write_text("[firewall]\ndry_runn = false\n")
    assert main(["check", "-c", str(path)]) == 2
    assert "dry_runn" in capsys.readouterr().err


def test_check_on_a_missing_file_is_an_error(tmp_path, capsys):
    assert main(["check", "-c", str(tmp_path / "nope.toml")]) == 2


def test_ban_list_and_unban_commands_use_the_database(tmp_path, capsys):
    cfg = tmp_path / "p.toml"
    db = (tmp_path / "p.db").as_posix()
    cfg.write_text(f'[storage]\npath = "{db}"\n[firewall]\ndry_run = true\n')
    assert main(["ban", "8.8.4.4", "-c", str(cfg), "--hours", "2", "--reason", "scanner"]) == 0
    assert main(["bans", "-c", str(cfg)]) == 0
    assert "8.8.4.4" in capsys.readouterr().out
    assert main(["unban", "8.8.4.4", "-c", str(cfg)]) == 0
    capsys.readouterr()  # discard the "Unblocked 8.8.4.4" line the unban command printed
    assert main(["bans", "-c", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert "8.8.4.4" not in out and "No active blocks" in out


def test_ban_command_rejects_bad_addresses(tmp_path, capsys):
    cfg = tmp_path / "p.toml"
    db = (tmp_path / "p.db").as_posix()
    cfg.write_text(f'[storage]\npath = "{db}"\n')
    assert main(["ban", "not-an-ip", "-c", str(cfg)]) == 2
    assert main(["ban", "10.0.0.1", "-c", str(cfg)]) == 2  # protected


def test_simulator_can_backfill_a_day_of_history_without_creating_blocks():
    cfg = Config()
    cfg.detection.ignore_private = False
    engine = Engine(cfg, Store(), DryRunFirewall())
    Simulator(engine, rng=random.Random(3)).seed_history()
    stats = engine.store.stats(engine.clock())
    assert sum(1 for h in stats["hourly"] if h["failures"] > 0) >= 20
    assert stats["total_bans"] == 0


def test_simulator_produces_attacks_that_get_banned_and_a_legit_login():
    cfg = Config()
    cfg.detection.ignore_private = False
    engine = Engine(cfg, Store(), DryRunFirewall())
    sim = Simulator(engine, rng=random.Random(7))
    for _ in range(400):
        sim.step()
    stats = engine.store.stats(engine.clock())
    assert stats["failures_24h"] > 100
    assert stats["total_bans"] >= 3
    assert stats["successes_24h"] >= 1
