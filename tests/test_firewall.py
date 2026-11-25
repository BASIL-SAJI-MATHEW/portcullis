import pytest

from portcullis.config import Config
from portcullis.firewall import (
    CommandFirewall,
    DryRunFirewall,
    build_commands,
    make_firewall,
    validate_ip,
)


def test_validate_ip_accepts_v4_and_v6_and_normalises():
    assert validate_ip("203.0.113.5") == "203.0.113.5"
    assert validate_ip("2001:0db8:0:0:0:0:0:1") == "2001:db8::1"


@pytest.mark.parametrize("bad", [
    "", "1.2.3.4; rm -rf /", "256.1.1.1", "1.2.3.0/24", "a b", "$(id)", "1.2.3.4\n5.6.7.8", "-1.1.1.1",
])
def test_validate_ip_rejects_anything_that_is_not_a_plain_address(bad):
    with pytest.raises(ValueError):
        validate_ip(bad)


def test_windows_commands():
    cmds = build_commands("windows", "203.0.113.5")
    assert cmds["add"] == [
        "netsh", "advfirewall", "firewall", "add", "rule", "name=Portcullis 203.0.113.5",
        "dir=in", "action=block", "remoteip=203.0.113.5", "enable=yes"]
    assert cmds["delete"] == [
        "netsh", "advfirewall", "firewall", "delete", "rule", "name=Portcullis 203.0.113.5"]
    assert cmds["check"][:5] == ["netsh", "advfirewall", "firewall", "show", "rule"]


def test_iptables_commands_use_the_right_tool_for_each_ip_version():
    v4 = build_commands("iptables", "203.0.113.5")
    v6 = build_commands("iptables", "2001:db8::1")
    assert v4["add"][0] == "iptables" and v6["add"][0] == "ip6tables"
    assert v4["add"] == ["iptables", "-I", "INPUT", "-s", "203.0.113.5", "-m", "comment",
                         "--comment", "portcullis", "-j", "DROP"]
    assert v4["check"][1] == "-C" and v4["delete"][1] == "-D"


def test_building_commands_for_a_bad_ip_raises_before_anything_runs():
    with pytest.raises(ValueError):
        build_commands("iptables", "1.2.3.4; reboot")


class FakeRunner:
    def __init__(self, existing=False, fail=False):
        self.calls, self.existing, self.fail = [], existing, fail

    def __call__(self, cmd):
        self.calls.append(cmd)
        if self.fail:
            raise FileNotFoundError("netsh")
        if cmd[1:2] == ["-C"] or "show" in cmd:
            return 0 if self.existing else 1
        return 0


def test_block_checks_first_and_adds_when_missing():
    r = FakeRunner()
    fw = CommandFirewall("iptables", runner=r)
    assert fw.block("203.0.113.5") is True
    assert [c[1] for c in r.calls] == ["-C", "-I"]


def test_block_is_idempotent_when_the_rule_already_exists():
    r = FakeRunner(existing=True)
    fw = CommandFirewall("iptables", runner=r)
    assert fw.block("203.0.113.5") is True
    assert len(r.calls) == 1  # only the check ran


def test_unblock_runs_delete():
    r = FakeRunner(existing=True)
    assert CommandFirewall("iptables", runner=r).unblock("203.0.113.5") is True
    assert r.calls[-1][1] == "-D"


def test_a_missing_firewall_tool_returns_false_instead_of_crashing():
    fw = CommandFirewall("windows", runner=FakeRunner(fail=True))
    assert fw.block("203.0.113.5") is False
    assert fw.unblock("203.0.113.5") is False


def test_dry_run_never_runs_anything_and_remembers_what_it_would_do():
    fw = DryRunFirewall()
    assert fw.block("203.0.113.5") is True
    assert fw.unblock("203.0.113.5") is True
    assert fw.log == [("block", "203.0.113.5"), ("unblock", "203.0.113.5")]


def test_make_firewall_respects_dry_run_and_backend_choice():
    cfg = Config()
    assert isinstance(make_firewall(cfg), DryRunFirewall)  # dry_run defaults to true
    cfg.firewall.dry_run = False
    cfg.firewall.backend = "iptables"
    fw = make_firewall(cfg)
    assert isinstance(fw, CommandFirewall) and fw.backend == "iptables"
