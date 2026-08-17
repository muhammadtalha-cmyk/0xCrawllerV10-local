from pathlib import Path

from smart_recon.cli import build_parser
from smart_recon.commands import build_commands, build_wafw00f_command


def test_httpx_commands_include_wappalyzer_and_cdn(tmp_path: Path):
    commands = build_commands("example.com", tmp_path, False)
    for name in ("httpx_root_probe", "httpx_probe", "httpx_browser_discovered"):
        command = commands[name]
        assert "-tech-detect" in command
        assert "-cdn" in command
        assert "-cname" in command


def test_wafw00f_command_is_structured_and_bounded(tmp_path: Path):
    command = build_wafw00f_command(tmp_path, request_timeout=9, find_all=True)
    assert "smartrecon/wafw00f:2.4.2" in command
    assert command[command.index("-i") + 1] == "/output/waf_targets.txt"
    assert command[command.index("-o") + 1] == "/output/wafw00f.json"
    assert command[command.index("-f") + 1] == "json"
    assert command[command.index("-T") + 1] == "9"
    assert "-a" in command


def test_cli_active_waf_aliases():
    parser = build_parser()
    args = parser.parse_args(["--target", "example.com", "--authorized", "--wafw00f"])
    assert args.active_waf is True
    assert args.waf_limit == 20
    assert args.waf_request_timeout == 7
