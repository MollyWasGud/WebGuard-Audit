"""End-to-end: CLI -> scope check -> fetch -> Module 1 audit -> risk/compliance -> JSON + HTML report."""

import json
import sys

from webguard import cli
from webguard.security import scope_validator
from demo.servers import HardenedHandler, WeakHandler, start


def _run(monkeypatch, tmp_path, url):
    # The real scope allows only 127.0.0.1:8000; tests approve their own random loopback port.
    origin = ("http", url.split("//")[1].rstrip("/"))
    monkeypatch.setattr(scope_validator, "APPROVED_SCOPE", {origin})
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", url])
    monkeypatch.setattr(cli, "confirm_authorization", lambda _: True)
    return cli.main()


def test_weak_server_is_reported(monkeypatch, tmp_path, capsys):
    server, url = start(WeakHandler)
    try:
        assert _run(monkeypatch, tmp_path, url) == 0
    finally:
        server.shutdown()
        server.server_close()
    out = capsys.readouterr().out
    assert "JSON report" in out and "HTML report" in out
    jsons = list(tmp_path.rglob("*.json"))
    htmls = list(tmp_path.rglob("*.html"))
    assert jsons and htmls
    data = json.loads(jsons[0].read_text(encoding="utf-8"))
    assert data["findings"]


def test_hardened_server_has_fewer_findings(monkeypatch, tmp_path, capsys):
    server, url = start(HardenedHandler)
    try:
        assert _run(monkeypatch, tmp_path, url) == 0
    finally:
        server.shutdown()
        server.server_close()
    assert "Findings: 0" in capsys.readouterr().out


def test_unreachable_target_returns_error(monkeypatch, tmp_path, capsys):
    assert _run(monkeypatch, tmp_path, "http://127.0.0.1:1") == 1
    assert "Could not audit" in capsys.readouterr().out
