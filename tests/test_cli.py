
"""Automated tests for CLI and safety controls."""

import sys
from unittest.mock import Mock

from webguard import cli

TARGET = "http://127.0.0.1:8000"


def test_unapproved_target(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["main.py", "--target", "https://google.com"]
    )

    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)

    assert cli.main() == 1
    audit.assert_not_called()


def test_authorization_denied(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["main.py", "--target", TARGET]
    )

    monkeypatch.setattr(
        cli, "confirm_authorization", lambda _: False
    )

    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)

    assert cli.main() == 1
    audit.assert_not_called()


def test_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv",
        ["main.py", "--target", TARGET, "--dry-run"]
    )

    monkeypatch.setattr(
        cli, "confirm_authorization", lambda _: True
    )

    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)

    assert cli.main() == 0
    audit.assert_not_called()
    assert "DRY-RUN MODE" in capsys.readouterr().out


def test_normal_execution(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["main.py", "--target", TARGET]
    )

    monkeypatch.setattr(
        cli, "confirm_authorization", lambda _: True
    )

    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)

    assert cli.main() == 0
    audit.assert_called_once_with(TARGET)


def test_kill_switch(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv",
        ["main.py", "--target", TARGET]
    )

    monkeypatch.setattr(
        cli, "confirm_authorization", lambda _: True
    )

    monkeypatch.setattr(
        cli, "run_audit",
        Mock(side_effect=KeyboardInterrupt)
    )

    assert cli.main() == 130
    assert "Kill switch activated" in capsys.readouterr().out
