
"""Automated tests for CLI and safety controls."""

import sys
from unittest.mock import Mock

import pytest

from webguard import cli

TARGET = "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    ("scheme", "expected"),
    [
        (
            "http",
            [
                ("http_headers", "HTTP security header analysis"),
                ("http_redirect", "First-hop HTTP redirect assessment"),
            ],
        ),
        (
            "https",
            [
                ("tls_certificate", "Certificate and verified TLS connectivity"),
                ("tls_protocols", "Modern TLS protocol assessment"),
                ("http_redirect", "HTTPS availability and first-hop redirect assessment"),
            ],
        ),
    ],
)
def test_operation_plan_returns_ordered_list(scheme, expected):
    assert cli._operation_plan(scheme) == expected


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

    audit = Mock(return_value=0)
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


@pytest.mark.parametrize("suffix", ["", "--dry-run"])
def test_approved_https_plan(monkeypatch, capsys, suffix):
    target = "https://127.0.0.1:8443"
    audit = Mock(return_value=0)
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--target", target] + ([suffix] if suffix else [])
    )
    assert cli.main() == 0
    if suffix:
        out = capsys.readouterr().out
        assert "Certificate and verified TLS connectivity" in out
        assert "Modern TLS protocol assessment" in out
        assert "HTTPS availability and first-hop redirect assessment" in out
        assert "HTTP security header analysis" not in out
        audit.assert_not_called()
    else:
        audit.assert_called_once_with(target)


@pytest.mark.parametrize(
    "target",
    [
        "https://127.0.0.1:8000",
        "https://127.0.0.1:443",
        "https://localhost:8443",
        "https://127.0.0.2:8443",
        "http://127.0.0.1:8443",
    ],
)
def test_exact_origin_blocks_secondary_targets(monkeypatch, target):
    auth = Mock(return_value=True)
    audit = Mock()
    monkeypatch.setattr(cli, "confirm_authorization", auth)
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", target])
    assert cli.main() == 1
    auth.assert_not_called()
    audit.assert_not_called()


def test_startup_legal_disclaimer_before_authorization(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", TARGET])
    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)

    def deny_authorization(_):
        out = capsys.readouterr().out
        assert "LEGAL DISCLAIMER" in out
        assert "Computer Crimes Act 1997 (Act 563)" in out
        assert "authorized security auditing only" in out
        return "no"

    monkeypatch.setattr("builtins.input", deny_authorization)
    assert cli.main() == 1
    audit.assert_not_called()


def test_help_includes_approved_usage_examples(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "python main.py --target http://127.0.0.1:8000" in out
    assert "python main.py --target https://127.0.0.1:8443 --dry-run" in out


def test_release_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--version"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "WebGuard Audit 1.0.0"
