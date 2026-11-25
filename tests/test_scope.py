
"""Automated tests for scope validation."""

from webguard.security.scope_validator import validate_target


def test_approved_target():
    assert validate_target("http://127.0.0.1:8000") is True


def test_unapproved_target():
    assert validate_target("https://google.com") is False


def test_invalid_url():
    assert validate_target("invalid-url") is False


def test_unsupported_protocol():
    assert validate_target("ftp://127.0.0.1:8000") is False


def test_unapproved_port():
    assert validate_target("http://127.0.0.1:9000") is False


def test_empty_target():
    assert validate_target("") is False


def test_embedded_credentials():
    assert validate_target(
        "http://user:password@127.0.0.1:8000"
    ) is False


def test_unapproved_path():
    assert validate_target(
        "http://127.0.0.1:8000/admin"
    ) is False
