
"""Automated tests for authorization safeguards."""

from webguard.security.authorization import confirm_authorization


def test_authorization_accepted(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "yes")

    assert confirm_authorization("http://127.0.0.1:8000") is True


def test_authorization_denied(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "no")

    assert confirm_authorization("http://127.0.0.1:8000") is False


def test_invalid_response(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "maybe")

    assert confirm_authorization("http://127.0.0.1:8000") is False


def test_empty_response(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")

    assert confirm_authorization("http://127.0.0.1:8000") is False


def test_authorization_interrupted(monkeypatch):
    def interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)

    assert confirm_authorization("http://127.0.0.1:8000") is False
