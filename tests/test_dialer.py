import http.client
import socket
import ssl
import sys
from unittest.mock import MagicMock, Mock

import pytest

from webguard import cli
from webguard.auditors import https, tls
from webguard.security.scope_validator import validate_target

TARGET = "http://127.0.0.1:8000"


@pytest.mark.parametrize(
    "target", ["\x00" + TARGET, TARGET + "\x7f", TARGET + "/?", TARGET + "/#"]
)
def test_malformed_targets_stop_before_confirmation(target, monkeypatch):
    prompt = Mock(return_value=False)
    audit = Mock()
    monkeypatch.setattr(cli, "confirm_authorization", prompt)
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", target])
    assert not validate_target(target)
    assert cli.main() == 1
    prompt.assert_not_called()
    audit.assert_not_called()


def test_dry_run_lists_only_current_operations(monkeypatch, capsys):
    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", TARGET, "--dry-run"])
    assert cli.main() == 0
    assert "TLS and HTTPS analysis" not in capsys.readouterr().out
    audit.assert_not_called()


def test_prompt_interrupt_exits_130(monkeypatch):
    monkeypatch.setattr("builtins.input", Mock(side_effect=KeyboardInterrupt))
    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", TARGET])
    assert cli.main() == 130
    audit.assert_not_called()


@pytest.mark.parametrize("failure", ["parser", "status"])
def test_invalid_http_response_is_safe_failure(monkeypatch, capsys, failure):
    conn = MagicMock()
    response = conn.getresponse.return_value
    response.status = 999
    if failure == "parser":
        conn.getresponse.side_effect = http.client.BadStatusLine("SYNTH_PRIVATE_42B")
    monkeypatch.setattr(http.client, "HTTPConnection", Mock(return_value=conn))
    monkeypatch.setattr(socket, "socket", Mock())
    from test_report_adapter import first_hop

    redirect = Mock(return_value=first_hop("http", "no_redirect", None, 200))
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    audit = Mock()
    render = Mock()
    monkeypatch.setattr(cli, "audit_http", audit)
    monkeypatch.setattr(cli, "generate_json_report", render)
    monkeypatch.setattr(cli, "generate_html_report", Mock())
    assert cli.run_audit(TARGET) == 1
    output = capsys.readouterr().out
    assert "SYNTH_PRIVATE_42B" not in output
    assert "Partial audit" in output
    audit.assert_not_called()
    render.assert_called_once()
    assert render.call_args.args[0]["findings"] == []
    assert any(
        row["coverage_status"] == "INCOMPLETE"
        for row in render.call_args.args[0]["audit_coverage"]
    )
    redirect.assert_called_once()
    conn.close.assert_called_once()


def authorized(**kwargs):
    from webguard.security.dialer import AuthorizedTransport

    return AuthorizedTransport("https", "origin.test", 8443, "127.0.0.1", **kwargs)


@pytest.mark.parametrize(
    "origin",
    [
        ("http", "origin.test", 8443),
        ("https", "other.test", 8443),
        ("https", "origin.test", 443),
    ],
)
def test_wrong_origin_is_refused_before_socket(monkeypatch, origin):
    from webguard.security.dialer import UnauthorizedDial

    factory = Mock()
    monkeypatch.setattr(socket, "socket", factory)
    with pytest.raises(UnauthorizedDial):
        authorized().connect(*origin, 5)
    factory.assert_not_called()


@pytest.mark.parametrize(
    "peer,address",
    [
        ("127.0.0.1", ("127.0.0.1", 8443)),
        ("::1", ("::1", 8443, 0, 0)),
    ],
)
def test_pinned_numeric_peer_has_no_second_resolution_or_fallback(
    monkeypatch, peer, address
):
    from webguard.security.dialer import AuthorizedTransport

    resolver = Mock(
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.2", 8443))]
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    factory = Mock()
    conn = factory.return_value
    conn.connect.side_effect = ConnectionRefusedError
    monkeypatch.setattr(socket, "socket", factory)
    transport = AuthorizedTransport("https", "origin.test", 8443, peer)
    with pytest.raises(ConnectionRefusedError):
        transport.connect("https", "origin.test", 8443, 5)
    resolver.assert_not_called()
    factory.assert_called_once()
    conn.connect.assert_called_once_with(address)
    conn.close.assert_called_once()


def test_transport_rejects_scoped_ipv6_before_socket(monkeypatch):
    from webguard.security.dialer import AuthorizedTransport, UnauthorizedDial

    factory = Mock()
    monkeypatch.setattr(socket, "socket", factory)
    with pytest.raises(UnauthorizedDial):
        AuthorizedTransport("https", "origin.test", 8443, "fe80::1%3")
    factory.assert_not_called()


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_protocol_probes_stop_before_next_dial(monkeypatch, stop):
    from webguard.security import dialer

    clock = Mock(return_value=0)
    cancelled = Mock(return_value=False)
    monkeypatch.setattr(dialer, "monotonic", clock)
    transport = authorized(deadline=3, cancelled=cancelled)
    tcp = MagicMock()
    tcp.__enter__.return_value = tcp
    factory = Mock(return_value=tcp)
    monkeypatch.setattr(socket, "socket", factory)
    context = MagicMock(
        minimum_version=ssl.TLSVersion.TLSv1_2,
        maximum_version=ssl.TLSVersion.MAXIMUM_SUPPORTED,
        options=0,
    )
    peer = context.wrap_socket.return_value
    peer.__enter__.return_value = peer

    def handshake():
        if stop == "cancel":
            cancelled.return_value = True
        else:
            clock.return_value = 3

    peer.do_handshake.side_effect = handshake
    monkeypatch.setattr(tls, "_create_verified_client_context", lambda: context)
    expected = KeyboardInterrupt if stop == "cancel" else TimeoutError
    with pytest.raises(expected):
        tls.audit_tls_protocols("origin.test", 8443, transport=transport)
    factory.assert_called_once()
    tcp.settimeout.assert_called_with(3)
    context.wrap_socket.assert_called_once_with(
        tcp, server_hostname="origin.test", do_handshake_on_connect=False
    )
    tcp.__exit__.assert_called_once()


def test_authorized_https_preserves_host_and_never_follows(monkeypatch):
    import io

    stream = io.BytesIO(
        b"HTTP/1.1 302 Found\r\nLocation: https://other.test/\r\nContent-Length: 0\r\n\r\n"
    )
    tcp = Mock()
    factory = Mock(return_value=tcp)
    monkeypatch.setattr(socket, "socket", factory)
    resolver = Mock()
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    context = Mock()
    peer = context.wrap_socket.return_value
    peer.makefile.return_value = stream
    monkeypatch.setattr(https, "_create_verified_client_context", lambda: context)
    result = https.audit_http_redirect(
        "origin.test", 8443, source_scheme="https", transport=authorized()
    )
    assert result["redirect"]["destination"]["verification"] == "not_attempted"
    context.wrap_socket.assert_called_once_with(tcp, server_hostname="origin.test")
    assert b"Host: origin.test:8443\r\n" in peer.sendall.call_args.args[0]
    factory.assert_called_once()
    resolver.assert_not_called()


def test_cancelled_transport_does_not_create_socket(monkeypatch):
    factory = Mock()
    monkeypatch.setattr(socket, "socket", factory)
    with pytest.raises(KeyboardInterrupt):
        authorized(cancelled=lambda: True).connect("https", "origin.test", 8443, 5)
    factory.assert_not_called()


def test_authorized_tls_closes_both_peers_after_handshake_failure(monkeypatch):
    tcp = MagicMock()
    tcp.__enter__.return_value = tcp
    peer = MagicMock()
    peer.__enter__.return_value = peer
    peer.do_handshake.side_effect = ssl.SSLError("synthetic handshake failure")
    context = Mock()
    context.wrap_socket.return_value = peer
    monkeypatch.setattr(tls, "_create_verified_client_context", lambda: context)
    factory = Mock(return_value=tcp)
    monkeypatch.setattr(socket, "socket", factory)
    result = tls.audit_tls_connectivity("origin.test", 8443, transport=authorized())
    assert result["status"] == "tls_handshake_error"
    factory.assert_called_once()
    tcp.__exit__.assert_called_once()
    peer.__exit__.assert_called_once()


def test_cli_fetch_dials_approved_peer_and_audits_valid_response(monkeypatch, tmp_path):
    import io

    from webguard.security.fetcher import fetch

    peer = Mock()
    peer.makefile.return_value = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    head = Mock()
    head.makefile.return_value = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    factory = Mock(side_effect=[peer, head])
    resolver = Mock()
    monkeypatch.setattr(socket, "socket", factory)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    monkeypatch.chdir(tmp_path)
    assert cli.run_audit(TARGET) == 0
    assert len(list((tmp_path / "reports").iterdir())) == 2
    peer.connect.assert_called_once_with(("127.0.0.1", 8000))
    resolver.assert_not_called()
    assert b"Host: 127.0.0.1:8000\r\n" in peer.sendall.call_args.args[0]
    peer.close.assert_called_once()

    with pytest.raises(PermissionError):
        fetch("http://127.0.0.1:8001")
    assert factory.call_count == 2
    head.connect.assert_called_once_with(("127.0.0.1", 8000))


def test_authorized_http_redirect_refuses_destination(monkeypatch):
    import io

    from webguard.security.fetcher import fetch

    peer = Mock()
    peer.makefile.return_value = io.BytesIO(
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8001/\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    factory = Mock(return_value=peer)
    monkeypatch.setattr(socket, "socket", factory)
    with pytest.raises(PermissionError, match="Redirects are not followed"):
        fetch(TARGET)
    peer.connect.assert_called_once_with(("127.0.0.1", 8000))
    factory.assert_called_once()
    peer.close.assert_called_once()


def test_authorized_ipv6_https_uses_bracketed_host(monkeypatch):
    import io

    from webguard.security.dialer import AuthorizedTransport

    transport = AuthorizedTransport("https", "::1", 8443, "::1")
    tcp = Mock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=tcp))
    context = Mock()
    peer = context.wrap_socket.return_value
    peer.makefile.return_value = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    monkeypatch.setattr(https, "_create_verified_client_context", lambda: context)

    result = https.audit_https_availability("::1", 8443, transport=transport)

    assert result["outcome"] == "available"
    tcp.connect.assert_called_once_with(("::1", 8443, 0, 0))
    context.wrap_socket.assert_called_once_with(tcp, server_hostname="::1")
    assert b"Host: [::1]:8443\r\n" in peer.sendall.call_args.args[0]


def test_prompt_eof_remains_denial(monkeypatch):
    monkeypatch.setattr("builtins.input", Mock(side_effect=EOFError))
    audit = Mock()
    monkeypatch.setattr(cli, "run_audit", audit)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", TARGET])
    assert cli.main() == 1
    audit.assert_not_called()


def test_fetch_cancellation_after_dial_prevents_request(monkeypatch):
    from webguard.security.dialer import AuthorizedTransport
    from webguard.security.fetcher import fetch

    cancelled = Mock(return_value=False)
    transport = AuthorizedTransport(
        "http", "127.0.0.1", 8000, "127.0.0.1", cancelled=cancelled
    )
    peer = Mock()

    def cancel(*args):
        cancelled.return_value = True

    peer.connect.side_effect = cancel
    monkeypatch.setattr(socket, "socket", Mock(return_value=peer))
    with pytest.raises(KeyboardInterrupt):
        fetch(TARGET, transport=transport)
    peer.connect.assert_called_once_with(("127.0.0.1", 8000))
    peer.sendall.assert_not_called()
    peer.close.assert_called_once()
