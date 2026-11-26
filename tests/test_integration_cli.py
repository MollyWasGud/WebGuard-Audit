"""End-to-end: CLI -> scope check -> fetch -> Module 1 audit -> risk/compliance -> JSON + HTML report."""

import json
import sys

import pytest

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


def test_http_cli_reports_first_hop_after_content_refusal(
    monkeypatch, tmp_path, capsys
):
    from unittest.mock import Mock

    from test_report_adapter import first_hop

    from webguard.auditors import https, report_adapter
    from webguard.security.fetcher import FetchRefused

    fetch = Mock(side_effect=FetchRefused("synthetic private error"))
    monkeypatch.setattr(cli, "fetch", fetch)
    raw = first_hop("http", "upgrade", "https", 302)
    raw["source"].update(hostname="127.0.0.1", port=8000)
    raw["redirect"]["same_host"] = False
    redirect = Mock(return_value=raw)
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    adapter = Mock(wraps=report_adapter.to_safe_audit_report)
    monkeypatch.setattr(report_adapter, "to_safe_audit_report", adapter)
    monkeypatch.chdir(tmp_path)

    assert cli.run_audit("http://127.0.0.1:8000") == 1

    transport = fetch.call_args.kwargs["transport"]
    redirect.assert_called_once_with(
        "127.0.0.1", 8000, source_scheme="http", transport=transport
    )
    assert transport.peer == "127.0.0.1"
    adapter.assert_called_once_with("http_redirect", raw)
    (path,) = (tmp_path / "reports").glob("*.json")
    report = json.loads(path.read_text(encoding="utf-8"))
    json.dumps(report, allow_nan=False)
    row = next(row for row in report["audit_coverage"] if row.get("redirect_outcome"))
    assert row["redirect_outcome"] == "upgrade"
    assert row["destination_verification"] == "not_attempted"
    output = capsys.readouterr().out
    assert "partial" in output.lower()
    assert "synthetic private error" not in output


def test_https_cli_deduplicates_failures_and_keeps_rejection(monkeypatch, tmp_path):
    from unittest.mock import Mock

    from test_report_adapter import connectivity, protocol_result, unconfirmed_protocol

    from webguard.auditors import https, report_adapter, tls

    raw_failure = connectivity() | {
        "hostname": "127.0.0.1",
        "port": 8443,
        "status": "certificate_verification_failed",
        "failed_stage": "handshake",
        "tls_version": None,
        "cipher_suite": None,
        "verify_code": 62,
    }
    cert = Mock(
        return_value={
            "connectivity": raw_failure,
            "certificate_status": "not_collected",
            "certificate": None,
            "certificate_error": None,
        }
    )
    restricted = unconfirmed_protocol(
        "TLSv1.2", "client_restricted", "client_version_policy", None
    )
    failed = unconfirmed_protocol(
        "TLSv1.3", "inconclusive", "certificate_verification_failed", "handshake"
    ) | {"verify_code": 10}
    protocols = Mock(
        return_value=protocol_result(restricted, failed)
        | {
            "target": {"hostname": "127.0.0.1", "port": 8443},
        }
    )
    # A structurally invalid sibling must not turn into a finding.
    redirect = Mock(return_value={"source": "SYNTHETIC_REJECTED_42C"})
    fetch = Mock(side_effect=AssertionError("HTTPS content fetch was not planned"))
    monkeypatch.setattr(cli, "fetch", fetch)
    monkeypatch.setattr(tls, "audit_tls_certificate", cert)
    monkeypatch.setattr(tls, "audit_tls_protocols", protocols)
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    adapter = Mock(wraps=report_adapter.to_safe_audit_report)
    monkeypatch.setattr(report_adapter, "to_safe_audit_report", adapter)
    monkeypatch.chdir(tmp_path)

    assert cli.run_audit("https://127.0.0.1:8443") == 1

    transport = cert.call_args.kwargs["transport"]
    cert.assert_called_once_with("127.0.0.1", 8443, transport=transport)
    protocols.assert_called_once_with("127.0.0.1", 8443, transport=transport)
    redirect.assert_called_once_with(
        "127.0.0.1", 8443, source_scheme="https", transport=transport
    )
    assert (transport.scheme, transport.peer, transport.port) == (
        "https",
        "127.0.0.1",
        8443,
    )
    assert [call.args[0] for call in adapter.call_args_list] == [
        "tls_certificate",
        "tls_protocols",
        "http_redirect",
    ]
    fetch.assert_not_called()
    (json_path,) = (tmp_path / "reports").glob("*.json")
    (html_path,) = (tmp_path / "reports").glob("*.html")
    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    report = json.loads(json_text)
    json.dumps(report, allow_nan=False)
    assert report["schema_version"] == 1
    assert report["risk_summary"]["total_risk_score"] == 7
    assert report["risk_summary"]["duplicates_removed"] == 1
    assert [f["check_id"] for f in report["findings"]] == [
        "TLS:certificate-verification"
    ]
    assert any(
        row["audit_kind"] == "Rejected TLS input" for row in report["audit_coverage"]
    )
    assert "SYNTHETIC_REJECTED_42C" not in json_text + html_text


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_https_audit_stops_before_next_operation(monkeypatch, tmp_path, stop):
    from unittest.mock import Mock

    from test_report_adapter import certificate

    from webguard.auditors import https, tls
    from webguard.security import dialer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", "https://127.0.0.1:8443"])
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    clock = Mock(return_value=0)
    monkeypatch.setattr(cli, "monotonic", clock, raising=False)
    monkeypatch.setattr(dialer, "monotonic", clock)

    def first(*args, **kwargs):
        if stop == "cancel":
            raise KeyboardInterrupt
        clock.return_value = 1000
        return certificate()

    cert = Mock(side_effect=first)
    monkeypatch.setattr(tls, "audit_tls_certificate", cert)
    protocols = Mock()
    redirect = Mock()
    monkeypatch.setattr(tls, "audit_tls_protocols", protocols)
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    assert cli.main() == (130 if stop == "cancel" else 1)
    cert.assert_called_once()
    protocols.assert_not_called()
    redirect.assert_not_called()
    if stop == "cancel":
        assert not (tmp_path / "reports").exists()
    else:
        (path,) = (tmp_path / "reports").glob("*.json")
        report = json.loads(path.read_text(encoding="utf-8"))
        assert "TLS:expired" in [f["check_id"] for f in report["findings"]]
        assert any(
            "deadline" in row["audit_kind"].lower() for row in report["audit_coverage"]
        )


def test_https_cli_uses_only_pinned_dials_and_preserves_verification(
    monkeypatch, tmp_path
):
    import io
    import socket
    import ssl
    from unittest.mock import MagicMock, Mock

    from test_report_adapter import certificate

    from webguard.auditors import tls

    tls_peers = []
    tcp_peers = []

    def socket_factory(*args):
        tcp = MagicMock()
        tcp.__enter__.return_value = tcp
        tcp_peers.append(tcp)
        return tcp

    def wrap(ctx, tcp, *, server_hostname, do_handshake_on_connect=True):
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert tcp is tcp_peers[-1]
        assert server_hostname == "127.0.0.1"
        peer = MagicMock()
        peer.__enter__.return_value = peer
        peer.version.return_value = (
            "TLSv1.2" if ctx.maximum_version == ssl.TLSVersion.TLSv1_2 else "TLSv1.3"
        )
        peer.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        peer.getpeercert.return_value = b"synthetic-der"
        peer.makefile.return_value = io.BytesIO(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:8000/\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        tls_peers.append(peer)
        return peer

    resolver = Mock(side_effect=AssertionError("unexpected resolver call"))
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    monkeypatch.setattr(socket, "socket", socket_factory)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    monkeypatch.setattr(
        tls, "_certificate_metadata", lambda *_: certificate()["certificate"]
    )
    monkeypatch.setattr(sys, "argv", ["main.py", "--target", "https://127.0.0.1:8443"])
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.chdir(tmp_path)

    assert (
        cli.main() == 1
    )  # Protocol coverage remains partial with legacy probes disabled.
    assert len(tcp_peers) == len(tls_peers) == 4
    resolver.assert_not_called()
    for tcp in tcp_peers:
        tcp.connect.assert_called_once_with(("127.0.0.1", 8443))
    for peer in tls_peers[:-1]:
        peer.sendall.assert_not_called()
    assert b"HEAD / HTTP/1.1\r\n" in tls_peers[-1].sendall.call_args.args[0]
    assert b"Host: 127.0.0.1:8443\r\n" in tls_peers[-1].sendall.call_args.args[0]
    (report_path,) = (tmp_path / "reports").glob("*.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert any(
        row["audit_kind"] == "Audit scope: https://127.0.0.1:8443"
        for row in report["audit_coverage"]
    )
    redirect = next(
        row for row in report["audit_coverage"] if row["audit_kind"] == "http_redirect"
    )
    assert redirect["redirect_outcome"] == "downgrade"
    assert redirect["destination_verification"] == "not_attempted"


def test_http_dry_run_matches_execution_and_reports_escape_html(
    monkeypatch, tmp_path, capsys
):
    from unittest.mock import Mock

    from test_report_adapter import first_hop

    from webguard.auditors import https
    from webguard.core.models import Finding, ResponseData

    target = "http://127.0.0.1:8000"
    raw = first_hop("http", "no_redirect", None, 200)
    raw["source"].update(hostname="127.0.0.1", port=8000)
    fetch = Mock(return_value=ResponseData(target, 200, []))
    redirect = Mock(return_value=raw)
    monkeypatch.setattr(cli, "fetch", fetch)
    monkeypatch.setattr(https, "audit_http_redirect", redirect)
    finding = Finding(
        "TEST:offline", "test", "INFO", "<script>synthetic</script>", "", ""
    )
    monkeypatch.setattr(cli, "audit_http", Mock(return_value=[finding]))
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    monkeypatch.chdir(tmp_path)
    argv = ["main.py", "--target", target]
    monkeypatch.setattr(sys, "argv", [*argv, "--dry-run"])
    assert cli.main() == 0
    dry_output = capsys.readouterr().out
    fetch.assert_not_called()
    redirect.assert_not_called()

    monkeypatch.setattr(sys, "argv", argv)
    assert cli.main() == 0
    terminal = capsys.readouterr().out
    for operation in (
        "HTTP security header analysis",
        "First-hop HTTP redirect assessment",
    ):
        assert operation in dry_output and operation in terminal
    fetch.assert_called_once()
    redirect.assert_called_once()
    assert fetch.call_args.kwargs["transport"] is redirect.call_args.kwargs["transport"]
    (html_path,) = (tmp_path / "reports").glob("*.html")
    html = html_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;synthetic&lt;/script&gt;" in html
    assert "<script>synthetic</script>" not in html
