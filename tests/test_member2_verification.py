import os
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest

REQUIRED_LOOPBACK_NODEIDS = (
    "tests/test_tls.py::test_local_tls_integration[trusted-matching-hostname]",
    "tests/test_tls.py::test_local_tls_integration[untrusted-ca]",
    "tests/test_tls.py::test_local_tls_integration[trusted-mismatched-hostname]",
    "tests/test_tls.py::test_local_certificate_audit[trusted]",
    "tests/test_tls.py::test_local_certificate_audit[near-expiry]",
    "tests/test_tls.py::test_local_certificate_audit[expired]",
    "tests/test_tls.py::test_local_certificate_audit[untrusted]",
    "tests/test_tls.py::test_local_certificate_audit[mismatch]",
    "tests/test_tls.py::test_local_certificate_rejects_dns_hostname_mismatch",
    "tests/test_tls.py::test_local_tls_protocol_integration[tls12-only]",
    "tests/test_tls.py::test_local_tls_protocol_integration[tls13-only]",
    "tests/test_tls.py::test_local_tls_protocol_integration[both-versions]",
    "tests/test_tls.py::test_local_tls_protocol_integration[tcp-close-before-tls]",
    "tests/test_tls.py::test_local_tls_protocol_integration[untrusted-ca]",
    "tests/test_tls.py::test_local_tls_protocol_integration[trusted-ip-mismatch]",
    "tests/test_tls.py::test_keylog_red_loopback_protocols_preserve_version_restriction[local_tls_server0]",
    "tests/test_https.py::test_local_https_integration_response[ok]",
    "tests/test_https.py::test_local_https_integration_response[method-not-allowed]",
    "tests/test_https.py::test_local_https_integration_response[service-unavailable]",
    "tests/test_https.py::test_local_https_integration_response[malformed-status]",
    "tests/test_https.py::test_local_https_integration_response[truncated-head]",
    "tests/test_https.py::test_local_https_integration_response[control-character]",
    "tests/test_https.py::test_local_https_integration_response[continue-then-ok]",
    "tests/test_https.py::test_local_https_integration_response[unsupported-version]",
    "tests/test_https.py::test_local_https_integration_response[stalled]",
    "tests/test_https.py::test_local_https_integration_rejects_certificate_before_http[untrusted-ca]",
    "tests/test_https.py::test_local_https_integration_rejects_certificate_before_http[trusted-identity-mismatch]",
    "tests/test_https.py::test_local_https_integration_leaves_redirect_destination_uncontacted",
    "tests/test_https.py::test_local_redirect_integration_keeps_destination_uncontacted[upgrade]",
    "tests/test_https.py::test_local_redirect_integration_keeps_destination_uncontacted[downgrade]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[plaintext-no-upgrade]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[relative-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[duplicate-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[credential-bearing-location]",
    "tests/test_https.py::test_local_redirect_integration_classifies_plaintext_response[ambiguous-ipv4-location]",
    "tests/test_https.py::test_local_redirect_integration_skips_assessment_on_tls_verification_failure[untrusted-ca]",
    "tests/test_https.py::test_local_redirect_integration_skips_assessment_on_tls_verification_failure[trusted-identity-mismatch]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[trusted]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[untrusted]",
    "tests/test_https.py::test_keylog_red_loopback_https_preserves_verification[mismatch]",
)


def test_member2_verification_requires_the_windows_loopback_inventory():
    runner = import_module("verify_member2")

    assert len(runner.REQUIRED_LOOPBACK_NODEIDS) == len(REQUIRED_LOOPBACK_NODEIDS)
    assert set(runner.REQUIRED_LOOPBACK_NODEIDS) == set(REQUIRED_LOOPBACK_NODEIDS)


@pytest.mark.parametrize(
    ("case", "pytest_exit", "verifies"),
    [
        ("all-pass", 0, True),
        ("missing-collected-case", 0, False),
        ("replacement-keeps-count", 0, False),
        ("missing-execution", 0, False),
        ("skipped", 0, False),
        ("call-failure", 0, False),
        ("setup-failure", 0, False),
        ("teardown-failure", 0, False),
        ("collection-failure", 2, False),
        ("pytest-usage-error", 4, False),
    ],
)
def test_member2_verification_checks_required_case_results(
    monkeypatch, case, pytest_exit, verifies
):
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)
    monkeypatch.delenv("PYTEST_PLUGINS", raising=False)
    runner = import_module("verify_member2")
    required = REQUIRED_LOOPBACK_NODEIDS[0]
    collected = list(REQUIRED_LOOPBACK_NODEIDS)
    if case in {"missing-collected-case", "replacement-keeps-count"}:
        collected.remove(required)
    if case == "replacement-keeps-count":
        collected.append("tests/test_tls.py::test_unrelated_case")
        assert len(collected) == len(REQUIRED_LOOPBACK_NODEIDS)
    if case == "collection-failure":
        collected.clear()

    def run_pytest(args, *, plugins):
        session = SimpleNamespace(
            items=[SimpleNamespace(nodeid=nodeid) for nodeid in collected],
        )
        for plugin in plugins:
            plugin.pytest_collection_finish(session)
        for nodeid in collected:
            if nodeid == required and case == "missing-execution":
                continue
            for phase in ("setup", "call", "teardown"):
                if (
                    nodeid == required
                    and phase == "call"
                    and case
                    in {
                        "skipped",
                        "setup-failure",
                    }
                ):
                    continue
                outcome = "passed"
                if nodeid == required and phase == "setup" and case == "skipped":
                    outcome = "skipped"
                if nodeid == required and case == f"{phase}-failure":
                    outcome = "failed"
                report = pytest.TestReport(
                    nodeid=nodeid,
                    location=(nodeid.split("::")[0], 0, ""),
                    keywords={},
                    outcome=outcome,
                    longrepr=None,
                    when=phase,
                    sections=[],
                )
                for plugin in plugins:
                    plugin.pytest_runtest_logreport(report)
        return pytest.ExitCode(pytest_exit)

    monkeypatch.setattr(pytest, "main", run_pytest)

    status = runner.main()

    if pytest_exit:
        assert status == pytest_exit
    else:
        assert (status == 0) is verifies


_RUN_PYTEST_POLICY_PROBE = """
import os
import sys
from pathlib import Path

import pytest

network_attempts = []

def block_network(event, args):
    if event.startswith("socket."):
        network_attempts.append(event)
        raise AssertionError("The synthetic verification test must stay offline")

sys.addaudithook(block_network)
options = os.environ.get("PYTEST_ADDOPTS")
assert options == (sys.argv[3] if len(sys.argv) == 4 else None)
plugins = os.environ.get("PYTEST_PLUGINS")
pytest_main = pytest.main

if sys.argv[2] == "ordinary":
    status = pytest_main([
        "--disable-plugin-autoload", "-p", "no:cacheprovider", "-q", "test_required.py"
    ])
else:
    sys.path.insert(0, sys.argv[1])
    import verify_member2

    verify_member2.REQUIRED_LOOPBACK_NODEIDS = ("test_required.py::test_required",)

    def use_synthetic_suite(args, *, plugins):
        Path("pytest-invoked").touch()
        profile = [arg for arg in args if not arg.startswith("tests/")]
        return pytest_main([*profile, "test_required.py"], plugins=plugins)

    pytest.main = use_synthetic_suite
    status = verify_member2.main()

assert os.environ.get("PYTEST_ADDOPTS") == options
assert os.environ.get("PYTEST_PLUGINS") == plugins
assert not network_attempts
print("Child environment unchanged and zero socket operations")
raise SystemExit(status)
"""


def _run_member2_policy_probe(
    tmp_path, options, *, xfail=False, ordinary=False, plugins=None
):
    required = "from pathlib import Path\n"
    if xfail:
        required += (
            "import pytest\n\n"
            "@pytest.mark.xfail(run=False, reason='synthetic expected failure')\n"
        )
    required += "def test_required():\n    Path('required-ran').touch()\n"
    (tmp_path / "test_required.py").write_text(required, encoding="utf-8")
    (tmp_path / "test_extra.py").write_text(
        "from pathlib import Path\n\n"
        "def test_extra():\n    Path('extra-ran').touch()\n",
        encoding="utf-8",
    )
    caller = os.environ.get("PYTEST_ADDOPTS")
    caller_plugins = os.environ.get("PYTEST_PLUGINS")
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    if options is not None:
        env["PYTEST_ADDOPTS"] = options
    if plugins is not None:
        env["PYTEST_PLUGINS"] = plugins

    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            _RUN_PYTEST_POLICY_PROBE,
            str(Path(__file__).resolve().parent),
            "ordinary" if ordinary else "designated",
            *([] if options is None else [options]),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert os.environ.get("PYTEST_ADDOPTS") == caller
    assert os.environ.get("PYTEST_PLUGINS") == caller_plugins
    assert "Child environment unchanged and zero socket operations" in result.stdout
    return result


@pytest.mark.parametrize(
    ("options", "xfail"),
    [
        pytest.param("--runxfail", True, id="runxfail"),
        pytest.param("test_extra.py", False, id="additional-path"),
        pytest.param(" \t ", False, id="whitespace-is-nonempty"),
    ],
)
def test_member2_inherited_options_rejected_before_pytest(tmp_path, options, xfail):
    result = _run_member2_policy_probe(tmp_path, options, xfail=xfail)
    observed = {
        "exit": result.returncode,
        "pytest_invoked": (tmp_path / "pytest-invoked").exists(),
        "required_executed": (tmp_path / "required-ran").exists(),
        "extra_executed": (tmp_path / "extra-ran").exists(),
    }

    assert observed["exit"] != 0, observed
    assert not any(value for key, value in observed.items() if key != "exit"), observed
    assert result.stderr.strip() == (
        "Designated verification requires PYTEST_ADDOPTS to be unset or empty."
    )
    if options.strip():
        assert options not in result.stdout + result.stderr


@pytest.mark.parametrize("options", [None, ""], ids=["absent", "empty"])
def test_member2_inherited_options_allows_clean_verification(tmp_path, options):
    result = _run_member2_policy_probe(tmp_path, options)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "pytest-invoked").exists()
    assert (tmp_path / "required-ran").exists()
    assert not (tmp_path / "extra-ran").exists()
    assert "1/1 required loopback cases passed" in result.stdout


def test_member2_inherited_options_default_rejects_required_xfail(tmp_path):
    result = _run_member2_policy_probe(tmp_path, None, xfail=True)

    assert result.returncode != 0
    assert (tmp_path / "pytest-invoked").exists()
    assert not (tmp_path / "required-ran").exists()
    assert "0/1 required loopback cases passed" in result.stdout
    assert "setup xfail/xpass" in result.stderr


def test_member2_inherited_options_ordinary_pytest_still_honors_options(tmp_path):
    result = _run_member2_policy_probe(
        tmp_path, "--runxfail test_extra.py", xfail=True, ordinary=True
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "required-ran").exists()
    assert (tmp_path / "extra-ran").exists()


@pytest.fixture
def member2_plugin_marker(tmp_path):
    marker = tmp_path / "plugin-loaded"
    (tmp_path / "member2_plugin_probe.py").write_text(
        "from pathlib import Path\n\nPath('plugin-loaded').touch()\n",
        encoding="utf-8",
    )
    return marker


@pytest.mark.parametrize(
    "plugins",
    [
        pytest.param("member2_plugin_probe", id="explicit-plugin"),
        pytest.param(" \t ", id="whitespace-is-nonempty"),
    ],
)
def test_member2_explicit_plugins_rejected_before_pytest(
    tmp_path, member2_plugin_marker, plugins
):
    result = _run_member2_policy_probe(tmp_path, None, plugins=plugins)
    observed = (
        result.returncode,
        (tmp_path / "pytest-invoked").exists(),
        member2_plugin_marker.exists(),
        (tmp_path / "required-ran").exists(),
    )
    assert observed[0] != 0 and observed[1:] == (False, False, False), observed
    assert result.stderr.strip() == (
        "Designated verification requires PYTEST_PLUGINS to be unset or empty."
    )
    if plugins.strip():
        assert plugins not in result.stdout + result.stderr


@pytest.mark.parametrize("plugins", [None, ""], ids=["absent", "empty"])
def test_member2_explicit_plugins_allows_clean_verification(
    tmp_path, member2_plugin_marker, plugins
):
    result = _run_member2_policy_probe(tmp_path, None, plugins=plugins)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "pytest-invoked").exists()
    assert (tmp_path / "required-ran").exists()
    assert not member2_plugin_marker.exists()
    assert "1/1 required loopback cases passed" in result.stdout


def test_member2_explicit_plugins_ordinary_pytest_still_imports_plugin(
    tmp_path, member2_plugin_marker
):
    result = _run_member2_policy_probe(
        tmp_path, None, ordinary=True, plugins="member2_plugin_probe"
    )

    assert result.returncode == 0, result.stderr
    assert member2_plugin_marker.exists()
    assert (tmp_path / "required-ran").exists()
