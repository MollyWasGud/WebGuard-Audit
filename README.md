# WebGuard-Audit
A Python-based web server and TLS security compliance auditing tool with policy-based evaluation, risk scoring and remediation reporting.


## CLI and Ethical Safeguards

WebGuard Audit includes safety controls to support
authorized and responsible security auditing.

### Features

- Command-line interface using argparse.
- Explicit user authorization confirmation.
- Approved target scope validation.
- Rejection of invalid and out-of-scope URLs.
- Dry-run mode without network requests.
- Keyboard interruption handling (Ctrl+C).
- Automated unit testing using pytest.

### Usage

Display available commands:

```bash
python main.py --help
```

Display the application version:

```bash
python main.py --version
```

Run a dry-run simulation:

```bash
python main.py --target http://127.0.0.1:8000 --dry-run
```

Run the audit entry point:

```bash
python main.py --target http://127.0.0.1:8000
```

### Ethical Usage

Only audit systems that you own or have explicit
permission to test.

The current approved scope is restricted to the
local development target:

- http://127.0.0.1:8000

User confirmation alone does not establish permission.

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | Successful execution |
| 1 | Scope or authorization rejected |
| 2 | Invalid command-line arguments |
| 130 | Execution interrupted by user |

### Automated Testing

Run all unit tests:

```bash
python -m pytest -v
```

Initial testing results:

- Authorization: 5 passed
- Scope validation: 8 passed
- CLI and safety controls: 5 passed
- Total: 18 passed, 0 failed

### Current Limitations

Scanner integration is pending. The current audit
entry point is a placeholder.

Network-level scope enforcement, redirect validation
and cancellation of active network operations must
be verified after scanner integration.
