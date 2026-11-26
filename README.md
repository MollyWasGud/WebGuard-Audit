# WebGuard Audit

WebGuard Audit is a Python tool for a university ethical hacking project. It
audits one approved web origin at a time, scores observed findings against
project policies, and writes local reports with prioritised remediation.

| Module | Responsibility |
| --- | --- |
| [1. HTTP Security Auditor](docs/MODULE1_WRITEUP.md) | Analyses response headers, cookies, CSP, and disclosure evidence. |
| [2. TLS and HTTPS Security Auditor](docs/MODULE2_WRITEUP.md) | Checks verified connectivity, certificates, protocol versions, HTTPS availability, and first-hop redirects. |
| [3. Compliance and Reporting](docs/MODULE3_WRITEUP.md) | Adapts transport results, maps and deduplicates findings, tracks coverage, scores risk, and generates reports. |
| 4. CLI and Ethical Safeguards | Validates the origin, prompts for authorisation, binds network operations to the approved peer, and runs the audit plan. |

## Setup

From the repository root in Windows PowerShell, create an environment for a new
checkout and install the [declared dependencies](requirements.txt). The verified
Windows profile used Python 3.14.5.

```powershell
python -m venv .venv
$Python = Resolve-Path .\.venv\Scripts\python.exe
& $Python -m pip install -r requirements.txt
```

The manifest lists `requests`, `rich`, `jinja2`, `cryptography`, `flask`,
`pytest`, and `ruff`. The proposed `cryptography>=42.0.0` minimum and adoption
of reporting schema version 1 as a team contract still require team agreement.

## CLI usage and scope

```powershell
& $Python -B main.py --help
& $Python -B main.py --version
& $Python -B main.py --target http://127.0.0.1:8000 --dry-run
& $Python -B main.py --target http://127.0.0.1:8000
& $Python -B main.py --target https://127.0.0.1:8443
```

Only test services you own or have explicit permission to audit. The CLI
allowlist contains exactly `http://127.0.0.1:8000` and
`https://127.0.0.1:8443`. Each invocation needs its own confirmation, including
dry-run. HTTP authorisation does not carry over to HTTPS. Other origins and
external websites are outside CLI scope. Targets may have a trailing slash.
Other paths, credentials, queries, and fragments are rejected.

| Origin | Operations |
| --- | --- |
| HTTP on port 8000 | Bounded `GET /` for HTTP security analysis and source-only `HEAD /` for first-hop redirect assessment. TLS certificate and protocol security are unassessed. |
| HTTPS on port 8443 | Verified TLS connectivity and certificate collection on one connection, exact TLS 1.2 and 1.3 probes, and one verified `HEAD /` for HTTPS response availability and first-hop redirect assessment. HTTPS content-header auditing is outside the current fetch contract. |

Dry-run prints the selected plan without opening network connections or
writing reports. The live CLI binds each operation to the approved scheme, host,
port, and numeric peer. It connects directly without DNS fallback or proxy
discovery. A redirect destination remains uncontacted and unverified. Legacy
TLS probing is disabled by default and has no CLI flag.

The live CLI uses a shared 20-second budget and applies remaining time at
transport checkpoints. Ctrl+C cancels when Python delivers the interrupt.
Cooperative checks cannot guarantee immediate interruption of Windows I/O
already blocked in the operating system.

## Reports and exit codes

Live audits print the paths to local JSON and HTML files in `reports/`, relative
to the working directory. Incomplete observations can still yield useful
findings. Read coverage and policy status alongside the risk score. A low
score alone does not establish compliance, and a completed first-hop check
does not verify its destination.

| Code | Meaning |
| --- | --- |
| 0 | Confirmed dry-run, or live audit with complete recorded coverage. |
| 1 | Invalid or out-of-scope target, denied authorisation, or a completed run that wrote partial reports. |
| 2 | Invalid command-line arguments. |
| 130 | Ctrl+C reached the CLI interrupt handler. |

The default HTTPS plan leaves legacy versions unprobed. Current coverage rules
therefore mark the protocol assessment incomplete even if both modern probes
succeed, and the CLI can exit 1 after saving useful reports.

## Local demonstration

Start the deliberately weak HTTP fixture in one terminal, run the HTTP CLI
command above in another, then stop the fixture with Ctrl+C.

```powershell
& $Python -B -m demo.serve
```

The HTTP fixture handles GET. Its inherited HEAD response is 501, which
provides an observed non-redirect response. Use a controlled HEAD-capable
fixture for the separate redirect confinement scenario.

The standalone Member 2 demo starts its own dynamic loopback listeners and
takes no target arguments. A trusted **integrated** HTTPS demo instead needs a
listener on `127.0.0.1:8443`, a leaf certificate with IP SAN `127.0.0.1`, and a
temporary CA loaded only in the test context. The ordinary CLI has no CA flag
and keeps default certificate trust and hostname verification. The trusted
integrated demo verified TLS 1.2 and 1.3 with test-scoped trust. It reported
partial coverage because legacy versions remained unprobed. The default
trust run rejected the fixture certificate and reported one deduplicated
finding. [Standalone demo and trust setup](docs/MODULE2_WRITEUP.md#standalone-loopback-demo)

## Verification

```powershell
& $Python -B tests\verify_member2.py
& $Python -B -m pytest --disable-plugin-autoload -p no:cacheprovider -o addopts= -q tests/test_scope.py tests/test_authorization.py tests/test_cli.py tests/test_integration_cli.py
& $Python -B -m ruff check --no-cache demo webguard tests main.py
& $Python -B -m ruff format --check --no-cache demo webguard tests main.py
```

The Windows Member 2 runner checks 40 exact required real-loopback test
identities. Use the corrected verification launcher for the final integrated
run so the parent and audited subprocesses are confined. Steps 44 and 44.1
recorded 900 unique passing tests across two successful guarded partitions:
680 Member 2 tests, including all 40 required loopback cases, and 220 remaining
integration tests. Both partitions exited 0. The original remaining-partition
launcher failure was retained as evidence. The corrected replay used a local
non-listening port reservation and passed all 220 cases.

The approved HTTP demo returned GET 200 and HEAD 501, with 14 findings and
TLS policy `NOT_CHECKED`. The controlled 302 produced first-hop evidence
without contacting its destination. The HTTP and HTTPS CLI demonstrations
verified mandatory safe adaptation and authorization of the actual dialed peer. [Verification notes](docs/MODULE2_WRITEUP.md#verification)

## Historical SonarQube review

The main-branch snapshot at `cdae30e3` reported Security B with five Low findings,
Reliability A with zero open findings, and Maintainability A with 79 issues.
The Quality Gate was **Not computed**. The two configuration warnings concerned
`sonar.python.version` and `sonar.tests`. The five Low findings concern
intentional synthetic demo data, controlled loopback HTTP, and RFC 1918
private-network constants. These results belong to the historical snapshot.
