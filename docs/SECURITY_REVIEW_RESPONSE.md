# Response to the Module 1 Security and Integration Review

Branch: `feature/http-auditor` (PR #1). All 11 original tests are unchanged and still pass.

| ID | Severity | Status | What changed | Regression tests |
|----|----------|--------|--------------|------------------|
| M1-01 | High | Fixed | `demo/loopback_fetch.py` now uses `http.client` (no proxy discovery), refuses redirects, accepts only plain `http` to a loopback IP literal (no hostnames, no URL credentials), and bounds the body size. | `tests/test_demo_fetch.py` (10 refused URLs, proxy env ignored, redirect target never contacted, body bounded) |
| M1-02 | Medium | Fixed | Cookie names are validated as RFC 6265 tokens; malformed cookies give one generic finding with no name or value. All evidence passes `clean()` (printable ASCII, max 60 chars). Disclosure evidence keeps only `product/version`; internal-IP evidence is the header name only. `ResponseData.headers` and `.body` are hidden from `repr()`. | `test_malformed_cookie_names_never_reach_findings`, `test_cookie_name_and_evidence_are_bounded`, `test_disclosure_headers_are_sanitised`, `test_raw_headers_and_body_are_not_in_repr` |
| M1-03 | Medium | Fixed | HSTS max-age missing / 0 / short; X-Frame-Options accepts only a single DENY or SAMEORIGIN; frame-ancestors is read as a real CSP directive (no substring match); SameSite is matched by exact attribute name, invalid values flagged, `None` without `Secure` flagged; cookie prefix rules added. | `test_hsts_*`, `test_invalid_x_frame_options_values`, `test_frame_ancestors_must_be_a_real_directive`, `test_samesite_*`, `test_cookie_prefix_rules` |
| M1-04 | Medium | Fixed | New CSP parser (first duplicate directive wins), several policies (separate headers or comma-separated), a weakness counts only if every restricting policy has it, nonce/hash/strict-dynamic neutralise `'unsafe-inline'`, exact wildcard detection, script and style judged separately, report-only is not enforced. | `test_duplicate_directive_first_wins`, `test_nonce_*`, `test_multiple_policies_*`, `test_wildcard_detection_is_exact`, `test_script_and_style_*`, `test_policy_without_script_restriction_and_report_only` |
| M1-05 | Low | Fixed | CORS `*` is LOW with accurate wording; `*` + credentials and `null` origin are MEDIUM; Referrer-Policy values validated (last valid value wins) and weak values flagged; technology headers flagged even without a version, bare `Server: nginx` is not. | `test_cors_*`, `test_referrer_policy_validation`, `test_disclosure_heuristics` |

## Test results
`python -m pytest -q` -> **43 passed** (11 original + 32 new). The 32 new tests were also run against the previous version: 24 of them fail there, so they catch the reported defects. All tests are offline (loopback only).

## Not changed (contract kept)
`Finding` and `ResponseData` are unchanged apart from hiding raw headers/body in `repr()`.
Target-qualified deduplication, severity policy and separating "audit incomplete" from vulnerabilities belong to the shared integration layer (Members 2, 3 and 4).
