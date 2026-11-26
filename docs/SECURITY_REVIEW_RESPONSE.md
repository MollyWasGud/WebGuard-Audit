# Response to the Module 1 Security and Integration Review

Original review: `feature/http-auditor` (PR #1). All 11 original tests passed in that review.

| ID | Severity | Status | What changed | Regression tests |
|----|----------|--------|--------------|------------------|
| M1-01 | High | Fixed | `demo/loopback_fetch.py` now uses `http.client` (no proxy discovery), refuses redirects, accepts only plain `http` to a loopback IP literal (no hostnames, no URL credentials), and bounds the body size. | `tests/test_demo_fetch.py` (10 refused URLs, proxy env ignored, redirect target never contacted, body bounded) |
| M1-02 | Medium | Fixed | Cookie names are validated as RFC 6265 tokens; malformed cookies give one generic finding with no name or value. All evidence passes `clean()` (printable ASCII, max 60 chars). Disclosure evidence keeps allowlisted product identifiers without version strings. Private-IP evidence uses a fixed label or a canonical allowlisted header name. `ResponseData.headers` and `.body` are hidden from `repr()`. | `test_malformed_cookie_names_never_reach_findings`, `test_cookie_name_and_evidence_are_bounded`, `test_disclosure_headers_are_sanitised`, `test_raw_headers_and_body_are_not_in_repr` |
| M1-03 | Medium | Fixed | HSTS max-age missing / 0 / short; X-Frame-Options accepts only a single DENY or SAMEORIGIN; frame-ancestors is read as a real CSP directive (no substring match); SameSite is matched by exact attribute name, invalid values flagged, `None` without `Secure` flagged; cookie prefix rules added. | `test_hsts_*`, `test_invalid_x_frame_options_values`, `test_frame_ancestors_must_be_a_real_directive`, `test_samesite_*`, `test_cookie_prefix_rules` |
| M1-04 | Medium | Fixed | New CSP parser (first duplicate directive wins), several policies (separate headers or comma-separated), a weakness counts only if every restricting policy has it, nonce/hash/strict-dynamic neutralise `'unsafe-inline'`, exact wildcard detection, script and style judged separately, report-only is not enforced. | `test_duplicate_directive_first_wins`, `test_nonce_*`, `test_multiple_policies_*`, `test_wildcard_detection_is_exact`, `test_script_and_style_*`, `test_policy_without_script_restriction_and_report_only` |
| M1-05 | Low | Fixed | CORS `*` is LOW with accurate wording; `*` + credentials and `null` origin are MEDIUM; Referrer-Policy values validated (last valid value wins) and weak values flagged; technology headers flagged even without a version, bare `Server: nginx` is not. | `test_cors_*`, `test_referrer_policy_validation`, `test_disclosure_heuristics` |

## Original review results
`python -m pytest -q` -> **43 passed** (11 original + 32 new). The 32 new tests were also run against the previous version: 24 of them fail there, so they catch the reported defects. That review was confined to local fixtures and loopback.

## Not changed (contract kept)
`Finding` and `ResponseData` are unchanged apart from hiding raw headers/body in `repr()`.
Target-qualified deduplication, severity policy and separating "audit incomplete" from vulnerabilities belong to the shared integration layer (Members 2, 3 and 4).

---

# Follow-up review (commit 2ded10a)

| ID | Status | What changed | Tests (`tests/test_followup_review.py`) |
|----|--------|--------------|------------------------------------------|
| M1-02 | Fixed | Technology evidence retains only allowlisted product identifiers. Numeric versions and unlisted header names are omitted. `repr(ResponseData)` shows only `scheme://host:port` (no path, query token, user:password or fragment). | `test_disclosure_evidence_is_allowlisted`, `test_repr_does_not_expose_url_tokens` |
| M1-03 | Fixed | HSTS is validated by directive syntax: a repeated directive (for example two `max-age`), bad syntax, unbalanced or repeated quotation marks, non-ASCII digits, or a value over the local 12-digit limit is classified as `HDR:hsts-invalid`. No `ValueError` can escape. | `test_malformed_hsts_is_invalid_and_never_raises` (12 cases), `test_valid_hsts_forms_are_accepted`, `test_audit_survives_garbage_headers` |
| M1-01 | Fixed | An explicit port 0 is refused instead of becoming port 80. Loopback confinement, proxy isolation and redirect rejection are unchanged. | `test_port_zero_is_refused_not_defaulted_to_80`, `test_default_port_is_still_80_and_loopback_rules_stay` |
| M1-04 | Fixed | `'strict-dynamic'` only affects scripts, never style findings. JavaScript string evaluation uses script-src with default-src fallback. Script source wildcards are checked for elements, and inline findings identify the affected context. CSP3 inline fallback chains are used: `script-src-elem` / `script-src-attr` (and the style equivalents) fall back to `script-src`, then `default-src`. | `test_strict_dynamic_does_not_suppress_style_findings`, `test_script_src_elem_*`, `test_script_elem_and_attr_directives_are_analysed` |
| M1-05 | Fixed | All `Referrer-Policy` header fields are combined; the last valid token wins. The downgrade policy warning distinguishes full referrer exposure on same-security-level requests and upgrades from omission on HTTPS-to-HTTP downgrades. Private-IP findings require a real RFC 1918 address (checked with `ipaddress`), so `999.1.1.1`, `010.0.0.1` and `10.0.0.1.2` give no finding. | `test_multiple_referrer_policy_header_fields`, `test_not_a_real_private_ip_gives_no_finding`, `test_real_private_ip_gives_finding_*` |

Results: `python -m pytest -q` -> **79 passed** (43 existing, all preserved, plus 36 new). 19 of the new test cases fail on the previous version.
Real-loopback cases (fetcher tests and the demo server test) pass. Standalone demo: weak server 14 findings, hardened server 0.

## Integration follow-up

Step 43A verified M1-02 through M1-05 with 20 focused regressions and passed
95 tests in the offline Member 1 partition. M1-01 remained resolved. The
integrated loopback HTTP demo returned GET 200 and HEAD 501, produced 14
findings, and left TLS policy `NOT_CHECKED`. The controlled 302 recorded its
first hop without contacting the destination. The final guarded partitions
passed 900 unique tests.
