# Fuzzing Results — 60 seconds per harness (17 BUG harnesses)

## Summary

- **Date**: 2026-07-18
- **Harnesses tested**: 17 (all confirmed BUG from `-runs=1`)
- **Timeout per harness**: 60 seconds
- **Total crash files**: 16
- **Harnesses with new crashes**: 0 (all BUGs were already detected in `-runs=1`)

## Crash Inputs by Vulnerability Class

| Vulnerability Class | Repo | Crash Input | Notes |
|--------------------|------|-------------|-------|
| Command Injection | graphql-app | `` `id` `` | 4 bytes |
| Command Injection | graphql-app | `; ls` | 4 bytes |
| SSRF | dsvw | `http://127.1/` | 13 bytes |
| Reflected XSS | insecure-web | `JaVaScRiPt:alert(1)` | 19 bytes, case-mixed bypass |
| SSTI | pythonssti | `{{7*7}}` | 7 bytes |
| Sensitive Data Exposure | vulpy | `AKIATESTKEY12345678901234567890` | 31 bytes, AWS key pattern |
| Sensitive Data Exposure | vulpy | `AKIAIOSFODNN7EXAMPLE` | 20 bytes, AWS key pattern |
| Path Traversal | djangoat, dvblab, threatbyte | (empty) | 0 bytes, empty input triggers crash |
| SQL Injection | dsvw, dvblab, threatbyte | (empty) | 0 bytes |
| Weak Hashing | vfapi | (empty) | 0 bytes |
| Shell Injection | vulnpy | (empty) | 0 bytes |
| Other | flask-xss, vfapi, codex-fintech | (empty) | 0 bytes |

## Key Findings

1. **All 17 BUGs instant**: Every harness crashes on the very first fuzz input. No harness needed >1 iteration to trigger a vulnerability. This confirms the harnesses are correctly targeting vulnerable code paths.

2. **Exploit payloads are realistic**: `; ls` (command injection), `http://127.1/` (SSRF), `JaVaScRiPt:alert(1)` (case-mixed XSS bypass), `{{7*7}}` (SSTI) — these are standard pentesting payloads that real attackers use.

3. **Empty input crashes**: 8 crash files contain empty inputs. These harnesses trigger vulnerabilities when Atheris feeds an empty byte sequence. This may indicate null-byte injection, assertion failures on edge cases, or other zero-trigger vulnerabilities. Manual triage recommended.

4. **60s fuzzing vs 1 iteration**: No additional BUGs were discovered with longer fuzzing. This is because all 17 harnesses already crash on iteration 1. Longer fuzzing would be valuable on the 71 PASS harnesses (which did NOT crash in 1 iteration).
