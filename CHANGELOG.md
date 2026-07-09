# Changelog

All notable changes to claude-guard are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); this project uses calendar-based
versioning (`YYYY.M.BUILD`).

## 2026.7.0

Security-hardening release: closes 8 command-guard evasions found and empirically
verified in a full re-analysis, fixes a fail-open path, and cleans up the code,
tests, and docs. Test suite grew from 278 to 312.

### Security
- Command substitution inside a safe wrapper's double-quoted argument is no
  longer treated as inert data. `echo "$(rm -rf ~)"` (also `tee`, `printf`,
  backticks) previously ran silently; the inner command now reaches the guard
  and requires confirmation. (SEC-1)
- `#` inside `${#var}` is no longer mistaken for a comment, so a dangerous
  statement after it is caught — e.g. `echo ${#PATH} && rm -rf /`. (SEC-2)
- Pipe-to-shell is caught behind a temporary env-var prefix — `curl … | FOO=1 bash`. (SEC-3)
- The inline-interpreter bridge tolerates flags before `-c`/`-e` and now covers
  `php -r` — e.g. `python3 -I -c …`, `ruby -w -e …`. (SEC-4)
- Newlines are treated as statement separators, so an allowlisted line can no
  longer shield a dangerous one on the next line. (SEC-5)
- Broader disk-destruction coverage: `mkfs -t`, bare `mkfs /dev/…`, `wipefs`,
  `blkdiscard`, and `sgdisk --zap-all`. (SEC-6, SEC-7)
- `rm -rf` on a top-level system directory (`/usr`, `/etc`, `/var`, …) is now a
  hard deny instead of a confirm. (SEC-8)
- The guard no longer fails open on Python 3.9 — PEP 604 annotations are deferred
  so the hook imports cleanly instead of crashing and letting commands through
  unguarded. (Q-4)

### Docs
- Corrected the status command to `/claude-guard:status` (the documented
  `/guard:status` returned "command not found").
- Fixed the Explain Mode example to match real output, and corrected the Tier 2
  description: it prompts for confirmation and does not auto-substitute.

### Other
- De-duplicated the recursive-`rm` flag grammar into shared constants so the deny
  rules and the temp-dir allowlist can no longer drift; removed dead code; and
  trimmed redundant regex alternatives. (Q-8, Q-9, Q-10)
- Extracted a shared test harness and added direct unit tests for the parsing
  functions where the two critical bugs lived. (Q-6, Q-7)
- Packaging: removed a duplicate version field in the skill; added
  `.pytest_cache/` and `.omc/` to `.gitignore`. (Q-11)

**Full Changelog**: https://github.com/hex/claude-guard/compare/v2026.6.0...v2026.7.0

## 2026.6.0

Security release closing allowlist short-circuit and coverage gaps; Tier 1 now
matches the whole command (allowlist-immune) and Tier 2 is evaluated per
statement segment.
