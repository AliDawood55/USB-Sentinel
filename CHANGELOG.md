# Changelog

USB Sentinel has had no prior release — every phase below shipped
directly to this repository's working tree, verified and documented as
it went (see `PROGRESS.md` for the full blow-by-blow, `ARCHITECTURE.md`
for the reasoning behind each decision). This file summarizes that
history as the single v1.0.0 release it now becomes with the project's
first git commit and tag.

Dates reflect when each phase's work was actually done, not calendar
spacing.

## [1.0.0] — 2026-09-12

### Phase 1 — Project foundation

Repository scaffolded: CMake + Ninja build (`x64-debug`/`x64-release`
presets), C17 under `/W4 /permissive-` with an opt-in `/WX`, core types
and status codes, a leveled logger, a generated version header, CLI
dispatch (`version`/`help`), and the in-repo test harness every test
executable since has used.

### Phase 2 — USB device detection

Volume enumeration (`FindFirstVolumeW`/`FindNextVolumeW`), authoritative
USB identification via `IOCTL_STORAGE_QUERY_PROPERTY` (never
`GetDriveType`), device identity via CfgMgr32 (VID/PID/serial, immune to
drive-letter reassignment), and capability-based privilege probing —
attempt the handle, never branch on admin-membership checks. The `devices`
CLI command. WMI was evaluated and rejected (`ARCHITECTURE.md` §7.1): COM
from C17, a live-service dependency an offline forensic tool shouldn't
have, and a query pattern EDR products already flag.

### Phase 3 — Scanning, detection, storage, reporting

End-to-end `scan`: a hand-rolled JSON writer/reader (no external
dependency), atomic (temp+rename) report storage under
`%LOCALAPPDATA%\USBSentinel`, a self-healing non-authoritative
`index.json` cache, single-threaded depth-first traversal with
reparse-point and depth guards, the first detector (`autorun.inf`), and a
`schema_version: 1` JSON report with every check explicitly
`ran`/`skipped`/`failed`. Ctrl+C cancellation. The per-file digest was a
placeholder (FNV-1a) — deliberately flagged, not silently load-bearing —
pending real SHA-256.

### Phase 4 — Detection hardening

FNV-1a replaced by verified SHA-256 (Windows CNG, checked against NIST
test vectors). Two new detectors: `suspicious_filename` (double
extensions, bidi-override, space-padding, hidden executables) and
`lnk_inspection` — a defensive MS-SHLLINK parser that never follows or
executes a target. Findings gained a `severity`. The general traversal
became metadata-only (no file is opened just to compute an unconsumed
hash), closing a resource-exhaustion path. A malformed-input battery
against the `.lnk` parser caught a real defect: a declared-but
out-of-bounds field was silently ignored rather than rejected, producing
a falsely clean result on hostile input.

### Phase 5 — Walk consolidation and a hash-matching detector

The detector interface split into `run` (whole-check) and `on_file`
(per-file); three independent per-scan walks became one shared walk in
`scanner.c`. A fourth detector, `hash_match_example`, gave the SHA-256
primitive a real consumer — one hardcoded EICAR entry, with a structural
disclaimer that survives in every report it appears in.

### Phase 6 — Real signature sourcing (hash-list)

`hash_match_example` can load real SHA-256 signatures from a local,
user-supplied file (`--signatures <path>`, or a default location), with a
size-bucketed lookup and a disclaimer that honestly tracks whether a real
file was loaded. Hash-list only — no ClamAV `.ndb`/`.ldb` byte-pattern
parsing (out of scope; see `TASKS.md`'s "Post-v1.0" section), no network
access, no bundled database.

### Phase 7 — Hash-match size-prefilter fix and CSV export

Fixed a real Phase 6 regression: the size-bucketed *lookup* was never
gated behind a size check on the *hashing* that fed it, reintroducing
whole-volume hashing once a real signature file was loaded. CSV export,
generated automatically alongside JSON, with RFC 4180 quoting and a
formula-injection mitigation for attacker-influenced fields.

### Phase 8 — Native Win32 GUI

`usb-sentinel-gui.exe`, a second, independent executable consuming the
same scan engine — not a layer on top of the CLI. Device dropdown,
Scan/Cancel/Refresh/"Open Reports Folder", a marquee progress bar, a
results view fed by the existing text renderer. A real bug, found only
by testing the actual window against real hardware: `tmpfile_s()`
defaults to the root of the current drive, which a standard user can't
write to — fixed with `GetTempPathW`/`GetTempFileNameW`.

### Phase 9 — Hot-plug detection

`WM_DEVICECHANGE`/`RegisterDeviceNotificationW` in the GUI, an opt-in,
off-by-default "Auto-scan new devices" checkbox with a per-identity guard
against double-scanning one physical insert. Verified end-to-end by a
real physical unplug/replug after a synthetic injection attempt was
correctly rejected by Windows itself.

### Phase 10 — Packaging (per-user NSIS installer)

A per-user, no-elevation NSIS installer via CPack. Two real problems
found and fixed before handoff: the stock CPack NSIS template
unconditionally requests admin elevation and silently redirects
Administrator/Power-User accounts to an all-users install; and CPack's
own `CPackConfig.cmake` dump doesn't re-escape backslashes, breaking a
naively-embedded NSIS script (worked around with a real `.nsh` file and
careful path escaping).

### Phase 11 — UI polish

The results view moved from a plain `EDIT` to RichEdit 4.1 (with a
graceful fallback) for per-finding severity colouring; an owner-drawn
verdict banner where green is reserved for exactly one claim ("nothing
bad was found"); a determinate progress bar against real filesystem
bytes-in-use; a custom application icon. A real bug, found by comparing
the live window against the report it had just saved: a throttled
progress snapshot was reused as the finished report's file/byte count,
under-reporting a fast scan's real coverage by orders of magnitude.

### Phase 12 — Code hardening and edge cases

A dedicated pre-release hardening pass. An AddressSanitizer build
(`x64-asan` preset) and a full MSVC `/analyze` (PREfast) audit
(`x64-analyze` preset), both clean, verified against real hardware on
both the CLI and the GUI. Two real defects fixed: a `realloc()`
overwrite-before-NULL-check pattern in the JSON `\u`-escape decoder that
leaked the original buffer on allocation failure, and a 64 KB stack
buffer in the hash-match detector moved to the heap. Explicit lifetime
handling for two loose ends: the GUI's icon handles now call
`DestroyIcon()`, and three progress-throttle statics moved from
file-scope into the per-window state struct. Extended malformed-input
and fixed-seed fuzz batteries for the signature-list loader and the JSON
parser, a deep-nesting stress test proving the real traversal respects
its depth cap at the exact boundary, and an oversized-finding truncation
boundary test.

### Phase 13 — v1.0 release prep and tagging

Documentation brought up to a complete-user-manual standard (this
`README.md`), this changelog, a final pass over `ARCHITECTURE.md` and
`TASKS.md` to separate what shipped from what is deliberately deferred,
and the project's first git commit and `v1.0.0` tag.

## Known limitations at v1.0.0

Recorded here so they are found by reading this file, not discovered the
hard way — full detail in `TASKS.md`'s "Post-v1.0" section and the
architecture-review reasoning `ARCHITECTURE.md` links against each:

- No quarantine or remediation of any kind — detection only, by design
  (the safety policy in `README.md`).
- No ClamAV `.ndb`/`.ldb` byte-pattern or logical signature parsing —
  hash-list signatures only.
- No live signature-update mechanism — a local file you supply, always.
- No report history browser (`report list`/`report show`) — the JSON/CSV
  files on disk are the interface.
- No background service or continuous monitoring — the GUI's auto-scan
  only reacts while the GUI window is open.
- No per-monitor DPI awareness in the GUI.
- Physical device removal mid-scan is verified only by local simulation,
  not against real hardware.
