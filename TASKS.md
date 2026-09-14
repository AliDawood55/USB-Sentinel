# USB Sentinel — Task Tracking

## Phase 1 — Project foundation ✅

- [x] Verify toolchain (MSVC, Windows SDK, CMake, Ninja, Git)
- [x] Initialize git repository, `.gitignore`, `.gitattributes`
- [x] Top-level CMake project, C17, `/W4 /permissive-`, `USBS_WERROR` option
- [x] `CMakePresets.json` with `x64-debug` and `x64-release`
- [x] Core types (`types.h`)
- [x] Status codes and `usbs_status_string()` (`error.h`, `error.c`)
- [x] Leveled logger (`log.h`, `log.c`)
- [x] Generated version header and accessors (`version.h.in`, `version.c`)
- [x] CLI dispatch: `version`, `help`, unknown-command handling
- [x] Executable entry point with status → exit-code mapping
- [x] Test harness and three CTest targets
- [x] README, ARCHITECTURE, PROGRESS, TASKS
- [x] Build and test clean in Debug and Release

## Phase 2 — USB device detection ✅

- [x] Record enumeration and privilege decisions (ARCHITECTURE.md §7)
- [x] `platform` module: Win32 boundary, error translation from `GetLastError()`
- [x] Volume enumeration via `FindFirstVolumeW` / `FindNextVolumeW`
- [x] Bus type via `IOCTL_STORAGE_QUERY_PROPERTY` — not `GetDriveType`
- [x] USB VID/PID via SetupAPI + CfgMgr32 parent walk
- [x] Device metadata (letters, label, filesystem, capacity, free space)
- [x] Drive-letter-independent device identity
- [x] Capability probing by attempting, with graceful degradation
- [x] `usb-sentinel devices` command, with `--all`
- [x] Enumeration seam plus fixture source; tests run without hardware

## Phase 3 — Scanning, detection, storage, reporting ✅

- [x] Record storage/schema/concurrency/notification decisions (ARCHITECTURE.md §9)
- [x] `core`: minimal JSON writer + reader (`json.h`/`json.c`), no external dependency
- [x] `core`: shared scan-result model (`scan.h`/`scan.c`) — checks, findings, statuses
- [x] `platform`: read-only directory/file traversal API (`fs_win32.c`)
- [x] `platform`: separate, narrow local-store write API (storage only, never scanner/detectors)
- [x] `platform`: Ctrl+C cancellation via `SetConsoleCtrlHandler`
- [x] `storage`: `%LOCALAPPDATA%\USBSentinel` layout, atomic temp+rename writes
- [x] `storage`: `index.json` as a self-healing, non-authoritative cache
- [x] `scanner`: single-threaded depth-first traversal, streaming hash (FNV-1a placeholder)
- [x] `scanner`: reparse-point skip, depth cap, per-file error isolation
- [x] `scanner`: cancellation and device-removal handling, always producing a valid report
- [x] `detectors`: fixed registry (no plugin system), `autorun_inspection` detector
- [x] `reporting`: JSON envelope (`schema_version: 1`) + text renderer over the same struct
- [x] `usb-sentinel scan [target]` wired into the CLI
- [x] Fixture/real-directory tests for storage, detectors, scanner, reporting, JSON
- [x] Build and test clean in Debug and Release with `/W4 /permissive- /WX`

Named follow-up, resolved in Phase 4 — see ARCHITECTURE.md §9.3 (original) and
§10.1 (resolution): the FNV-1a placeholder was replaced with verified SHA-256.

## Phase 4 — Detection hardening ✅

- [x] Record Phase 4 architecture decisions (ARCHITECTURE.md §10)
- [x] SHA-256 via Windows CNG (bcrypt), streaming, verified against NIST test vectors
- [x] Remove unconditional whole-volume hashing; traversal counts via `entry.size_bytes`
- [x] Additive `severity` field on findings (`schema_version` stays `1`)
- [x] `suspicious_filename` detector: double extensions, bidi-override, space-padding, hidden executables
- [x] `lnk_inspection` detector: defensive MS-SHLLINK parser, never follows/executes a target
- [x] Shared detector-internal traversal helper (`detectors/walk.h`) — 2nd/3rd real consumer
- [x] SHA-256 NIST vector tests, severity/report round-trip tests
- [x] Suspicious-filename positive/negative fixture tests
- [x] LNK malformed-input battery (empty, truncated, bad magic/CLSID, inflated
      sizes, out-of-bounds offsets, arguments overflow, random bytes, oversized)
      plus benign and suspicious well-formed fixtures
- [x] Build and test clean in Debug and Release with `/W4 /permissive- /WX`
- [x] Partial real-hardware verification (see ARCHITECTURE.md §10.6)

Real defect found and fixed by the malformed-input battery: a declared-but-
out-of-bounds `LocalBasePathOffset` was silently ignored rather than rejected
— see ARCHITECTURE.md §10.4. No crash occurred; the parser produced a
misleadingly clean ("nothing to report") result instead of a malformed one.

**Outstanding real-hardware validation** (ARCHITECTURE.md §10.6):
physical device removal during an active scan has not been verified against
real hardware — only simulated locally (`tests/test_scanner.c`).

## Phase 5 — Walk consolidation and a hash-matching detector ✅

- [x] Record Phase 5 architecture decisions (ARCHITECTURE.md §11)
- [x] `detector.h`: `run`/`on_file` interface split, `usbs_detector_file_ctx_t`
- [x] `scanner.c`: single shared walk owns both metadata counting and
      per-file dispatch to every registered `on_file` detector
- [x] `suspicious_filename`, `lnk_inspection` converted to `on_file`; each
      lost its own independent walk of the volume
- [x] `src/detectors/walk.{h,c}` deleted (not relocated) — logic subsumed
      into `scanner.c`'s existing walk, avoiding two parallel implementations
- [x] `hash_match_example` detector — one hardcoded entry (EICAR), a real
      third consumer of Phase 4's SHA-256 primitive, with a structural
      (message-field) disclaimer present in every report it appears in
- [x] `usbs_hash_match_lookup()` factored out for testing without ever
      writing real EICAR content to disk (see below)
- [x] Every existing LNK/suspicious-filename fixture test adapted to call
      `.on_file()` directly against a synthetic `usbs_dir_entry_t` —
      preserves test intent, and is a genuine simplification, not just an
      adaptation (no real file needed for `suspicious_filename` at all)
- [x] New consolidation test: one scan produces exactly five checks
      (`file_traversal` + four detectors), with cross-detector findings
      verified in the same pass
- [x] Cancellation/device-removed tests extended to cover `on_file`
      detectors' "skipped, partial findings discarded" contract
- [x] Build and test clean in Debug and Release with `/W4 /permissive- /WX`,
      13/13 tests passing

**Unplanned finding during independent hash verification**: writing genuine
EICAR content to disk and reopening it failed on the development machine —
Windows Defender intercepted the file between write and reopen, exactly the
reaction EICAR is designed to trigger. Handled correctly by existing
per-file error isolation (skipped, not a crash); documented in
`hash_match.c` and ARCHITECTURE.md §11.3 as a real environmental property,
not a defect. Drove the `usbs_hash_match_lookup()` test-isolation design.

## Phase 6 — Real signature sourcing (hash-list only) ✅

- [x] Record Phase 6 architecture decisions (ARCHITECTURE.md §12)
- [x] `core/env.c`: shared `usbs_getenv`/`usbs_setenv`, replacing storage.c's
      inline env-var dance (2nd+3rd real consumer of the same pattern)
- [x] `src/detectors/signature_list.{h,c}`: `sha256:size:name` loader,
      malformed-line isolation, bounded (64 MiB) read
- [x] Size-bucketed lookup (binary search + short same-size run) replacing
      the O(n) scan — required once a real, large signature file is loaded
- [x] `hash_match.c`: loads from `USBS_HASH_MATCH_SIGNATURES` env override
      or the default `%LOCALAPPDATA%\USBSentinel\signatures.txt`; falls
      back to the original single EICAR entry when no file is found
- [x] Two-state disclaimer (fallback vs. loaded-from-`<path>`), still
      structural (set on every call, printed unconditionally)
- [x] `usb-sentinel scan [target] [--signatures <path>]` — env-var
      indirection into the one detector that needs it, cli/scanner stay
      ignorant of individual detectors otherwise
- [x] `usbs_hash_match_reset_for_testing()` — test-only reset for the
      process-lifetime load cache
- [x] `tests/test_env.c`, `tests/test_signature_list.c` (new); `test_hash_match.c`
      extended for env override, loaded-vs-fallback state, real end-to-end
      match against a *loaded* (non-hardcoded) entry
- [x] Every Phase 6 fixture hash computed via the verified SHA-256 primitive
      against a synthetic marker string — never EICAR content, on either
      the fallback or the loaded-file path (Phase 5's lesson applied
      proactively)
- [x] Build and test clean in Debug and Release with `/W4 /permissive- /WX`,
      15/15 tests passing
- [x] Verified manually against the real attached USB device: `--signatures`
      switches the disclaimer to loaded state; scan completes cleanly
      against 631 real files; nothing written to the scanned device

Scope discipline honored: no ClamAV `.ndb`/`.ldb` byte-pattern matching (a
materially larger undertaking, explicitly out of scope), no network access
for fetching or updating signatures, no bundled vendor database, no
byte-for-byte ClamAV compatibility claimed (format is ClamAV-*inspired*
only — never independently verified against real ClamAV files).

## Phase 7 — Hash-match size-prefilter fix and CSV export ✅

- [x] Record Phase 7 architecture decisions (ARCHITECTURE.md §13)
- [x] `usbs_signature_list_has_size()` (`signature_list.{h,c}`), sharing a
      factored-out `lower_bound_by_size()` with the existing lookup
- [x] `hash_match_on_file` gated on size before opening/hashing — for both
      the loaded-file path and the single-entry EICAR fallback
- [x] Debug-level log line at the prefilter skip point — diagnostic value,
      and lets the test suite verify the skip actually fires
- [x] `usbs_report_build_csv()` — one row per (check, finding), one row for
      a zero-finding check carrying its check-level message, RFC 4180
      quoting, formula-injection prefix mitigation
- [x] `usbs_store_write_report_csv()`, sharing `write_report_file()` with
      the existing JSON writer (same atomicity, same stem, no duplicated
      write logic)
- [x] `cmd_scan.c` saves `.csv` alongside `.json` automatically, no flag
- [x] `tests/test_hash_match.c`: prefilter verified via captured log
      output, not just unchanged end-to-end findings
- [x] `tests/test_report.c`: CSV structure, zero-finding row, RFC 4180
      escaping, formula-injection mitigation
- [x] `tests/test_storage.c`: CSV companion write, same stem as JSON, one
      scan on record despite two files
- [x] Build and test clean in Debug and Release with `/W4 /permissive- /WX`,
      15/15 tests passing
- [x] Verified on the real attached USB device: matching `.json`/`.csv`
      pair, disclaimer correctly carried in the CSV's `check_message`
      column, both with and without `--signatures`

Real regression found and fixed, not by luck: Phase 6 added the
size-bucketed *lookup* but never gated the *hashing that feeds it* on
size — hashing every file up to 64 MiB once a real signature file was
loaded, an unintended reintroduction of the Phase 4 whole-volume-hashing
cost. Found during the Phase 7 architecture review itself, before any
concurrency work would have been asked to compensate for it.

Known, pre-existing, not Phase-7-caused: an unusually long `--signatures`
path can push `hash_match_example`'s loaded-state disclaimer past
`USBS_CHECK_MESSAGE_MAX` (256 bytes), truncating identically across JSON,
text, and CSV (all three read the same already-truncated
`usbs_check_result_t.message`) — observed during real-hardware
verification, noted rather than silently dropped.

## Phase 8 — Native Win32 GUI ✅

- [x] Record Phase 8 architecture decisions (ARCHITECTURE.md §14)
- [x] `usbs_scan_progress_t`/`usbs_progress_fn` added to `scanner.h`/`.c` —
      a third optional callback on `usbs_scanner_scan()`, called once per
      file at the same granularity cancellation is already polled at, no
      throttling of its own (that policy lives in the GUI's own callback)
- [x] `src/gui/gui_worker.{h,c}` — the testable core: runs one scan via
      plain callbacks, no `HWND`, no window messages, no thread creation of
      its own; `gui_cancel_flag_t` (Interlocked-based) is the only Win32 it
      needs
- [x] `src/gui/gui_window.{h,c}` — the main window: device dropdown,
      Refresh/Scan/Cancel/"Open Reports Folder" buttons, marquee progress
      bar, read-only results text area fed by the existing
      `usbs_report_render_text()`; `_beginthreadex` worker +
      `PostMessage`-based `WM_APP_SCAN_PROGRESS`/`WM_APP_SCAN_DONE`
      marshaling back to the UI thread, which is the only thread that ever
      touches `storage`/`reporting`
- [x] `src/app_gui/main_gui.c` + `usb-sentinel-gui.exe` — a second,
      separate `WIN32` executable target; `usb-sentinel.exe` (the CLI)
      untouched
- [x] `tests/test_gui_worker.c` — headless: normal completion, a pre-set
      cancel flag, and every callback left NULL, all with no window and no
      real worker thread
- [x] `tests/test_scanner.c` gained `test_progress_callback_fires`
- [x] Build and test clean in Debug and Release with `/W4 /permissive-
      /WX`, 16/16 tests passing, zero regressions to the CLI
- [x] Verified against the real attached USB device by driving the actual
      window (Windows UI Automation + `BM_CLICK`): device dropdown
      populated correctly, Scan produced a `.json`/`.csv` pair matching the
      CLI's own report for the same device, "Open Reports Folder" enabled
      only after a successful save

Real bug found and fixed during that real-hardware verification, not by
luck: the results text box came back empty because `tmpfile_s()` — the
first implementation of `render_text_to_buffer()` — defaults to the root
of the current drive, which a standard, non-elevated user cannot write to
on modern Windows (confirmed directly: writing to `C:\` failed with access
denied). This project never elevates, so this was a real, live failure,
not a theoretical one. Fixed with `GetTempPathW`/`GetTempFileNameW`
instead, which resolves to the user's own `%TEMP%`. A "never simply
absent" fallback message was also added for the results box in case
rendering ever fails for any other reason.

**Known gap, not closed by this phase:** Cancel was not exercised against
real hardware — this device's scan completes in well under a second even
through the GUI, too fast to land an automated click mid-scan. Needs a
human's manual test (larger device, or a deliberate click race) before
being considered fully verified — see ARCHITECTURE.md §14.5.

## Phase 9 — Hot-plug detection ✅

- [x] Record Phase 9 architecture decisions (ARCHITECTURE.md §15)
- [x] `RegisterDeviceNotificationW`/`WM_DEVICECHANGE` in `gui_window.c`,
      scoped to `GUID_DEVINTERFACE_VOLUME`; `HDEVNOTIFY` released in
      `on_destroy`; registration failure degrades gracefully (no live
      updates, Refresh still works manually)
- [x] Opt-in "Auto-scan new devices" checkbox, off by default (`BS_
      AUTOCHECKBOX`, "no silent action" per §1)
- [x] `gui_should_auto_scan()` (`gui_worker.h`/`.c`) — the auto-scan
      decision as a pure, testable function, no `HWND`
- [x] Per-identity auto-scanned set (`gui_state_t.auto_scanned_identities`,
      pruned on removal) — prevents double-scanning one physical insert
      across multiple `WM_DEVICECHANGE` messages, while still allowing a
      later re-insertion of the same drive to auto-scan again
- [x] `start_scan_for_device()` factored out of `on_scan_clicked()` — one
      launch path shared by manual Scan and auto-scan
- [x] Dropdown selection persisted by device identity across
      `populate_devices()` refreshes, including hot-plug-triggered ones
- [x] `hash_match.c`'s loaded-state disclaimer shows only the signature
      file's name (`path_filename()`), not the full `--signatures` path —
      fixes the `USBS_CHECK_MESSAGE_MAX` truncation observed in Phase 7/8
- [x] `tests/test_gui_worker.c` gained `test_should_auto_scan_decision()`
- [x] `tests/test_hash_match.c` updated to assert the scratch directory
      prefix is *absent* from the disclaimer (a real regression test, not
      just an updated expectation)
- [x] Build and test clean in Debug and Release with `/W4 /permissive-
      /WX`, 16/16 tests passing, zero regressions
- [x] Verified against real hardware (two USB devices attached during this
      phase): selection persistence confirmed via Refresh; the truncation
      fix confirmed end-to-end through the real CLI with a 227-character
      `--signatures` path (158-byte result, well under the 256-byte
      limit, not truncated); the auto-scan checkbox's wiring confirmed
      directly

**Gap closed after this phase, by the user's manual test:** genuine
`WM_DEVICECHANGE` delivery could not be verified in-environment (a
synthetic injection attempt was correctly rejected by the OS itself,
`ERROR_INVALID_PARAMETER`, before reaching this project's code — see
ARCHITECTURE.md §15.5 for why). The user then physically unplugged and
replugged a real device: the dropdown updated automatically, auto-scan
triggered exactly once (confirming the per-identity guard), and
selection persistence held. Phase 9 is signed off in full.

## Phase 10 — Packaging (per-user NSIS installer) ✅

- [x] Record Phase 10 architecture decisions (ARCHITECTURE.md §16)
- [x] `install()` rules added for `usb_sentinel` and `usb_sentinel_gui`
      (`RUNTIME DESTINATION bin`)
- [x] CPack configured for the NSIS generator, per-user install root
      (`%LOCALAPPDATA%\Programs\USB Sentinel\`)
- [x] Investigated the actual CPack NSIS template shipped with this
      CMake install (not assumed) — found it unconditionally requests
      admin elevation and silently redirects to `$DOCUMENTS` and
      all-users shell context for Administrator/Power-User accounts
- [x] `packaging/usbs_installer_extra.nsh` — forces `RequestExecutionLevel
      user`, corrects the install context without discarding a
      deliberate user folder choice, and keeps the uninstaller's shell
      context consistent with what was actually installed
- [x] Opt-in "Launch USB Sentinel when I log in" checkbox on the finish
      page, unchecked by default — Startup-folder shortcut only, no
      tray icon, no service, no scan
- [x] Uninstall verified by construction to never reference
      `%LOCALAPPDATA%\USBSentinel\` (scan history, signatures file)
- [x] README "Installing" section added
- [x] Build and test clean in Debug and Release with `/W4 /permissive-
      /WX`, 16/16 tests passing, zero regressions (packaging touches no
      compiled code)
- [x] `cpack` now produces a real installer (`USB Sentinel-0.1.0-win64.exe`)
      once NSIS was installed on the same machine — found and fixed a
      real `!include`-rejects-forward-slashes bug from the user's first
      real `cpack` run (ARCHITECTURE.md §16.8), plus a related
      mixed-separator `InstallDir` issue found proactively while fixing
      it
- [x] `RequestExecutionLevel user`'s second-declaration-wins behavior
      confirmed directly — the compiled installer's embedded manifest
      reads `requestedExecutionLevel level="asInvoker"`
- [x] Found and fixed a real files-vs-shortcut mismatch from the user's
      real install: `SetOutPath "$INSTDIR"` in the stock template runs
      *before* `UsbsFixInstallContext` corrects `$INSTDIR` for an
      Administrator account, so the recursive file copy used the
      pre-correction path while `CreateShortCut` (reading `$INSTDIR`
      fresh) used the corrected one — files and shortcut disagreed,
      producing Windows' "target has been moved" dialog. Fixed with one
      added `SetOutPath "$INSTDIR"` re-issued after the correction.
      Verified by actually running two disposable, silent, throwaway
      NSIS installers (writing only into scratch `%TEMP%`
      subdirectories) reproducing the buggy and fixed orderings — the
      buggy one's file landed at the stale path, the fixed one's at the
      corrected path, confirmed with `Test-Path` on all four candidate
      locations (ARCHITECTURE.md §16.9)

**Known gap, not closed by this phase:** the installer compiles cleanly,
its manifest has been inspected directly, and the file-vs-shortcut fix
has been verified against real NSIS runtime behavior in an isolated
test — but the actual install/uninstall wizard flow for the real
product — Directory page, Start Menu creation, the finish-page checkbox
and Startup shortcut, uninstall — has not been run. That is left to the
user's own environment
deliberately, the same precedent as Cancel (§14.5) and, until Phase 9's
user-run test closed it, `WM_DEVICECHANGE` delivery (§15.5).

## Phase 11 — UI polish ✅

- [x] Record presentation decisions (ARCHITECTURE.md §17)
- [x] Results view moved from `EDIT` to RichEdit 4.1 (`Msftedit.dll`) —
      an `EDIT` has one text colour for its whole content and no
      owner-draw, so per-finding colouring is impossible there
- [x] Plain-`EDIT` fallback if `Msftedit.dll` cannot be loaded: same
      report, no colour, never a blank results pane
- [x] `src/gui/gui_report_view.{h,c}` — sectioned, bulleted report as
      semantic `(style, text)` runs; no `<windows.h>`, no colour values,
      so it is unit-testable headlessly
- [x] `tests/test_gui_report_view.c` — verdict rules, styling of
      findings, counts, NULL-safety (17/17 suite passing)
- [x] Verdict banner: owner-drawn, GDI-drawn glyph (no font dependency),
      green / red / amber / slate per verdict
- [x] `ALL CLEAR` requires completed **and** every check run **and**
      nothing above INFO; anything else with zero findings is
      "SCAN INCOMPLETE" with the specific reason, never green
- [x] Green reserved for exactly one claim ("nothing bad was found") —
      the scan's own `Outcome: Completed` line is deliberately not green.
      Caught by a test, fixed in the code rather than the test
- [x] Determinate progress bar against filesystem-reported bytes-in-use,
      clamped and monotonic; marquee fallback when that is unavailable;
      hidden when idle, 0 at start, full at finish, reset afterwards
- [x] Found and fixed a real defect: the finished report reused the last
      *throttled* progress snapshot, reporting "1 file(s), 12 B" for a
      scan that actually covered 631 files / 14,870,278,601 bytes.
      Found by comparing the live window against the JSON/CSV it had
      just saved for that same scan — invisible from either alone
      (ARCHITECTURE.md §17.5)
- [x] Custom shield application icon, generated reproducibly by
      `resources/make_icon.ps1`; 7 sizes, each rendered natively;
      verified through the real Win32 loader at every size
- [x] Icon wired into the GUI executable (`.rc` via `configure_file`,
      absolute escaped paths), the window class, and the installer
      (`CPACK_NSIS_MUI_ICON` / `MUI_UNIICON` / `INSTALLED_ICON_NAME`)
- [x] `.rc` version metadata driven from the one place the version lives
- [x] Resizable window with a single `WM_SIZE` layout function and a
      minimum size; real shell UI font (Segoe UI) instead of the
      `DEFAULT_GUI_FONT` bitmap face
- [x] Verified visually against the real device with
      `PrintWindow(PW_RENDERFULLCONTENT)` — clean, threat and incomplete
      states, plus the progress bar across a slow scan
- [x] **Cancel verified against real hardware** — open since Phase 8
      (§14.5). Forced a slow scan, cancelled mid-run: stopped at 105
      files / 3.6 GiB matching the engine's own count, bar hid and reset,
      and the zero-finding cancelled scan rendered as "SCAN INCOMPLETE",
      not green
- [x] Build and test clean in Debug and Release with `/W4 /permissive-
      /WX`, 17/17 tests passing; CLI output and the JSON/CSV schema
      byte-for-byte unchanged
- [x] `cpack` rebuilt; icon confirmed embedded in both the GUI
      executable and the installer

**Deliberately not done:** per-monitor DPI awareness (needs a real
application manifest plus a full `WM_DPICHANGED` relayout and DPI-scaled
metrics throughout — larger than the rest of this phase combined, and
wanting its own verification pass on actual high-DPI hardware). The
window is bitmap-scaled by Windows in the meantime: usable, slightly
soft.

## Phase 12 — Code hardening and edge cases ✅

- [x] Record Phase 12 architecture decisions (ARCHITECTURE.md §18)
- [x] `x64-asan` preset: MSVC native `/fsanitize=address`, `/RTC1` stripped
      from Debug flags (incompatible with ASan), explicit ASan runtime
      library + `/wholearchive:` thunk + `/INCREMENTAL:NO` link settings
      (CMake's Ninja/MSVC generator links via `link.exe` directly, so
      `cl.exe`'s automatic ASan library selection does not happen)
- [x] Full CTest suite under ASan: 17/17, zero reports
- [x] Real-hardware ASan verification: CLI scan of the real attached USB
      device (916 files, 4,759,379,016 bytes, exit 0); GUI driven through
      a real Scan click via UI Automation + native `SendMessage(BM_CLICK)`
      (this environment's UIA-to-Win32 bridge did not expose
      `InvokePattern`, worked around via each control's real `HWND`),
      completed and closed cleanly, exit 0, no ASan report
- [x] `x64-analyze` preset: MSVC `/analyze` (PREfast), full clean build,
      every warning triaged to fixed-or-documented (ARCHITECTURE.md §18.2)
- [x] Fixed: two `realloc()` sites in `json.c`'s `\u`-escape decode that
      leaked the original buffer on allocation failure
      (`buf = realloc(buf, ...)` overwriting `buf` before the NULL check)
- [x] Fixed: `hash_match_on_file()`'s 64 KB stack read-buffer moved to the
      heap, matching `lnk_inspect.c`'s existing pattern for its own buffer
- [x] Fixed: `wWinMain`'s SAL annotations now match the SDK's own
      `winbase.h` prototype
- [x] Documented (false positive, suppressed with reasoning): a C6001 in
      `usbs_json_free()` PREfast cannot resolve without seeing
      `object_push()`'s invariant
- [x] Documented (reviewed, not changed - test-only code): six C6262
      stack-usage warnings in `test_gui_report_view.c`; one C6001 false
      positive in `test_scanner.c`
- [x] `LoadImageW` icon handles (`gui_window.c`) explicitly destroyed via
      `DestroyIcon()` at every exit path of `gui_window_run()`, never the
      shared `LoadIconW(NULL, IDI_APPLICATION)` fallback
- [x] The three Phase 11 progress-throttle statics
      (`s_final_progress`/`s_have_final_progress`/`s_last_progress_tick`)
      moved into `gui_state_t` - same safety argument, correctly scoped to
      the scan rather than the process
- [x] `tests/test_signature_list.c`: extended malformed-line battery, CRLF
      and no-trailing-newline line endings, duplicate entries, a
      4,000-entry/80-same-size-group stress load, a 200-trial fixed-seed
      random-binary fuzz sweep
- [x] `tests/test_json.c`: extended malformed-input battery, a nested-object
      depth-limit test (with a genuine off-by-one caught in the test
      itself, not the parser), a 3,000-repetition `\u`-escape stress test
      exercising both fixed `realloc` sites, a 5,000-element wide-document
      round-trip, a 500-trial fixed-seed random-binary fuzz sweep
- [x] `tests/test_scanner.c`: `test_deep_nesting_stops_at_scan_max_depth()`
      - a 70-level directory chain confirms the real traversal opens
      exactly depths 0-64 and refuses depth 65 onward
- [x] `tests/test_report.c`: `test_oversized_finding_truncation_boundary()`
      - one byte over a finding field's capacity truncates safely and
      identically across JSON/CSV/text; exactly at capacity does not
      truncate at all
- [x] Build and test clean in Debug and Release with `/W4 /permissive-
      /WX`, 17/17 tests passing, zero regressions; CLI output and the
      JSON/CSV schema byte-for-byte unchanged

All four presets (`x64-debug`, `x64-release`, `x64-asan`, `x64-analyze`)
verified individually after every change in this phase, not only at the
end.

## Phase 13 — v1.0 release prep and tagging ✅

- [x] Record Phase 13 architecture decisions (ARCHITECTURE.md §19)
- [x] README rewritten as a complete user manual: installation, building
      from source (including the two hardening presets), CLI usage, GUI
      usage, a dedicated signature-list-format section, a dedicated
      reports/storage-layout section, privileges, tests
- [x] `CHANGELOG.md` created — a single v1.0.0 entry summarizing Phases
      1 through 13, plus a "known limitations at v1.0.0" section
      cross-referencing this file's "Post-v1.0" section below
- [x] This file's trailing deferred-work section renamed from
      "Phase 13+" to "Post-v1.0" and reconciled against
      ARCHITECTURE.md §8/§17.7/§18 with one previously-implicit item
      (a background service / continuous monitoring, distinct from the
      GUI's already-shipped foreground auto-scan) named explicitly rather
      than left folded into "concurrency"
- [x] `.gitignore` reviewed against the four build presets now in use
      (`x64-debug`/`x64-release`/`x64-asan`/`x64-analyze`) — `build/` and
      the test-scratch-directory pattern already cover all four, no
      changes needed
- [x] First git commit and annotated `v1.0.0` tag (the repository was
      initialized but had never been committed to, across all twelve
      prior phases)

## Phase 14 — Cross-platform support (POSIX) ✅

- [x] Record Phase 14 architecture decisions (ARCHITECTURE.md §20)
- [x] `USBS_VOLUME_PATH_MAX`/`USBS_MOUNT_POINT_MAX` resized from
      Win32-specific values (64 / 8) to 512, with `USBS_IDENTITY_MAX`
      re-derived from the former so the two can never silently drift out
      of sync again; landed as its own Windows-only commit, 17/17, before
      any POSIX code existed (§20.1)
- [x] GitHub Actions CI: Windows (MSVC), Linux (GCC + Clang), macOS
      (Clang), no third-party actions; caught a real pre-existing
      unguarded MSVC `#pragma` in the portable core on its first run (§20.2)
- [x] `autorun.c` matches `autorun.inf` case-insensitively via the
      volume's own directory listing, not by trusting the host filesystem
      - the same open that quietly relied on NTFS's case-insensitivity
      would have missed `AUTORUN.INF` outright on ext4 (§20.3)
- [x] `fs_posix.c`: directory traversal, file reads, and the local data
      store's own writes. Symlinks reported via `lstat`, never followed;
      non-UTF-8 filenames sanitized to U+FFFD at this boundary (§20.4)
- [x] One platform backend selected by CMake per host
      (`device_win32.c`/`fs_win32.c` vs. `device_posix.c`/`fs_posix.c`/
      `hash_posix.c`), replacing the old compiled-everywhere `#else` stub
      halves; `platform_unsupported.c` for an unfamiliar host (§20.5)
- [x] SHA-256: Windows CNG unchanged, Apple CommonCrypto, a vendored
      primitive on Linux (opt-in `-DUSBS_USE_OPENSSL=ON` for packagers who
      forbid vendored crypto) (§20.6)
- [x] `usbsentinel/path.h` (`USBS_PATH_SEP`, `usbs_path_join()`) and
      `usbs_user_data_dir()` replace hardcoded `"\\"` and
      `%LOCALAPPDATA%` across `scanner.c`/`storage.c`/`hash_match.c`/
      `cli.c` (§20.7)
- [x] A fifth CI job: the full suite under Clang ASan + UBSan + leak
      detection - found a genuine `qsort(NULL, 0, ...)` UB in
      `signature_list.c` on its first run (§20.8)
- [x] `scan <path>`: when no enumerated device matches `target` (including
      when enumeration itself is unsupported), it is tried as a directory
      and scanned directly, honestly reporting `bus_type: unknown` and
      identity `volume:<path>` - closes the gap where the CLI could not
      reach the portable engine at all on a host with no enumeration
      backend yet (§20.9/§20.11)
- [x] README `Platform support` table and POSIX build instructions;
      project description no longer says "for Windows"
- [x] Full suite green on every platform throughout: Windows 18/18, Linux
      (GCC/Clang) 16/16, clean under ASan+UBSan+leaks

## Phase 14b — Device enumeration (Linux, then macOS)

Sequenced Linux-first, each step its own verified commit. Real-hardware
verification is not available this phase (the maintainer's own hardware
is Windows-only); see this section's closing note and the "Post-v1.0"
entry below for how that gap is being closed instead.

- [x] Record Phase 14b.1 architecture decisions (ARCHITECTURE.md §21.1)
- [x] `device_linux.c`: block enumeration via `/sys/class/block`
      (partition-vs-whole-disk detection, `capacity_bytes` from the
      kernel's stable 512-byte-sector `size` ABI, `removable_media` via
      `"<partition>/../removable"` - independent of any partition-naming
      scheme). `bus_type` deliberately stays `USBS_BUS_UNKNOWN` this step;
      capability probing deliberately deferred for all of 14b
- [x] `device_posix.c` split: trimmed to the genuinely OS-independent
      half (the `status_from_win32` stub, cancellation); the enumeration/
      capability stubs it used to hold move to a new
      `device_posix_unsupported.c`, used by Apple until 14b.3 lands
      `device_macos.c` and by any other UNIX permanently
- [x] Fixed before it ever ran: reusing `fs_posix.c`'s
      `AT_SYMLINK_NOFOLLOW`-based directory iterator to list
      `/sys/class/block` would have reported every entry there as "not a
      directory" (they are all symlinks, by construction) and silently
      enumerated nothing - indistinguishable from "no devices attached".
      Fixed with a small raw `opendir`/`readdir`/`stat` listing scoped to
      exactly that one call
- [x] Fixed before it reached CI: an early CMake draft routed Apple at
      `device_macos.c`, which does not exist until 14b.3 - would have
      broken the macOS job's configure step immediately. Caught by
      dry-running `cmake -DCMAKE_SYSTEM_NAME=Darwin` locally
- [x] `tests/test_platform.c`'s `test_live_enumeration()` now asserts
      three genuinely different platform states (Windows: full;
      Linux: 14b.1's honest partial state; other POSIX:
      `USBS_ERR_UNSUPPORTED`) rather than a lowest common denominator -
      runs against the real `/sys` of whatever machine executes it
- [x] Verified: 16/16 on Linux (GCC + Clang), clean under ASan+UBSan+leaks,
      Windows unaffected at 18/18
- [x] 14b.2: Linux bus-type ancestry walk (sysfs parent chain via
      `realpath()` + parent-directory climbing, checking each level's
      `subsystem` symlink and `idVendor` presence - never
      `/sys/block/<name>/removable` as a USB test) + `/proc/self/mountinfo`
      for mount points/volume_path/filesystem/free_bytes +
      `/dev/disk/by-label`+`by-uuid` for label and media presence
      (ARCHITECTURE.md §21.2)
- [x] Fixed: `realpath()` implicitly declared under this project's
      `-std=c17 -D_POSIX_C_SOURCE=200809L`, silently truncating the
      returned pointer to 32 bits and corrupting it - `_XOPEN_SOURCE=700`
      (the macro glibc actually gates `realpath()` behind) now defined
      project-wide, not just locally, since any future POSIX file needing
      another XSI-only function would hit the same trap
- [x] Fixed: a classic `for`-loop bug (`tok = strtok_r(...)` in the
      increment clause, called once more than the body executes) silently
      consumed mountinfo's own `"-"` field separator, breaking every
      mountinfo match completely and silently - masked by a stale
      14b.1-era test assertion that still expected `mount_point_count == 0`
- [x] Fixed: a second, independent bug - accumulating `/proc/self/
      mountinfo`'s seq_file content across multiple `read()` calls is not
      guaranteed a consistent snapshot if the mount table changes between
      calls, and a real container's mount churn produced genuinely
      garbled, interleaved lines. Fixed by reading in exactly one
      generously-sized call, the same approach `mount`/`findmnt`/`systemd`
      already use
- [x] Fixed: a mountinfo match must be verified as a directory (`stat()`
      + `S_ISDIR`) before becoming `volume_path` - Docker's own container
      runtime bind-mounts config files (`/etc/resolv.conf` etc.) onto
      plain files, a real case this project's own CI/dev environment
      supplied, not a hypothetical one; `mount_points[]` still records
      every match regardless
- [x] `tests/test_device_linux.c` (Linux-only): a real fake sysfs tree
      (real symlinks via raw `symlink()`) covering partition/whole-disk
      detection, the ancestor walk's negative and positive paths, a
      directory mountinfo match, the file-bind-mount rejection, and
      escaped-space unescaping
- [x] `linux-loopdev-negative-path` CI job: a genuine loop-backed block
      device (`losetup`/`mkfs.ext4`/`mount`), the real built
      `usb-sentinel devices --all`, asserting `bus: unknown` - never USB -
      and incidentally re-confirming the mountinfo pipeline end to end
      against a real mount
- [x] Verified: 17/17 on Linux (GCC + Clang, 16 plus the new test), clean
      under ASan+UBSan+leaks, Windows unaffected at 18/18, loop-device job
      confirmed locally before being trusted to CI
- [x] 14b.3: `device_macos.c` - `DADiskCopyDescription()` for mount
      point/label/filesystem/capacity/removable/bus-protocol (the full
      SATA/NVMe/SCSI/SD set, not just USB - `DeviceProtocol` is already
      resolved by the OS, unlike Linux's sysfs ancestry walk), IOKit
      registry walk (via `DADiskCopyIOMedia()`) for VID/PID/serial
      specifically, `statvfs()` for free space, `hdiutil`-disk-image
      negative-path CI job (ARCHITECTURE.md §21.3)
- [ ] **Not verified, and explicitly flagged as such**: this is the one
      file in Phase 14b with no local build-and-iterate cycle before
      pushing - no Mac is available here, not even to confirm it
      compiles. The `macos-hdiutil-negative-path` CI job is its only
      verification; a Build-step failure there is the expected first
      outcome to investigate, not a regression. The USB property key
      strings (`"idVendor"` etc.) and the actual positive USB path are
      unverified pending real hardware - §14b.4's beta-tester process
- [x] 14b.4: `.github/ISSUE_TEMPLATE/beta-test-device-enumeration.yml` - a
      structured GitHub issue form (not plain markdown) asking beta
      testers to run `usb-sentinel devices --all` on real Linux/macOS
      hardware with a USB stick attached and paste the full output
      (deliberately the whole listing, not just their device's own entry)
      plus a direct "was it classified correctly" field - the positive-
      path verification CI structurally cannot provide (§21.4).
      README.md's Platform support table links to it from the row that
      honestly still reads "unverified on real hardware"
- [x] Update ARCHITECTURE.md and this file to record the honest testing
      boundary this phase settled on: CI proves the negative path (a
      non-USB block device/disk image is correctly not misclassified);
      real hardware, via the community, verifies the positive path (real
      USB devices are correctly classified, with real VID/PID/serial/mount
      data) - the same shape of boundary §10.6 already established for
      the original Windows enumeration work, now made explicit as policy
      rather than discovered device-by-device

**Phase 14b status**: 14b.1-14b.4 complete. Linux enumeration is fully
implemented and verified (fixture tests + real loop-device CI); macOS
enumeration is fully implemented but verified only for compilation and
the negative path (no Mac was available during development) - real
positive-path verification is open, pending beta-tester reports via the
issue template above.

## Phase 14c — v1.2.2-debug: diagnostic logging for a real-hardware Linux report

- [x] A third beta report (real, mounted ADATA USB drive on real Ubuntu,
      missing mount point/filesystem in `v1.2.1`) checked against its own
      theory first: entry `[10]`'s `by-label` match in the tester's own
      output already rules out "whole disk enumerated instead of
      partition," directly from their evidence, before any code changed
      (ARCHITECTURE.md §22.10)
- [x] Reproduction attempted with a maximally-faithful hand-built fixture
      (two real drives, realistic 14-line mountinfo including snap
      mounts, correctly octal-escaped) at both `-O0` and `-O2`; both
      passed cleanly - the report does not reproduce against any fixture
      built so far
- [x] `USBS_LOG_I` diagnostic logging added to `device_linux.c`
      (`handle_block_entry()` and `fill_mount_info()`): every sysfs
      entry considered, the `is_partition_entry()`/skip-include verdict,
      every `dev` file read, every mountinfo line parsed with its
      major:minor and direct-vs-fallback match result, and the complete
      final `usbs_device_t` fields before each device is pushed -
      `USBS_LOG_I` specifically because it prints under `main.c`'s
      default `USBS_LOG_INFO` threshold with no extra flag needed
- [x] `.github/workflows/release.yml`: tags containing `-debug` are now
      marked as a GitHub pre-release, so this throwaway diagnostic build
      never appears as the repo's "latest release"
- [x] Rebuilt and re-tested (Debug and Release, Linux container): all 20
      tests still pass; a smoke run against a minimal fixture confirmed
      the new log lines actually appear and carry the expected data
- [x] Tagged `v1.2.2-debug` and pushed to trigger the release workflow;
      tester ran `usb-sentinel devices --all` and pasted the raw log -
      confirmed parsing consistently stopped at the same mountinfo line
      across every device, but the log had no byte-count/file-size data
      to distinguish a real short read from a namespace/timing question
- [x] `v1.2.2-debug2`: added one more measurement to `fill_mount_info()`
      (the actual `read()` byte count, whether the buffer came back
      completely full, and the last bytes captured) rather than guessing
      between the two candidate mechanisms; tagged and pushed separately
      from `v1.2.2-debug` so it stayed unambiguous which build produced
      which log
- [x] Settled definitively by the tester's `v1.2.2-debug2` run: a single
      262,143-byte `read()` call returned only 4,073 bytes, cut off
      mid-line, while the real USB drive's own mount entry - confirmed
      present via `mount` - sat later in the same file, never reached.
      Root cause: `/proc/pid/mountinfo`'s `seq_file` backing generates
      roughly one internal buffer's worth of content (stabilizing near
      `PAGE_SIZE`) per `read()` call regardless of the destination
      buffer's size, and this project's own Docker/CI containers never
      have a mountinfo large enough to hit it, unlike a real desktop with
      dozens of pseudo-filesystem and snap mounts

## Phase 14c (continued) — v1.2.2: the real fix

- [x] `fill_mount_info()` now loops `read()` until EOF on the same
      already-open file descriptor (never re-opening mid-loop - the
      detail that keeps this safely different from the interleaved/
      garbled-content bug already found and fixed once before, Phase
      14b.2 / ARCHITECTURE.md §21.2), requesting fixed 8 KiB chunks so
      the loop is always genuinely exercised and testable; `MOUNTINFO_CAP`
      raised from 256 KiB to 1 MiB as extra headroom
- [x] New deterministic test,
      `test_mountinfo_match_at_end_of_file_needing_multiple_reads()`: a
      ~40 KB fixture mountinfo with the matching line last, forcing
      several real `read()` calls - the test's own first draft
      under-sized its padding lines and its own `len > 3*8192` assertion
      caught that on the first Docker run before it was ever trusted
- [x] All temporary `v1.2.2-debug`/`v1.2.2-debug2` diagnostic logging
      (`[debug]`-prefixed `USBS_LOG_I` calls in `handle_block_entry()`
      and `fill_mount_info()`) removed now that its purpose - finding
      this bug - is served
- [x] Verified: plain Linux/GCC build matching `ci.yml`'s own
      `linux-gcc` configuration exactly, 20/20 tests passing in a Docker
      container; the changed/new test additionally passes clean under
      Clang ASan+UBSan (two unrelated, pre-existing tests -
      `test_detectors`, `test_gui_report_view` - showed segfaults under
      ASan in this same container that this Docker environment's own
      ptrace/seccomp defaults appear responsible for, neither touching
      `device_linux.c` at all; not treated as a regression from this
      change)
- [x] Tagged `v1.2.2` (a real release) and pushed

## Post-v1.0 — Not planned yet

Deliberately unscoped and deferred, none of it a v1.0.0 blocker — see
ARCHITECTURE.md §8 and the Phase 5/6/7/8/9/10/11/12 architecture reviews'
reasoning against each named item:

- **Quarantine or remediation of any kind.** Detection only, by design
  (the safety policy in README.md, ARCHITECTURE.md §1) — this is not a
  "not yet", it is the project's stated boundary.
- **A real ClamAV-compatible parser** (`.ndb`/`.ldb` byte-pattern and
  logical signatures). The hash-match detector's format is ClamAV-
  *inspired* only (ARCHITECTURE.md §12.1); real byte-pattern matching
  needs an actual pattern-matching engine with wildcard/offset semantics,
  a materially larger and higher-parser-risk undertaking than a
  colon-delimited hash list.
- **A live signature-update mechanism.** USB Sentinel parses a local,
  operator-supplied file only, and always will unless this is explicitly
  revisited — no network access is the point, not a temporary gap.
- **A JSON-report history browser/embedded viewer** (`report
  list`/`report show`, or a GUI equivalent). Needs a JSON-to-struct
  deserializer that does not exist; declined for the GUI's results view
  in Phase 8 for the same reason (ARCHITECTURE.md §14.4).
- **A background service or continuous monitoring.** Every scan today —
  CLI or GUI, manual or auto-scan-on-insert — runs as a foreground,
  user-initiated (or user-opted-in) process; there is no service, no
  tray icon, no monitoring that persists once the GUI window is closed.
  A long-running listener is a materially different threat profile from
  a one-shot invocation (ARCHITECTURE.md §7.3/§8) and would need its own
  privilege and IPC design, not an extension of the GUI's existing
  worker-thread model.
- **Concurrency beyond the GUI's single UI-local worker thread** (e.g.
  scanning multiple devices at once). Nothing in real usage so far has
  demanded it.
- **Per-monitor DPI awareness** for the GUI (ARCHITECTURE.md §17.7). The
  window is bitmap-scaled by Windows in the meantime: usable, slightly
  soft on a high-DPI display.
- **Physical device removal during an active scan, verified against real
  hardware** (as opposed to the local simulation `tests/test_scanner.c`
  already exercises) remains open pending a tester willing to force a
  mid-write disconnect against their own device (ARCHITECTURE.md §10.6).
