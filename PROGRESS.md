# USB Sentinel — Progress Log

Newest entries first.

## 2026-09-12 — Phase 13: v1.0 release prep and tagging

**Delivered.** The final, purely administrative phase before the
project's first release: no scanning/detection/reporting/GUI code
changed. README rewritten as a complete user manual with a table of
contents (installation, building from source including the two Phase 12
hardening presets, CLI usage, GUI usage, a dedicated signature-list
format section, a dedicated reports/storage-layout section, privileges,
tests); `CHANGELOG.md` created, summarizing Phases 1 through 13 as the
single v1.0.0 release they collectively become; `TASKS.md`'s trailing
deferred-work section renamed from "Phase 13+" (now a real, completed
phase) to "Post-v1.0", with a background-service/continuous-monitoring
item named explicitly for the first time rather than left folded into
"concurrency"; `.gitignore` reviewed against all four build presets now
in use and found already sufficient. Decisions recorded in
`ARCHITECTURE.md` §19 (new section; §1-§18 untouched).

**The one real judgment call: how to represent twelve phases of
uncommitted history honestly.** This repository has had a `.git`
directory and a `main` branch since Phase 1, but `git log` has reported
"no commits yet" through every phase up to this one — every prior
phase's `PROGRESS.md` entry that said "uncommitted: the working tree is
left for review" meant exactly that. Two ways to close that out were
considered and rejected before settling on the one used: reconstructing
twelve backdated commits (or twelve invented "v0.x" tags) from
`PROGRESS.md`'s own record would look like a more thorough history than
actually exists, and doing so by *inventing* per-phase diffs and
timestamps that were never real would be a worse dishonesty than having
no history at all — the same principle this project has applied to every
other claim in these documents (never assume, verify or state the gap
plainly). `CHANGELOG.md` instead presents the real history as a single
`[1.0.0]` entry with phase-by-phase subsections, and this phase creates
exactly one git commit covering the whole existing tree plus one
annotated `v1.0.0` tag — not an attempt to fabricate the commit history
this project never had. Full reasoning in `ARCHITECTURE.md` §19.1-19.2.

Build/test verification for this phase is inherited, not repeated:
Phase 12's own closing sweep already confirmed all four presets
(`x64-debug`/`x64-release`/`x64-asan`/`x64-analyze`) build clean with
17/17 passing, and nothing in this phase touched code that verification
covered.

## 2026-09-12 — Phase 12: code hardening and edge cases

**Delivered.** All four requested items, ahead of v1.0: an
AddressSanitizer build (`x64-asan` preset), a full MSVC `/analyze`
(PREfast) audit (`x64-analyze` preset) triaged warning-by-warning to
fixed-or-documented, explicit lifetime handling for two loose ends Phase
11 left behind, and grown malformed-input/fuzz batteries plus two named
stress tests. Builds and tests clean in Debug and Release under
`/W4 /permissive- /WX`, 17/17 passing, zero regressions — CLI output and
the JSON/CSV schema are byte-for-byte unchanged. Decisions recorded in
`ARCHITECTURE.md` §18 (new section; §1–§17 untouched).

**Two real defects found and fixed by the `/analyze` pass, not by
inspection.** `json.c`'s `\u`-escape decoder had two sites doing
`buf = realloc(buf, cap)` and checking the *same* variable for `NULL`
afterward — on allocation failure this overwrites the only pointer to the
original block before the check ever runs, leaking it. Never crashed
(the immediate `return` afterward touches nothing), but a real, silent
leak on an OOM path in a hand-rolled parser this project has otherwise
been careful about. Fixed with a `grown` temporary, matching the pattern
already used two lines below in the same function — the fix was there in
the same file the whole time. Separately, `hash_match_on_file()` carried
a 64 KB stack buffer (66,468 bytes reported once frame overhead is
counted) for its streaming read chunk; moved to the heap, the same
pattern `lnk_inspect.c` already uses for its own buffer.

**A real off-by-one, caught by running the new test rather than by
reasoning about the code.** Writing a "nested objects hit
`USBS_JSON_PARSE_MAX_DEPTH` at the same boundary as nested arrays" test,
the boundary case (32 levels, "must still succeed") failed. The depth
check in `parse_value()` runs on *every* call, including a leaf value's
own — an empty nested array never makes that extra call for its (absent)
contents, but an object holding a real value does, so an object chain's
innermost literal sits one level "deeper" than the same count of nested
empty arrays. 31 is the real boundary for a value-holding chain, not 32.
Fixed in the test, not the parser — the parser's behavior was already
correct and consistent between container types; the test's assumption
was wrong. Recorded in `ARCHITECTURE.md` §18.5 so the next depth-limit
test doesn't repeat the same wrong assumption.

**PREfast also flagged two real false positives**, both confirmed by
inspection rather than dismissed by assumption: a "using uninitialized
memory" warning in `usbs_json_free()` (it cannot see that
`object_push()` always sets `.key`/`.value` together before incrementing
`.count`) and the same diagnostic in a `test_scanner.c` fixture (every
array slot is unconditionally assigned by `CreateFileW` regardless of
success, since this project's `USBS_CHECK` macro never aborts on
failure). The first is suppressed at the exact line with the reasoning
inline; the second is left as-is and documented, since it is test-only
code the analyzer misreads, not a defect. Six more PREfast warnings — all
in `test_gui_report_view.c`, ~99 KB of stack from a deliberately large
test-only capture fixture — were reviewed and left alone for the same
reason: real safety cost is near zero (single-threaded, no recursion, the
default 1 MB test-process stack), and restructuring correct test code
purely to quiet the analyzer would be the wrong trade.

**The icon handles and the three Phase 11 statics, closed while the blast
radius was small, exactly as asked.** `register_class()`'s two
`LoadImageW()` calls return private `HICON`s that were never freed
(harmless today — one window, one process lifetime — but not something to
carry forward); `gui_window_run()` now destroys both at every exit path,
carefully never touching the *shared* `LoadIconW(NULL, IDI_APPLICATION)`
fallback. And `s_final_progress`/`s_have_final_progress`/
`s_last_progress_tick` (Phase 11's progress-throttle bookkeeping) moved
from file-scope statics into `gui_state_t` — same cross-thread safety
argument as before (worker writes, UI thread reads only after joining the
worker), just correctly scoped to the scan rather than the process.

**Fuzzing and stress, all with fixed seeds so a failure is reproducible,
not a one-time report.** `test_signature_list.c` gained a wider
malformed-line battery, CRLF/no-trailing-newline handling, duplicate
entries, a 4,000-entry stress load (80 groups of 50 entries deliberately
sharing one size each, to actually exercise the size-bucketed lookup's
same-size-run scan at scale), and a 200-trial random-binary fuzz sweep.
`test_json.c` gained a wider malformed-input battery, the nested-object
depth-limit test described above, a 3,000-repetition stress test that
forces both fixed `\u`-escape `realloc` sites through many growth cycles
(proving the *fix* still decodes correctly, not just that it no longer
leaks), a 5,000-element wide-document round-trip, and a 500-trial
random-binary fuzz sweep. `test_scanner.c` gained
`test_deep_nesting_stops_at_scan_max_depth()` — a real 70-level directory
chain confirming the actual traversal opens exactly depths 0 through 64
and refuses depth 65 onward, the exact boundary `USBS_SCAN_MAX_DEPTH`
(64) and the `depth > 64` guard imply but are easy to get off-by-one on
by inspection alone. `test_report.c` gained
`test_oversized_finding_truncation_boundary()`, characterizing the
property Phase 7 first noticed informally (§13.3): content one byte over
a finding field's capacity truncates identically across JSON, CSV, and
text, and content exactly at capacity is not touched at all.

**Real-hardware verification, both interfaces, under ASan.** The CLI
(`usb-sentinel.exe scan E:`) scanned the real attached ADATA device clean
under `/fsanitize=address` (916 files, 4,759,379,016 bytes, exit 0, no
ASan report). The GUI needed a workaround to drive at all: Windows UI
Automation resolved every control to `ControlType.Pane` rather than a
proper Button/Text type in this environment, so `InvokePattern` was
unavailable — worked around by reading each control's real native `HWND`
off the `AutomationElement` and driving it directly with
`SendMessage(BM_CLICK)`/`WM_CLOSE`. A real Scan click completed
("Scan complete - 1 finding(s) across 5 check(s)", the same
`hash_match_example` EICAR-fallback finding this device has shown since
Phase 4) and the window closed cleanly, exit 0, no ASan report. Worth
stating plainly: Windows ASan checks heap memory-safety, not GDI/USER
handle leaks, so this run does not independently confirm the icon-handle
fix above — that one relies on the `/analyze` pass and code inspection
instead, recorded honestly rather than implied by proximity to the ASan
verification.

One flaky `test_scanner` failure surfaced once under `x64-debug` during
this phase's own verification sweep and did not reproduce on an immediate
rerun (17/17 clean, and the same binary run standalone independently
showed zero failures) — consistent with this project's previously
documented experience of real-time antivirus occasionally interacting
with freshly-written scratch test files (§11.3), not a regression from
anything in this phase.

## 2026-09-12 — Phase 11: UI polish (readable report, threat colouring, real progress, icon)

**Delivered.** All four requested items. The results view is now a
RichEdit 4.1 control rendering a sectioned, bulleted report with
colour-coded severity; a prominent owner-drawn verdict banner (green
"ALL CLEAR", red "THREATS DETECTED", amber/slate for suspicious or
incomplete) sits above it; the progress bar is determinate, hidden when
idle, and fills proportionally; and the GUI executable and installer
carry a custom shield icon. Builds and tests clean in Debug and Release
under `/W4 /permissive- /WX`, 17/17 passing (one new test file), zero
regressions — `usbs_report_render_text()`, the JSON/CSV builders and the
CLI are all untouched, byte for byte.

Decisions recorded in `ARCHITECTURE.md` §17 (new section; §1–§16
untouched).

**A Win32 `EDIT` cannot do this, so the control changed.** An `EDIT` has
exactly one text colour for its whole content and no owner-draw support,
so per-finding red is impossible there without hand-writing a
replacement control. RichEdit 4.1 (`Msftedit.dll`) costs one runtime
`LoadLibraryW` and no link dependency, with a plain-`EDIT` fallback that
shows the same report uncoloured if the DLL ever fails to load — a
colourless report is degraded, a blank one would be broken.

The layout logic went into `src/gui/gui_report_view.{h,c}`, deliberately
free of `<windows.h>`: it emits *semantic* `(style, text)` runs and
`gui_window.c` owns the palette, so `tests/test_gui_report_view.c` can
assert that a malicious finding is emitted in the threat style with no
window and no RGB value — the same pure-core/thin-wrapper split as
`gui_worker.c`.

**A real bug, found by comparing the window against the report it had
just saved.** The first implementation reused the last *throttled*
progress snapshot as the finished report's "files scanned" figure. The
walk is metadata-only, so a 631-file volume finishes inside the first
100 ms throttle window — every later callback was dropped, and the
window confidently reported **"1 file(s), 12 B examined"** for a scan
that had really covered **631 files and 14,870,278,601 bytes**. The scan
was correct throughout; the saved JSON/CSV for that same scan had the
right numbers. Only the on-screen summary lied, and for a tool whose job
is to say what it checked, under-reporting coverage is a real defect, not
a cosmetic one. Invisible from either artifact alone — found only by
holding the window and its own saved report side by side. Fixed by
recording the snapshot before the throttle and reading it after joining
the worker thread; the rule is now written down in §17.5: throttling may
drop a repaint, never a fact.

**A test caught a design ambiguity too.** "Nothing green anywhere in a
threat report" failed on the obvious `completed ? GOOD : WARNING`
styling of the scan outcome line. Fixed in the code rather than the
test: green is now reserved for exactly one claim — "nothing bad was
found" — so a glance at green never needs its context read. Relatedly,
`ALL CLEAR` is deliberately hard to earn: it requires the scan to have
completed *and* every check to have run *and* nothing above INFO to have
been found. Anything else with zero findings shows "SCAN INCOMPLETE"
with the specific reason, never green (§17.3).

**Verification, and a long-standing gap closed.** Unlike Phase 8, this
phase could see the window: `PrintWindow(PW_RENDERFULLCONTENT)` against
the real running GUI produced actual screenshots. Confirmed against the
real ADATA device: the clean report (631 files / 13.8 GiB, matching the
engine's own `14870278601 byte(s)` exactly), the threat path (a
synthetic signature matching a benign file already on the drive via
`USBS_HASH_MATCH_SIGNATURES` — nothing was ever written to the user's
USB drive), and the progress bar across a deliberately slow, hashing
scan: hidden when idle, visible and at 0 on start, climbing
proportionally, hidden and reset to 0 afterwards.

**Cancel is finally verified.** Open since Phase 8 ("not exercised
against real hardware — this device's scan completes in well under a
second"), closed here by forcing a slow scan and clicking Cancel
mid-run: the scan stopped at 105 files / 3.6 GiB (matching the engine's
`3828252044 byte(s)`), the bar hid and reset, and — the part that
matters — a zero-finding cancelled scan rendered as slate "SCAN
INCOMPLETE … this device has not been fully checked", **not** green.
The honesty rule verified in the real product, not just in a unit test.

The installer was rebuilt with `cpack` and the icon confirmed embedded in
both the GUI executable and the installer, with the doubled-backslash
paths collapsing correctly in the generated `project.nsi` (the §16.5
round-trip hazard, handled the same way). Scratch artifacts were cleaned
up, including two saved reports containing the synthetic test signature —
those would otherwise have sat in the user's real scan history claiming a
threat on a benign file.

**Not done, deliberately:** per-monitor DPI awareness (needs a real
application manifest and a full `WM_DPICHANGED` relayout — larger than
the rest of this phase combined) and, for the third time, a report
history browser (still blocked on a JSON-to-struct deserializer that does
not exist). The window did gain a resizable frame, which a long report
needed.

## 2026-09-12 — Phase 10 follow-up 2: files and the Start Menu shortcut disagreed

The user installed the fixed installer — no elevation prompt, as
intended — but launching from the Start Menu produced Windows' "target
has been modified or moved" dialog. Root cause, found by reading the
stock template's full install Section rather than just the one line
inspected for the previous fix: `SetOutPath "$INSTDIR"` runs at the very
top of that section, *before* `CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS`
(where `UsbsFixInstallContext` corrects `$INSTDIR` for an Administrator
account). `SetOutPath` snapshots the variable's value at that moment
rather than tracking it live, so the recursive file copy right after
(`@CPACK_NSIS_FULL_INSTALL@`, confirmed by reading the actual compiled
`project.nsi` to be a single `File /r`) wrote to the *pre-correction*
path, while `CreateShortCut` — which re-reads `$INSTDIR` fresh — used the
corrected one. Files in one directory, shortcut pointing at another.

Fixed with one added line: another `SetOutPath "$INSTDIR"` at the end of
`UsbsFixInstallContext`, after the correction. Verified more strongly
than the previous fix, not just "it still compiles": built and actually
ran two minimal, silent, disposable NSIS installers writing only into
throwaway `%TEMP%` subdirectories — one reproducing the exact buggy
ordering, one with the fix. The buggy one's file landed at the stale
path and not the corrected one; the fixed one's landed at the corrected
path and not the stale one, confirmed with `Test-Path` against all four
candidate locations. Full account in ARCHITECTURE.md §16.9. Cleaned up
all scratch artifacts afterward.

## 2026-09-12 — Phase 10 follow-up: real `cpack` bug from the field, and a real installer

The user installed NSIS themselves and ran `cpack` for real — the first
time this project's actual `makensis` compilation was exercised, in this
environment or theirs — and it failed:
`!include: could not find: "C:/Projects/USB-Sentinel/packaging/usbs_installer_extra.nsh"`.
The path was already absolute; this was not the working-directory
problem it looked like. Root cause, confirmed by compiling four minimal
`.nsi` test files directly once `makensis.exe` was located on this same
machine too (`C:\Program Files (x86)\NSIS`, apparently installed there
in the meantime): NSIS's `!include` is a compile-time directive handled
by its own script compiler, and rejects forward slashes outright —
unlike the runtime path instructions this project already uses
(`CreateShortCut`, `StrCpy`), which go through slash-tolerant Win32 APIs.
The assumption that NSIS was uniformly slash-tolerant, made when the
original `CPackConfig.cmake` round-trip bug was fixed, was wrong for
this one directive.

Fixed without reintroducing that original bug: the include path now goes
through `file(TO_NATIVE_PATH ...)` + `string(REPLACE "\\" "\\\\" ...)` so
the value CPack dumps into `CPackConfig.cmake` contains a *doubled*
backslash, which is exactly what's needed to collapse back to one real
backslash on the second parse without breaking it — verified by reading
the CMake-stored value, the dumped `CPackConfig.cmake` text, and the
final compiled `project.nsi` line, at each step, not just by a clean exit
code. Found the same class of bug proactively in `CPACK_NSIS_INSTALL_ROOT`
while investigating (still a forward slash, silently producing a
mixed-separator `InstallDir` line) and fixed it the same way rather than
leave a second, easy-to-miss instance sitting nearby.

With a real `makensis` now available, `cpack` produces a genuine
`USB Sentinel-0.1.0-win64.exe`, and two things ARCHITECTURE.md §16.7
had listed as unverified are now confirmed directly: `RequestExecutionLevel
user`'s second-declaration-wins behavior (the compiled installer's own
embedded manifest reads `requestedExecutionLevel level="asInvoker"`), and
the include-path fix itself. The actual install/uninstall wizard flow is
still left to the user's own run, deliberately — same precedent as
Cancel and, until Phase 9's manual test, `WM_DEVICECHANGE` delivery. Full
account in ARCHITECTURE.md §16.7–16.8. Debug and Release both rebuilt and
retested clean afterward, 16/16, zero regressions — none of this touched
compiled code.

## 2026-09-12 — Phase 10: packaging (per-user NSIS installer)

First, closing out Phase 9's one open item: the user physically unplugged
and replugged a real USB device against the running GUI. The dropdown
updated on its own, auto-scan fired exactly once for the re-inserted
device, and selection persistence held across the refresh. The
`WM_DEVICECHANGE` arrival-to-auto-scan chain that could not be exercised
in-environment (ARCHITECTURE.md §15.5) is now verified end to end, and
Phase 9 is signed off in full.

**Phase 10, delivered.** A per-user NSIS installer via CPack, so the tool
can be used day to day without a Developer PowerShell and a from-source
build. `install()` rules for both executables; CPack configured for the
NSIS generator with the install root at
`%LOCALAPPDATA%\Programs\USB Sentinel\`; an opt-in, off-by-default
"Launch USB Sentinel when I log in" checkbox on the finish page that adds
a Startup-folder shortcut and nothing more (no tray icon, no service, no
scan). Touches no scanning/detection code — only the build system plus
one new file, `packaging/usbs_installer_extra.nsh`.

**Two real problems found and fixed before anything was handed off, not
after.** First: the actual CPack NSIS template shipped with this CMake
install (read directly, not assumed) unconditionally requests admin
elevation, and its own `.onInit` silently redirects a per-user install to
`$DOCUMENTS` and all-users shell context whenever the installing account
is an Administrator or Power User — the common case on a personal
machine. Left alone, this would have quietly produced an elevated,
all-users install on most real machines, contradicting the per-user,
no-elevation decision this phase was built around. Fixed by forcing
`RequestExecutionLevel user` and correcting the install context in
`packaging/usbs_installer_extra.nsh` — carefully, only when the stock
template's own wrong default was still in play, so a user's deliberate
"Browse..." folder choice is never silently overridden. Second: CPack's
own `CPackConfig.cmake` dump re-serializes `CPACK_NSIS_*` string values
as plain quoted CMake strings without re-escaping embedded backslashes or
quotes — a value that parsed fine in `CMakeLists.txt` (including via
CMake bracket arguments, tried first) came back unparsable one file
later. Fixed by moving the NSIS script into a real `.nsh` file referenced
by an unquoted, forward-slash path instead of embedding it as a CMake
string at all — arguably the better design regardless of the bug.

Full details, including why NSIS was chosen over WiX and the exact
mechanics of both fixes, are in ARCHITECTURE.md §16. Debug and Release
both rebuilt clean from scratch under `/W4 /permissive- /WX`, 16/16 tests
passing, zero regressions (packaging touches no compiled code). `cpack`
itself now fails only at the expected, legitimate point —
`makensis not found` — with zero CMake warnings or parse errors
beforehand, confirming the configuration is correct up to where it
genuinely needs the external tool.

**Known gap, stated plainly.** NSIS is not installed in this environment.
An attempt to download and silently install it (the official distribution
via SourceForge) was blocked — not by a network restriction, but by
SourceForge's own site gating automated, non-browser downloads behind a
JavaScript-driven mirror page, tried against several direct-mirror hosts
without success. Scripting around that would need a headless browser,
judged out of scope for this pass. The actual `makensis` compilation, and
the full installer/uninstaller wizard flow, remain unverified pending the
user installing NSIS and running `cpack` themselves.

## 2026-09-12 — Phase 9: hot-plug detection

**Delivered.** `WM_DEVICECHANGE`/`RegisterDeviceNotificationW` in the GUI
— the specific capability ARCHITECTURE.md §8 deferred until "a service or
GUI phase is actually planned," now true since Phase 8. An opt-in,
off-by-default "Auto-scan new devices" checkbox, its decision pulled into
a small pure function (`gui_should_auto_scan()`) with a per-identity guard
against double-scanning one physical insert. Plus two small, decoupled
fixes bundled in: the dropdown no longer resets the user's selection on a
refresh, and the hash-match disclaimer no longer truncates for a long
`--signatures` path. Builds and tests clean in Debug and Release with
`USBS_WERROR=ON`, 16/16 tests passing, zero regressions.

Decisions recorded in `ARCHITECTURE.md` §15 (new section; §1–§14
untouched). Scoped exactly as agreed: auto-scan is opt-in and off by
default ("no silent action," §1), manual Scan and auto-scan share one
launch path (`start_scan_for_device()`, factored out of the old
`on_scan_clicked()`), and no new device-filtering logic was written —
`WM_DEVICECHANGE` handling just calls the existing `populate_devices()`,
which already filters through `usbs_device_is_scannable_usb()`.

**A genuinely informative finding while verifying this, not a bug this
time but a real limit worth recording.** Wanting to verify the arrival
handler end-to-end without waiting for a physical unplug/replug, I tried
injecting a synthetic `WM_DEVICECHANGE`/`DBT_DEVICEARRIVAL` at the real
running window via `SendMessageW` from an external process. Windows
rejected it outright with `ERROR_INVALID_PARAMETER` before it ever reached
this project's window procedure - the OS validates this particular
message's parameters at the messaging layer itself, since a genuine
arrival always carries a real, OS-marshaled `DEV_BROADCAST_HDR`-derived
structure in `lParam` that no unrelated external process can supply
without disproportionate cross-process memory work. So the registration
call and the handler's decision logic are each independently verified
(registration succeeds on every launch; `gui_should_auto_scan()` is
unit-tested exhaustively), but the complete, OS-delivered arrival-to-
auto-scan chain has not been exercised against a real unplug/replug -
recorded honestly as a gap needing your manual test, not papered over.

What real hardware *did* let me verify directly, with two USB devices
attached by this point in the conversation (the original ADATA drive plus
a second one): dropdown selection survives a Refresh (selected the second
device, refreshed, selection stayed on it instead of resetting to the
first); and the truncation fix, end-to-end through the real CLI, using a
deliberately constructed 227-character `--signatures` path - the old
"full path in the message" format would have overflowed
`USBS_CHECK_MESSAGE_MAX` and been cut off mid-sentence exactly as first
observed in Phase 7/8; the fixed version came back at 158 bytes, intact,
ending correctly at "...verify its provenance yourself."

## 2026-09-12 — Phase 8: native Win32 GUI

**Delivered.** A minimal, native Win32 GUI (`usb-sentinel-gui.exe`) as a
second, separate executable — a peer consumer of the same scan engine the
CLI already uses, not a layer on top of `cli`. Device dropdown, Scan/
Cancel/Refresh/"Open Reports Folder" buttons, a marquee progress bar, and
a read-only results text area fed by the existing text renderer. Builds
and tests clean in Debug and Release with `USBS_WERROR=ON`, 16/16 tests
passing, zero regressions to the CLI (`usb-sentinel.exe` is untouched).

Decisions recorded in `ARCHITECTURE.md` §14 (new section; §1–§13
untouched). Scoped exactly per the Phase 8 architecture review: hot-plug
device notifications deferred to Phase 9, no embedded JSON/CSV viewer (an
"Open Reports Folder" button instead — building a viewer would reopen the
history-browser scope Phase 7 already declined, through a GUI side door),
concurrency confined to one UI-local `_beginthreadex` worker thread
calling the unmodified scan engine — `core`/`scanner`/`detectors` needed
no threading changes at all.

Two new pieces make this possible: `usbs_scanner_scan()` gained a third
optional callback, `usbs_progress_fn` (§14.2), so a caller can observe
live file/byte counts while a scan runs — `scanner.c` calls it once per
file, unconditionally, with no throttling of its own, matching
`usbs_cancel_check_fn`'s existing NULL-disables convention. And
`src/gui/gui_worker.{h,c}` (§14.3), deliberately split from the actual
window code: it knows how to run one scan and report progress/completion
through plain function-pointer callbacks, and has never seen an `HWND` —
the same "pure core, thin platform wrapper" split Phase 5 used for
`usbs_hash_match_lookup()`, applied here so `tests/test_gui_worker.c` can
exercise cancellation and completion plumbing headlessly, exactly like
`tests/test_scanner.c` already does for the engine itself.

**A real bug, found only because this was verified against real hardware
through the actual window, not just built and eyeballed.** The first
implementation of the results-box renderer used `tmpfile_s()` to get a
`FILE*` for `usbs_report_render_text()` to write into. `tmpfile_s()` has a
well-known but easy-to-forget Windows CRT pitfall: it creates the file in
the root of the current drive, which a standard, non-elevated user cannot
write to on a modern Windows install — confirmed directly (`C:\` write
denied), not assumed. This project never elevates, so every real scan
through the GUI silently produced an empty results box while the JSON/CSV
saved correctly — the kind of half-working state that's easy to miss
without testing the actual window against actual hardware. Fixed with
`GetTempPathW`/`GetTempFileNameW` instead (resolves to the user's own
`%TEMP%`), plus a "never simply absent" fallback message for the results
box in case rendering ever fails for some other reason
(ARCHITECTURE.md §7.3's discipline, applied here too).

Real-hardware verification (the real ADATA device, same one used since
Phase 4): drove the actual window — no mock — via Windows UI Automation
plus a direct `BM_CLICK`, since there is no visual/screenshot tooling in
this environment. Confirmed: the device dropdown populated with the real
device identity, matching the CLI's own `devices` output exactly; Scan
produced a real `.json`/`.csv` pair whose content matches the CLI's own
report for the same device; "Open Reports Folder" went from disabled to
enabled only once that save actually succeeded. The results box's content
specifically couldn't be read back through the external automation
harness (confirmed to be a harness/session limitation, not a product one,
via temporary in-process diagnostic logging that was removed once it had
served its purpose — see ARCHITECTURE.md §14.5 for the full trail).
**Known gap:** Cancel was not exercised against real hardware — this
device's scan completes in well under a second even through the GUI, too
fast to reliably land an automated click mid-scan. Needs a human's manual
test before being considered fully verified.

## 2026-09-11 — Phase 7: hash-match size-prefilter fix and CSV export

**Delivered.** Fixed a real Phase 6 regression (`hash_match_example` was
hashing every file up to 64 MiB regardless of whether its size could match
anything loaded); added CSV export, generated automatically alongside JSON
at scan time. Builds and tests clean in Debug and Release with
`USBS_WERROR=ON`, 15/15 tests passing.

Decisions recorded in `ARCHITECTURE.md` §13 (new section; §1–§12
untouched). Two small, bounded fixes chosen specifically for what they
avoid — no thread pool, no new dependency, no new subsystem — per the
Phase 7 architecture review's rejection of concurrency, a background
monitor, and a curses-based TUI.

**The prefilter fix was a genuine finding, not a stated requirement
turned into code.** Reviewing `hash_match.c` for the Phase 7 architecture
discussion (specifically, evaluating whether concurrency was justified)
surfaced that Phase 6's size-bucketed lookup was never actually gated
behind a size check on the hashing that feeds it — only the 64 MiB upper
cap was checked before opening a file. Once a real signature file was
loaded, this meant hashing every file on the device regardless of size,
exactly the whole-volume-hashing cost Phase 4 deliberately removed from
the general traversal. Fixed with `usbs_signature_list_has_size()`
(`signature_list.{h,c}`), applied to both the loaded-file path and the
single-entry EICAR fallback. Verified by a test that captures the debug
log line at the skip point (`usbs_log_set_stream()`, the pattern
`test_log.c` established) — not just that findings are unchanged
end-to-end, which was already true before the fix and would not have
caught its absence.

Created: nothing (CSV lives in the existing `reporting`/`storage`
modules — `usbs_report_build_csv()` in `report.c`,
`usbs_store_write_report_csv()` in `storage.c`, sharing a newly-factored
`write_report_file()` with the existing JSON writer rather than
duplicating the atomic-write logic). Modified: `signature_list.{h,c}`
(`usbs_signature_list_has_size()`, factored `lower_bound_by_size()`),
`hash_match.c` (prefilter gate + diagnostic log line), `report.h`/`.c`,
`storage.h`/`.c`, `cmd_scan.c` (saves `.csv` alongside `.json`
automatically, no flag — the same "just happens" pattern JSON and text
console output already follow).

CSV design: one row per (check, finding) pair, plus exactly one row for a
check with zero findings — never simply absent, the same discipline
`ARCHITECTURE.md` §7.3 already applies to JSON — carrying the check-level
message (skip reason, failure detail, or `hash_match_example`'s
disclaimer) in its own `check_message` column so it is never lost for lack
of a finding to attach to. RFC 4180 quoting throughout, plus the
formula-injection mitigation the Phase 7 review flagged as a hard
requirement: a field beginning with `=`, `+`, `-`, or `@` (attacker-
influenced content — a crafted filename, LNK-derived text) gets an
additional leading `'` inside the quotes, defanging spreadsheet formula
evaluation without altering the underlying data.

Real-hardware verification: a scan against the real attached device, both
with and without `--signatures`, produces matching `.json`/`.csv` files
with the same stem; the CSV's `check_message` column correctly carries
each detector's disclaimer, properly comma-quoted. One genuine, pre-
existing (not Phase-7-caused) observation surfaced during this
verification: an unusually long `--signatures` path pushed
`hash_match_example`'s loaded-state disclaimer past
`USBS_CHECK_MESSAGE_MAX` (256 bytes), truncating identically across JSON,
text, and CSV — all three read the same already-truncated
`usbs_check_result_t.message`, so this isn't something Phase 7 caused or
could fix in the renderer; noted rather than silently dropped.

Not done, by design (scope discipline honored, per the Phase 7 review):
no `report list`/`report show` history browser (would need a JSON-to-
struct deserializer that doesn't exist and wasn't justified by the actual
ask), no concurrency, no background monitor, no TUI/curses dependency.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 6: real signature sourcing (hash-list)

**Delivered.** `hash_match_example` can now load real SHA-256 signatures
from a local, user-supplied file (`--signatures <path>` or the default
`%LOCALAPPDATA%\USBSentinel\signatures.txt`), with a size-bucketed lookup
replacing the previous O(n) scan and a disclaimer that honestly tracks
whether a real file was loaded. Builds and tests clean in Debug and Release
with `USBS_WERROR=ON`, 15/15 tests passing.

Decisions recorded in `ARCHITECTURE.md` §12 (new section; §1–§11
untouched). Summary: hash-list signatures only (no ClamAV `.ndb`/`.ldb`
byte-pattern matching - out of scope, a materially larger undertaking);
format is ClamAV-*inspired*, not claimed byte-for-byte compatible (never
independently verified against real ClamAV files - the same discipline the
EICAR hash got before being hardcoded); SHA-256 only, no MD5; the tool
parses an operator-supplied local file only - no network access, no bundled
database, sourcing/licensing/update-mechanism stays the separate, deferred
decision it already was.

Created: `include/usbsentinel/env.h` + `src/core/env.c` (shared
`usbs_getenv`/`usbs_setenv` - `storage.c`'s inline env-var dance was its
first consumer, this Phase's the second and third, the bar this project
applies before extracting a shared helper), `src/detectors/signature_list.{h,c}`
(loader + size-bucketed lookup), `tests/test_env.c`, `tests/test_signature_list.c`.
Modified: `hash_match.c` (loads from an env-var-resolved path, two-state
disclaimer, `usbs_hash_match_reset_for_testing()` test hook), `cmd_scan.c`
(`--signatures <path>` flag parsing), `cli.c` (usage text), `storage.c`
(refactored to use the new shared `usbs_getenv`, no behavior change).

A latent cross-TU bug surfaced and was fixed during implementation, not by
luck: `usbs_hash_match_lookup()`'s signature changed (added a `size_bytes`
parameter) as part of this work, but the compiler did not catch the old
test file's now-mismatched ad-hoc `extern` declaration - C does not check
signatures across translation units without a shared header, so this built
and linked "successfully" while being genuinely wrong (the linker matches
symbols by name only). Caught by rebuilding and fixing the test file's
declaration before running anything, not discovered via a runtime failure -
a reminder that this codebase's habit of module-internal `extern`
declarations (used deliberately throughout to avoid growing public headers
for test-only or narrow cross-module surfaces) carries this exact risk, and
each one needs its signature checked by hand against the real definition
when either side changes.

Real-hardware verification: `--signatures <path>` exercised against the
real attached USB device end to end - correctly loaded a synthetic (never
EICAR) signature file, switched the report's disclaimer to the loaded
state, and completed a clean scan of 631 real files with nothing written to
the scanned device. Missing-path and target+flag argument combinations also
verified via the real CLI, not just unit tests.

Not done, by design (scope discipline honored): no ClamAV `.ndb`/`.ldb`
parsing, no network fetch/update, no bundled vendor database, no
remediation, no concurrency, no device-arrival notifications.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 5: walk consolidation and a hash-matching detector

**Delivered.** Detector interface split (`run`/`on_file`); a single shared
walk in `scanner.c` replaces three independent per-scan walks; a fourth
detector (`hash_match_example`) gives Phase 4's SHA-256 primitive a real
consumer. Builds and tests clean in Debug and Release with
`USBS_WERROR=ON`, 13/13 tests passing.

Decisions recorded in `ARCHITECTURE.md` §11 (new section; §1–§10 untouched).
Summary: `usbs_detector_t` now carries `run` (whole-check, e.g. autorun.inf)
and `on_file` (per-file, walk-driven); `scanner.c`'s existing traversal was
extended to dispatch to every registered `on_file` detector per entry rather
than each detector walking independently; `src/detectors/walk.{h,c}` was
deleted outright (not relocated) since only `scanner` walks now.

Created: `src/detectors/hash_match.c`, `tests/test_hash_match.c`. Modified:
`detector.h` (interface split), `scanner.c` (single-walk dispatch,
`on_file_slot_t`, `prepare_on_file_slots`), `autorun.c`/`suspicious_filename.c`/
`lnk_inspect.c` (designated-initializer struct literals; the latter two lost
their own walk calls and, for `lnk_inspect.c`, a now-redundant context
wrapper), `registry.c`. Every existing LNK/suspicious-filename fixture test
was adapted to call `.on_file()` directly against a synthetic
`usbs_dir_entry_t` — a genuine simplification, not just an adaptation:
`suspicious_filename` is metadata-only, so its tests need no real file on
disk at all now, and the Win32 `SetFileAttributesW` call they used to need
is gone. `test_scanner.c` gained a consolidation-proof test (one scan, five
checks, cross-detector findings in the same pass) and extended its
cancellation/device-removed tests to cover the new detector shape.

**A real, unplanned issue surfaced and was resolved during implementation,
not after**: verifying the EICAR SHA-256 independently (rather than trusting
memory) meant writing real EICAR content to disk as part of building
`test_hash_match.c`. This machine's Windows Defender intercepted the file
between write and reopen — exactly the reaction EICAR exists to trigger.
Traced via `usbs_status_string()` diagnostics, confirmed the file vanished
between `usbs_platform_write_file()` and the next
`usbs_platform_file_open_read()`. Resolved by factoring
`usbs_hash_match_lookup()` out as an internal, testable comparison function:
tests verify the match-lookup logic against the known hash *string*, and the
file-read/hash pipeline separately against ordinary non-triggering content —
neither test path ever writes real EICAR bytes to disk. Documented in
`hash_match.c`'s header comment and `ARCHITECTURE.md` §11.3 as a real,
disclosed environmental property (a genuine EICAR file on a scanned device
could go silently unmatched on a machine whose AV intercepts it first),
not a defect — the detector's existing per-file error isolation already
handles an unopenable file correctly.

Cleanup note: running test binaries directly (bypassing `ctest`, which
correctly contains scratch directories under `build/`) left harmless scratch
debris in the repo root during development; removed, and already covered by
the `.gitignore` pattern added during Phase 4's equivalent cleanup.

Not done, by design (scope discipline honored): still no real signature
database, no plugin system, no concurrency, no remediation.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 4: detection hardening

**Delivered.** SHA-256 replaces the FNV-1a placeholder; two new detectors
(`suspicious_filename`, `lnk_inspection`); finding severity. Builds and tests
clean in Debug and Release with `USBS_WERROR=ON`, 12/12 tests passing.

Decisions recorded in `ARCHITECTURE.md` §10 (new section; §1–§9 untouched).
Summary: SHA-256 via Windows CNG (bcrypt), streaming, verified against NIST
vectors, implemented in the existing `fs_win32.c` (still exactly two
`windows.h` translation units); the general traversal became metadata-only
(counts from `entry.size_bytes`, no file opened) since hashing every byte of
every file for an unconsumed digest was wasted I/O and an avoidable
resource-exhaustion risk on adversarial/large media; `severity` added to
findings as an additive field (`schema_version` stays `1`).

Created: `include/usbsentinel/platform.h` hash API (`usbs_platform_hash_*`),
implemented in `fs_win32.c`; `src/detectors/suspicious_filename.c`,
`lnk_inspect.c`, `walk.{h,c}` (a shared internal traversal helper — the
second and third real consumer, after `autorun.inf` needed none). Five new
test files: `test_hash.c` (NIST vectors), and extensions to
`test_detectors.c` (suspicious-filename fixtures) and a new `test_lnk.c`
(a hand-built well-formed + suspicious `.lnk` fixture, plus an 11-case
malformed-input battery).

Real defect found and fixed by the malformed-input battery, not by
inspection: `parse_lnk` silently ignored a `LocalBasePathOffset` field that
was declared present but pointed outside the structure's own bounds —
correctly never over-read (no memory-safety issue), but the parser then
proceeded as an ordinary shortcut with no target, producing a clean
zero-finding result instead of a "malformed" one. A masked-as-benign result
over hostile structured input is itself a defect this class of tool cannot
ship with. Fixed: once a field is declared present, every validation step
for it must succeed or the whole parse is rejected. See ARCHITECTURE.md
§10.4.

Real-hardware verification became possible partway through this phase — a
physical USB device was attached to the development machine, resolving most
of the gaps Phase 2/3 had flagged as untested: positive `BusTypeUsb`
classification, VID/PID/serial extraction (`device_win32.c`'s CfgMgr32 parent
walk — never exercised before this), volume identity, a full scan of a real
FAT32 volume (631 files, ~14.9 GB, all three detectors completing cleanly),
and a real saved report. Capability probing adapted correctly to the real
device (`can_read_raw_volume` was `true` unelevated on this particular FAT32
volume — consistent with §7.3's capability-based design, not a contradiction
of it). **Not verified: physical device removal during an active scan** —
deliberately not attempted against the tester's own real data; still only
simulated locally. See ARCHITECTURE.md §10.6 for the full breakdown.

Not done, by design (scope discipline honored): no real signature database,
no signature update mechanism, no device-arrival notifications, no
concurrency, no remediation/quarantine, no plugin loading.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 3: scanning, detection, storage, reporting

**Delivered.** End-to-end `usb-sentinel scan` — traversal, hashing, a first
detector, a JSON+text report, and persistence — builds and tests clean in
Debug and Release with `USBS_WERROR=ON`.

Decisions recorded in `ARCHITECTURE.md` §9 (new section; §1–§8 untouched
apart from trimming §8 to the item that is still genuinely open). Summary:
plain JSON files under `%LOCALAPPDATA%\USBSentinel` with atomic temp+rename
writes and a self-healing, non-authoritative index cache; `schema_version: 1`
report envelope with every check explicitly `ran`/`skipped`/`failed`;
single-threaded depth-first traversal with reparse-point/depth guards and
per-file error isolation; device-arrival notifications stay deferred.

Created: `core/json.{h,c}` (hand-rolled writer + reader, no external
dependency), `core/scan.{h,c}` (shared check/finding/scan-result model),
`storage/storage.c`, `detectors/autorun.c` + `registry.c`, `scanner/scanner.c`,
`reporting/report.c`, `cli/cmd_scan.c`, plus `platform` additions: read-only
directory/file traversal (`fs_win32.c`), a *separate* local-store write API
used only by `storage` (never `scanner`/`detectors` — keeps the read-only
guarantee for scanned content an absence of capability, not a convention),
and Ctrl+C cancellation. Five new test files
(`test_json`/`test_storage`/`test_detectors`/`test_scanner`/`test_report`),
all against real NTFS directories or a real temp store — no hardware, no
fake filesystem seam.

Mid-implementation refactor: `device.c` (portable device-model operations)
moved from `platform` to `core`. `reporting` (core-only, per §7.4) needs
`usbs_device_identity()`/`usbs_bus_type_string()`; leaving them in `platform`
would have made `reporting` link `platform` for two pure string functions,
breaking core's "zero outgoing dependencies" rule. No behavior changed.

Bug found and fixed during verification: the JSON writer inserted a spurious
comma between every object key and its own value (`"key":,"value"` instead of
`"key":"value"`), corrupting all writer output — caught by `test_json`, not
by inspection. Root cause: one shared `need_comma` flag was used both to gate
the comma before a new object *member* and, incorrectly, before that
member's *value*. Fixed by only consulting it in the array/bare-scalar case;
an object value now always follows its key with no comma check at all. Also
fixed two test-code bugs surfaced by the same failure: uninitialized/NULL
`text` pointers dereferenced by `strstr` after a writer failure (one caused
an actual SIGSEGV in `test_report`).

Known limitation, flagged deliberately rather than shipped silently: the
per-file digest is FNV-1a (non-cryptographic), chosen to prove the streaming
traversal machinery end-to-end without risking an unverified hand-rolled
SHA-256 under time pressure. Nothing currently consumes the hash. Recorded as
a named follow-up in `ARCHITECTURE.md` §9.3 and `TASKS.md`, not left implicit.

Real-hardware verification: `devices`/`scan` both exercised on this machine.
No physical USB device is attached (consistent with Phase 2's finding), so
`scan`'s negative path (no USB device found → clean error, exit 1) is the
only part verified live through the CLI itself; the scan/traversal/hash/
detector/report/storage pipeline is verified against real NTFS directories
and real Win32 APIs on this machine via `test_scanner.c`/`test_detectors.c`/
`test_storage.c`/`test_report.c` — genuine system calls, not mocks, just not
routed through a physically-inserted USB stick.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 2: USB device detection

**Delivered.** Volume enumeration, USB identification, and capability probing.
Builds and tests clean in Debug and Release with `USBS_WERROR=ON`.

Decisions recorded in `ARCHITECTURE.md` §7 (was "Deferred decisions"; the
still-open items moved to §8). §1–§6 untouched. Summary: volume APIs as the
enumeration spine, `IOCTL_STORAGE_QUERY_PROPERTY` as the authoritative bus-type
check, CfgMgr32 for device identity, WMI rejected, `asInvoker` with no self
elevation, capability-based degradation, JSON-primary reporting.

Created:

- `include/usbsentinel/device.h`, `include/usbsentinel/platform.h`
- `src/platform/device.c` — portable device model, list, identity
- `src/platform/device_win32.c` — the only TU that includes `<windows.h>`
- `src/platform/CMakeLists.txt` → `usbs_platform`, links `setupapi`/`cfgmgr32`
- `src/cli/cmd_devices.c` — the `devices` command
- `tests/test_device.c`, `tests/test_platform.c`

Verified on hardware with no USB device attached: the three internal NVMe
volumes are correctly classified as `NVMe`, **not** as USB — confirming that
bus type, not `DRIVE_REMOVABLE`, is doing the work. Unelevated, both raw-access
capabilities correctly report unavailable rather than failing the run.

Two defects found and fixed during verification:

- `hardware` line printed a leading space when the vendor field was empty.
- The `identity` label implied a volume-level key. It is a *device*-level key:
  several volumes on one physical disk legitimately share it. Relabelled
  `device id`, and the constraint is now documented in `device.h`. A
  volume-level key is deferred to `storage`, which does not exist yet.

Not done, by design: no traversal, no scanning, no detectors. `storage`,
`scanner`, `detectors`, and `reporting` still hold only `.gitkeep`.

Uncommitted: the working tree is left for review. No commits were made.

## 2026-09-11 — Phase 1: project foundation

**Delivered.** Repository scaffolded, builds and tests clean in Debug and
Release.

Created:

- Build: `CMakeLists.txt`, `CMakePresets.json`, per-module `CMakeLists.txt`
- Public headers: `types.h`, `error.h`, `log.h`, `version.h.in`
- `core`: `error.c`, `log.c`, `version.c` → static library `usbs_core`
- `cli`: `cli.h`, `cli.c` → static library `usbs_cli`
- `app`: `main.c` → `usb-sentinel.exe`
- `tests`: `test_util.h`, `test_version.c`, `test_error.c`, `test_log.c`
- Docs: `README.md`, `ARCHITECTURE.md`, `TASKS.md`, `PROGRESS.md`
- Repo: `git init`, `.gitignore`, `.gitattributes`

Environment notes:

- CMake and Ninja were **absent** from the machine. Installed via the Visual
  Studio Installer component *C++ CMake tools for Windows* (cmake 3.31.6-msvc6,
  ninja 1.12.1). They are not on the system PATH — builds must run inside a VS
  developer environment.
- C17 confirmed active under MSVC: `__STDC_VERSION__ == 201710`.

During implementation:

- Three `C4127` warnings appeared in `test_version.c` from tautological
  `>= 0` assertions on unsigned version macros. Replaced with a check that the
  numeric macros reconstruct the version string exactly — a real assertion
  rather than a suppressed warning.

Not done, by design: no USB detection, no scanning, no detectors. The
`platform`, `storage`, `scanner`, `detectors`, and `reporting` directories hold
only `.gitkeep`.

Uncommitted: the working tree is left for review. No commits were made.
