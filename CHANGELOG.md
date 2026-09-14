# Changelog

USB Sentinel had no prior release before v1.0.0 — every phase up to
that point shipped directly to this repository's working tree, verified
and documented as it went (see `PROGRESS.md` for the full blow-by-blow,
`ARCHITECTURE.md` for the reasoning behind each decision), and this file
summarized that history as the single v1.0.0 release the project's
first git commit and tag became. Every release since is summarized the
same way, as it ships.

Dates reflect when each phase's work was actually done, not calendar
spacing.

## [Unreleased] — Phase 17: full disk & volume scanning (Windows)

USB Sentinel can now scan **any** mounted volume on Windows, not only USB
devices: internal SATA/NVMe drives such as `C:`, external HDDs, and mapped
network drives. It is always opt-in. The GUI has a new "Show all drives
(Internal & External)" checkbox and the CLI has `scan <target> --all`.
USB-only remains the default everywhere. Full reasoning is in
`ARCHITECTURE.md` §23.

### Added
- GUI: "Show all drives (Internal & External)" checkbox, off by default.
  Toggling it re-enumerates the dropdown. Non-USB drives are labelled by
  connection and size. The live status line shows elapsed time and a
  skipped-location count for long scans.
- CLI: `scan <target> --all` targets any volume. `--all` without a target
  is refused, so a whole-disk scan is never picked implicitly.
  `devices --all` now also lists connected mapped network drives.
- Engine: `usbs_enum_mode_t`, `usbs_device_is_scannable(device, mode)`,
  `usbs_platform_device_source_ex(mode)`, `USBS_BUS_NETWORK`, and
  `paths_skipped` on the scan result and progress snapshot.

### Fixed — would have broken any system-drive scan
- **A single refused directory ended the whole scan.** The walker treated
  any subdirectory it could not open as "device removed", so
  `C:\System Volume Information` aborted a `C:` scan within a second and
  reported every detector as skipped. Such a path is now skipped, logged
  and counted. Only a failure where the volume root itself has also gone
  still counts as removal.
- **A directory deleted mid-scan by another process** was read the same
  way, and is now a skip.
- **Auto-scan could have started an unrequested scan of `C:`.** With all
  drives listed, the first USB insertion would have auto-scanned every
  listed identity not yet scanned, including the system drive. Auto-scan
  is now USB-only in every mode.

### Changed
- A device on a known non-USB bus is identified by its volume
  (`volume:\\?\Volume{GUID}\`, or the share's UNC path), never by the disk
  serial that its sibling partitions share. USB and unknown-bus identities
  are unchanged, so no existing report-store key moves.
- Content reads open with `FILE_FLAG_OPEN_NO_RECALL`, so a scan can never
  trigger a OneDrive or HSM download.
- More Win32 errors are grouped as "access denied": lock violations,
  Defender blocks, `ERROR_CANT_ACCESS_FILE`, and paths blocked by policy.
- The `file_traversal` message gains
  `", N location(s) skipped (access denied or unavailable)"` only when N
  is greater than 0, so USB scan reports are byte-for-byte unchanged.
- The verdict banner stays green when skipped locations are the only gap,
  and its wording then says so: "No threats in everything that could be
  read. N protected location(s) were skipped."

### Verified
- A real 476 GB NVMe `C:` (336 GB used), unelevated, via the CLI: completed
  with 1,484,561 files and 325 GB walked in 113 s, and 337 protected
  locations skipped (all `ACCESS_DENIED`, `System Volume Information`
  among them). Every check ran.
- The real GUI window was driven through the same drive. The scan
  completed with the same 439 findings and 337 skipped as the CLI. The UI
  thread answered in 0 ms throughout the walk, Cancel stopped a second
  scan immediately, and unticking the box returned to USB-only.
- **Not verified:** mapped network drives. No share was available on the
  development machine (see `TASKS.md` Phase 17).

## [1.2.2] — 2026-09-14

### A real read() truncation, confirmed by a beta tester and two debug builds

Three prior beta reports (v1.2.0's two mount-matching bugs, v1.2.1's
disproven root-filesystem theory) all touched Linux mount detection;
this one exposed the actual reason a real Ubuntu desktop's mounted USB
drive showed no mount point or filesystem in `devices --all` and the
web GUI alike, while `scan <path>` against the same drive worked fine
(a red herring: that command bypasses device enumeration entirely and
never touches the code in question — see `ARCHITECTURE.md` §20.11).

Two theories were proposed and checked against real evidence before
either was accepted, the same discipline every prior beta-report
investigation in this file has followed. The first (a hard 4 KiB
`read()` cap on `/proc` files "regardless of buffer size") conflicted
with this project's own understanding of `seq_file`'s fill logic and
was not accepted on assertion alone. A `v1.2.2-debug2` build added one
diagnostic measurement — the actual byte count `read()` returned — and
the tester's own real hardware settled it directly: a single
262,143-byte `read()` call against a real desktop's
`/proc/self/mountinfo` (with ~30-40 pseudo-filesystem and snap mounts
before a single real disk is ever reached) returned only 4,073 bytes,
cut off mid-line, while the drive's own mount entry — confirmed present
via `mount` — sat later in the same file, never reached.

The actual mechanism: `/proc/pid/mountinfo`'s `seq_file` backing
generates roughly one internal buffer's worth of content (which
stabilizes near `PAGE_SIZE` once no single mount line forces it to
grow) *per `read()` call*, regardless of how large a destination buffer
userspace offers — the requested size only bounds how much
already-generated content gets copied out, not how much gets generated
in the first place. A single call, however large the buffer, therefore
does not retrieve the whole file once the real mount table exceeds
about one page, which is routine on any real desktop and never happens
in this project's own minimal CI/Docker containers — exactly why this
was never caught before a real tester's own hardware hit it.

Fixed in `device_linux.c`'s `fill_mount_info()`: `read()` is now called
in a loop until EOF, on the same already-open file descriptor (never
re-opening mid-loop — the detail that keeps this safely different from
the actual interleaved/garbled-content bug this file already found and
fixed once before, `ARCHITECTURE.md` §21.2, which came from a
different, riskier pattern). Covered by a new deterministic test,
`test_mountinfo_match_at_end_of_file_needing_multiple_reads()`, that
forces the loop to run for real against a large fixture file with the
matching entry placed last. All temporary `v1.2.2-debug`/
`v1.2.2-debug2` diagnostic logging (the per-line and per-read-call
`[debug]` output) is removed now that its purpose — finding this bug —
is served.

## [1.2.1] — 2026-09-13

### A second beta report: one real gap, one disproven theory

A second Linux beta report (scanning a device with no mounted volume)
came with a theory attached — that this made the scanner fall back to
walking the entire host root filesystem, and that the cause was the
v1.2.0 udev label fix "not yet released." Both were checked against the
real code and a real repro before anything was changed:

- **The udev fix was already released.** `git merge-base
  --is-ancestor` against the `v1.2.0` tag confirms both Linux mount-
  matching fixes shipped in that release already — nothing to merge.
- **The root-filesystem-scan theory does not hold.** Traced through
  `scanner.c`/`fs_posix.c` and confirmed with a real unmounted loop
  device scanned through the actual `v1.2.0` binary: an unresolved
  mount point leaves `volume_path` empty, never `/`, and
  `opendir("")` fails immediately (`ENOENT`) — the scan reports
  `done: true` in under a second with a contained `USBS_ERR_NOT_FOUND`
  failure, not a multi-minute walk of `/`.
- **What was real underneath it**: nothing stopped `POST /api/scan`
  from accepting a device with no resolvable mount point at all,
  surfacing that raw internal status code in the browser instead of a
  clear explanation — reachable only through the web API, since the
  Win32 GUI's device dropdown is pre-filtered
  (`usbs_device_is_scannable_usb()`) before a device is ever
  selectable, and `POST /api/scan` had no equivalent check. Fixed with
  `device_has_valid_mount_point()` in `gui_web_app.c`, checked before a
  worker thread is ever spawned: a device with no mount points, an
  empty `volume_path`, or (defense in depth) a `volume_path` of exactly
  `/` now gets a `409` with `{"error":"No mount point found for this
  device. Cannot scan."}` instead of ever reaching the scan engine.
  Covered by a new deterministic test and re-confirmed against the same
  real unmounted-device repro that disproved the original theory. Full
  investigation in `ARCHITECTURE.md` §22.9.

## [1.2.0] — 2026-09-13

### Two real bugs found by the first Linux beta test

A beta tester's real ADATA USB drive exposed two genuine parsing
defects in `device_linux.c` that no fixture test had covered:

- A FUSE-backed filesystem mount (the shape `ntfs-3g`/`exfat-fuse`
  produce) whose `/proc/self/mountinfo` major:minor did not match the
  mounted partition's own sysfs identity, leaving mount point,
  filesystem, and free space all unpopulated. Fixed with a fallback
  match against the mount's `source` field, verified against a real
  loop-mounted `ntfs-3g`/`exfat-fuse` filesystem.
- `/dev/disk/by-label` symlink names were being unescaped with
  mountinfo's own octal `\NNN` scheme instead of udev's different,
  hex-based `\xHH` scheme — the literal cause of a label displaying as
  the undecoded `UBUNTU\x2022_0` instead of `UBUNTU 22_0`. Fixed with a
  second, correct decoder.

Both are covered by new deterministic tests in `test_device_linux.c`.

### Phase 16 — Cross-platform GUI (local HTTP server + browser frontend)

`usb-sentinel-gui-web`: a GUI for Linux and macOS without taking Qt or
GTK as a dependency. A hand-rolled HTTP/1.1 server over raw POSIX
sockets serves one embedded page to the system's own browser, backed by
the exact same scan engine the CLI and Windows GUI already use —
`gui_worker.c` (previously Windows-only because its cross-thread cancel
flag used MSVC's `Interlocked*`) is now portable via a `<stdatomic.h>`
path for POSIX, moved into a new `usbs_gui_core` library built on every
platform, so its own existing tests now run on Linux too.

Security model: binds `127.0.0.1` only, never `0.0.0.0`; a per-launch
CSPRNG token (`getrandom()`/`arc4random_buf()`, never this project's
existing non-cryptographic `rand()`) gates every request; the `Host`
header is validated against DNS rebinding; no CORS headers are ever
sent; a fixed, six-route table only, never a general static-file
server. A Unix domain socket was considered and rejected — strictly
safer, but a browser cannot `fetch()` a raw socket, and a browser tab
as the UI is the whole point (`ARCHITECTURE.md` §22).

Two more real bugs, found by this phase's own testing against the
actual running server rather than by inspection: a header-parsing
off-by-one that silently dropped the last header in a request block
(caught by a real `curl` request sending several headers, not a
hand-picked fixture), and `printf()`'s output sitting unflushed in a
fully-buffered stdio stream whenever the server's own output is
redirected to a file or pipe — fixed with an explicit `fflush()` before
the one fallback (the printed launch URL) that matters most when
nothing else is watching.

Verified: the full suite passes under GCC and Clang on Linux and is
unaffected on Windows (18/18, confirmed via a full rebuild before and
after); a new CI job drives the real running server with `curl`
(auth, Host validation, routing) on every push.

## [1.1.0] — 2026-09-13

### Phase 14 — Cross-platform support (POSIX)

The portable core, detection engine, and CLI now build and pass their
full test suite on Linux and macOS, not only Windows: a POSIX platform
backend (`fs_posix.c`, `hash_posix.c`, `device_posix.c`), CI across
Windows/Linux(GCC+Clang)/macOS plus a dedicated ASan+UBSan+leak-
detection job — which caught a real `qsort(NULL, 0, ...)` UB on its
first run — portable paths and per-user data directories, and
`scan <path>` as an honest fallback so the CLI can still reach the
portable engine on a host with no device-enumeration backend yet. The
Win32 GUI and its NSIS installer stay Windows-only; the CLI is the
cross-platform surface.

### Phase 14b — Device enumeration (Linux, then macOS)

Real USB device enumeration on Linux (`/sys/class/block`, a sysfs
bus-type ancestry walk, `/proc/self/mountinfo` for mount points and
free space, `/dev/disk/by-label`/`by-uuid` for label and media
presence) and macOS (DiskArbitration + IOKit). Verified on Linux
against a real loop-backed block device in CI, correctly reported as
`bus: unknown`, never misclassified as USB. macOS shipped with no Mac
available to build on during development — verified only for
compilation and the same negative-path proof via a real `hdiutil` disk
image; real-hardware verification deferred to a structured beta-tester
issue template, which is what surfaced v1.2.0's two Linux bug fixes
above.

### Phase 15 — Release automation

CPack gained a Linux `.tar.gz` generator (the CLI executable plus
`README.md`) alongside the existing Windows NSIS installer; a new
GitHub Actions release workflow builds both on every `v*` tag push and
publishes them to a GitHub Release automatically.

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
