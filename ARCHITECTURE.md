# USB Sentinel — Architecture

This document records design decisions and the reasoning behind them. It is
updated as phases land, not written ahead of the code.

## 1. Safety model

These constraints outrank every other concern, including performance and
feature completeness.

| Constraint | Enforcement |
| --- | --- |
| Read-only scanning | No write, delete, move, or rename API is exposed by any module. Files are opened read-only with sharing permitted. |
| No network | No socket, HTTP, or DNS dependency is linked. Detection data ships with the build. |
| No sample execution | Suspect content is parsed as data. Nothing is loaded as a module or launched as a process. |
| No silent action | Any future remediation must be explicit, opt-in, and reversible. Phase 1 has none. |

A change that weakens any row above is a breaking change and needs an explicit
decision recorded in this file.

## 2. Layering

Dependencies point in one direction only:

```
app  ──►  cli  ──►  core
                     ▲
       platform ─────┤
       storage  ─────┤
       scanner  ─────┤
      detectors ─────┤
      reporting ─────┘
```

Rules:

- **`core` depends on nothing** but the C standard library. It is the only
  module every other module may link.
- **`platform` is the only module permitted to include `<windows.h>`** or call
  Win32 APIs. Everything else stays portable C17, which keeps the bulk of the
  codebase unit-testable without a device attached.
- **`app` contains no logic.** It wires up logging, calls `cli`, and maps a
  status to an exit code.
- Modules never reach sideways into each other's private headers. The only
  cross-module surface is `include/usbsentinel/`.

Module headers that are internal (for example `src/cli/cli.h`) deliberately
live beside their `.c` file rather than in `include/`.

## 3. Error handling

A single return-code model, chosen over alternatives (errno-style globals,
`HRESULT` propagation, setjmp) because it is explicit at every call site and
carries no hidden state:

```c
usbs_status_t usbs_do_thing(const char *input, usbs_thing_t *out_thing);
```

- Every fallible function returns `usbs_status_t`.
- Results are delivered through pointer out-parameters.
- `USBS_OK` is `0`; `usbs_ok()` is the readable predicate.
- `usbs_status_string()` is **total** — it returns a non-NULL name for any
  input, including out-of-range values. `tests/test_error.c` enforces this, so
  adding an enum value without a matching string fails the build's test run.

Win32 error codes will be translated into `usbs_status_t` at the `platform`
boundary and never leak upward.

## 4. Logging

Intentionally under-built for Phase 1: one global threshold, one borrowed
`FILE*` sink defaulting to `stderr`, printf-style formatting.

Deferred until a real caller needs them: file sinks, rotation, structured
output, and thread-safety. Adding a sink abstraction before there is a second
sink would be speculative.

Note that `usbs_log_set_stream()` **borrows** the stream. The caller owns it and
must restore the default (`NULL`) before closing it.

## 5. Build

- **C17** (`__STDC_VERSION__ == 201710L`), verified under MSVC 19.44.
- MSVC's C17 support omits optional features (VLAs, `<threads.h>`). The code
  stays inside the well-supported subset and relies on no optional annex.
- `/W4 /permissive-` always; `/WX` behind the `USBS_WERROR` option, default
  `OFF` so an incidental warning never blocks early development.
- `_CRT_SECURE_NO_WARNINGS` is **not** defined. Where MSVC deprecates a CRT
  call, the `*_s` variant is used behind a `_MSC_VER` guard (see `log.c` and
  `tests/test_log.c`).
- `UNICODE`/`_UNICODE` are defined project-wide from the start so the future
  Win32 layer is `wchar_t`-correct by default rather than retrofitted.
- The version number lives in exactly one place — `project(VERSION ...)` in the
  top-level `CMakeLists.txt` — and reaches C via a generated `version.h`.

## 6. Testing

A ~40-line header (`tests/test_util.h`) instead of an external framework. It
counts checks, reports failures with file and line, and returns an exit code.
This is sufficient for value-level assertions and adds no dependency, which
matters for a security tool where supply-chain surface is a real cost.

Each test is its own executable registered with CTest, so a crash isolates to
one test rather than taking down a shared runner.

## 7. Device enumeration and privilege model

Decided before Phase 2. These supersede the corresponding entries that were
previously listed as deferred.

### 7.1 Enumeration strategy

The three candidate APIs are not alternatives; they sit at different layers of
the storage stack, and USB Sentinel needs three different facts. Each layer is
therefore assigned one question:

| Question | Authority |
| --- | --- |
| Where do I walk files? | Volume / mount-point APIs |
| Is this genuinely USB? | `DeviceIoControl` storage IOCTLs |
| What device is this, durably? | CfgMgr32 |

**Volume APIs are the enumeration spine.** `FindFirstVolumeW` /
`FindNextVolumeW` produce the volume set; `GetVolumePathNamesForVolumeNameW`,
`GetVolumeInformationW`, and `GetDiskFreeSpaceExW` supply letters, label,
filesystem, and capacity. Pure `kernel32`, no COM, sub-millisecond.

**Bus type is the authoritative USB test.** A volume handle opened with
`dwDesiredAccess = 0` still permits `FILE_ANY_ACCESS` IOCTLs, so
`IOCTL_STORAGE_GET_DEVICE_NUMBER` and `IOCTL_STORAGE_QUERY_PROPERTY`
(`StorageDeviceProperty`) yield the physical disk number and
`STORAGE_BUS_TYPE`. A device is USB when `BusType == BusTypeUsb`.

`GetDriveType` returning `DRIVE_REMOVABLE` is **not** a USB test and must never
be used as one. It reports media removability, not bus:

- USB external HDDs and most USB SSDs report `DRIVE_FIXED` and would be missed.
- Internal SD readers and hot-plug bays report `DRIVE_REMOVABLE` and are not USB.

It may be used as a display hint only.

**CfgMgr32 supplies stable device identity and device-tree structure.**
`CM_Get_Device_Interface_ListW` plus `CM_Get_Parent` walk volume → disk → USB
device node for VID/PID, device serial, and device class composition. CfgMgr32
is preferred over the older `SetupDi*` family; SetupAPI is used only where
CfgMgr32 has no equivalent.

**WMI is rejected.** The reasons are recorded because the convenience of its
association classes will make it look attractive again later:

- COM from C17 means manual vtable dispatch and hand-managed `BSTR`/`VARIANT`/
  `SAFEARRAY` lifetimes — the highest defect-density code available to this
  project, and effectively un-fakeable in tests.
- It depends on the `Winmgmt` service and a healthy repository. An offline
  forensic tool must not depend on the health of the machine under suspicion.
- Query latency is hundreds of milliseconds to seconds, against sub-millisecond
  for the chosen APIs, and queries can hang.
- Its repository is modifiable by an attacker holding admin; the live PnP tree
  is the more trustworthy evidence source.
- Heavy `Win32_DiskDrive` / `Win32_PnPEntity` querying is a recognised malware
  pattern and creates avoidable EDR friction for a security tool.

### 7.2 Identity and paths

- **Device identity must not depend on drive letters.** Letters are reassigned
  between insertions. The durable key is **USB VID/PID plus device serial**,
  falling back to the volume GUID where no serial is exposed. `storage` keys
  scan history on this, never on the letter.
- **`scanner` walks the `\\?\Volume{guid}\` path, not the drive letter.** This
  is immune to letter reassignment mid-scan, works for volumes with no letter,
  and the `\\?\` prefix provides long-path support against hostile directory
  trees.

### 7.3 Privilege model

**USB Sentinel ships as `asInvoker` and never requires elevation.**

The governing argument is the threat model, not convenience. The tool parses
hostile, attacker-controlled data using hand-written C parsers in `detectors` —
the highest-risk code in the project. A memory-safety defect there, running
elevated, converts "malicious USB stick" into local privilege escalation. The
parsing surface must be the least-privileged component, not the most.

Available **without** elevation — effectively the entire planned feature set:
volume enumeration and metadata, the CfgMgr32 device tree, the storage IOCTLs
above via the zero-access handle, file reads (FAT32/exFAT, which dominate USB
media, carry no ACLs at all), traversal, hashing, and content inspection.

Requiring elevation — a narrow, bounded slice: raw volume reads
(`\\.\X:` with `GENERIC_READ`) for boot sector and slack analysis, raw
`\\.\PhysicalDriveN` reads for MBR/GPT and bootkit checks, and ACL-denied files
on NTFS-formatted media.

**No automatic or self elevation.** Windows cannot elevate a running process;
`runas` would launch a second process, losing state and creating a
self-elevating binary that is itself an attractive target. If elevation is
wanted, the user re-runs the tool elevated, deliberately. The tool may state
that a capability was unavailable; it must never prompt for privilege.

**Capability-based detection, probed by attempting.** `platform` exposes a
capability set (`can_read_raw_volume`, `can_read_physical_disk`); `scanner` and
`detectors` branch on **capability**, never on privilege. Do not branch on
`IsUserAnAdmin()` (deprecated) or on `CheckTokenMembership` against the
Administrators SID: under UAC's split token, "is the user an admin" and "can
this process open that handle" are different questions and only the second one
matters. Attempt the handle once, treat `ERROR_ACCESS_DENIED` as the answer,
and cache the result.

**Raw-access checks degrade gracefully and are reported explicitly.** When a
capability is absent, the dependent checks are *skipped*, not failed; the scan
completes and still produces results. The report must state the elevation level
and name every skipped check. For a security tool a silent capability gap is
actively dangerous — a clean report that quietly omitted the bootkit check is
worse than no report.

A future elevated helper process that reads sectors on request is deliberately
**not** part of Phase 2. An elevated process accepting instructions from an
unelevated one is a classic escalation pattern and needs its own threat model,
IPC contract, and caller validation.

### 7.4 Consequence for reporting

Because every check now carries a run / skipped / failed status rather than
just findings, **JSON is the primary machine-readable report format, with a
text renderer layered over it** — not text-first with JSON bolted on later.

### 7.5 Side effects

- Never requesting write access, and using zero-access handles for metadata,
  means the read-only guarantee in §1 is enforced by the operating system
  rather than by developer discipline alone.
- No WMI, no raw disk reads, and no elevation in the default path means the
  tool stops resembling the malware patterns it is hunting.

## 8. Deferred decisions

Recorded so they are not silently assumed later:

- Whether `platform` exposes device-arrival notifications
  (`RegisterDeviceNotification`) or only point-in-time enumeration. Point-in-
  time enumeration fits a one-shot CLI process; an event-driven model needs a
  message loop, a second testing seam, and its own privilege discussion (a
  long-running listener is a different threat profile from a one-shot
  invocation under §7.3). Revisit only once a service or GUI phase is
  actually planned - nothing in Phase 3 needs it.
- Concrete detection-signature format and its on-disk location, once a
  detector needs one (the one detector so far, autorun.inf, needs no external
  signature data).
- Concurrency model beyond Phase 3's single-threaded traversal (§9.3), if a
  future phase's throughput needs actually demand it.

## 9. Phase 3 implementation notes

The three previously-deferred items below (detection data format/location,
JSON report schema, concurrency model) are resolved as of Phase 3. This
section records the concrete decisions; §7's decisions are unchanged.

### 9.1 Local data store

Plain JSON files, no database dependency, under
`%LOCALAPPDATA%\USBSentinel\` (`storage.h`/`storage.c`):

- `scans\<safe-device-id>\<timestamp>-<scan-id>.json` - one file per scan.
  `<safe-device-id>` is `usbs_device_identity()` with every byte outside
  `[A-Za-z0-9._-]` escaped as `_XX` hex (`usbs_store_safe_id()`), since the
  identity string's own `:` separators are not valid path characters.
  `<timestamp>` is the report's UTC timestamp with `-`/`:` stripped
  (`compact_timestamp()`) to a fixed 16 characters, so the scan-id suffix -
  which may itself contain punctuation - can be split off by position rather
  than by searching for a delimiter.
- `index.json` - a cache of `{device -> last_scan_id, last_scan_at,
  report_count}`, rewritten after every write. It is deliberately NOT the
  source of truth: `usbs_store_last_scan()` always answers by listing the
  device's report directory directly, so a missing or corrupted index.json
  cannot make that answer wrong - it only means index.json itself gets
  rebuilt (logged, not fatal) on the next write.
- Every write (a report, or the index refresh) uses temp-file-then-rename
  (`usbs_platform_write_file` + `usbs_platform_replace_file`, the latter
  wrapping `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`): a reader never
  observes a partial file, and a crash or device removal mid-write leaves at
  most an orphaned `.tmp`, never a corrupt report.
- `storage`'s local-store writes use a narrow, separate platform API
  (`usbs_platform_write_file` / `make_dirs` / `replace_file` / `delete_file`)
  that only `storage` calls. `scanner` and `detectors` are only ever handed
  `usbs_platform_file_open_read` (read-only). This means the read-only
  guarantee for *scanned* content (§1) is an absence of capability in those
  two modules, not merely a convention they are trusted to follow.

### 9.2 Report schema (`schema_version: 1`)

Implemented in `report.h`/`report.c`. One refinement from the schema sketched
during planning: there is no top-level `elevated` boolean. §7.3 already
prohibits deciding capability from admin-membership checks; a boolean that
claimed to say "elevated" without such a check would be dishonest. The report
carries only `capabilities.can_read_raw_volume` /
`can_read_physical_disk` (what was actually probed) plus each check's
`skip_reason` when a capability gap skipped it - capability-based, matching
§7.3 exactly, not privilege-based.

Envelope: `schema_version`, `tool`, `scan` (id/timestamps/status), `device`
(identity, bus type, hardware strings, volume path, mount points, filesystem,
capacity - one `usbs_device_t` already models exactly one volume, so there is
no nested `volumes[]` array), `capabilities`, `checks[]` (each explicitly
`ran` / `skipped` / `failed`, per §7.3 never simply absent), `summary`. A
`volume_identity` field (device identity + the volume path already in
`volume_path`) implements §5's volume-identity decision, computed inline in
`report.c` at its one real call site rather than added as a `device.h` API -
`device.h` already notes nothing consumes such an API yet.

### 9.3 Concurrency

Single-threaded, depth-first (`scanner.c`), as decided during planning:
reparse points (junction or symlink, file or directory) are never followed;
depth is capped; cancellation is a plain flag polled between files
(`usbs_platform_cancel_requested()`, set from a Win32 console-control
handler - the only reason `scanner`/`cli` never touch `windows.h` themselves
is that this, too, stays behind the platform boundary); a directory that
fails to open mid-walk, or three consecutive per-file read failures, are both
treated as "the device is gone" and end the scan cleanly rather than
cascading per-file errors. A cancelled or device-removed scan still produces
a complete, honest report (`USBS_SCAN_ABORTED`, with every not-yet-run
detector recorded as `skipped`, never silently missing).

Per-file content is hashed with a streaming FNV-1a 64-bit accumulator (fixed
buffer, no whole-file buffering) to exercise the traversal/hashing machinery
end to end. **This is not a cryptographic hash and nothing consumes it yet.**
Before any future detector relies on hash-based identification (matching
against known-bad hashes, meaningful deduplication), this must be replaced
with a verified SHA-256 implementation - recorded here and in TASKS.md so it
is a deliberate follow-up, not something a hand-rolled placeholder quietly
became load-bearing for.

### 9.4 Module placement correction

`device.c` (the portable device-model operations: init, `usbs_bus_type_string`,
`usbs_device_identity`, the growable device list) moved from `platform` to
`core` during this phase. It was placed in `platform` in Phase 2 alongside
`device_win32.c`, but `reporting` - core-only per §7.4 - needs
`usbs_device_identity()` and `usbs_bus_type_string()` to render a report, and
core must have zero outgoing library dependencies (the same reasoning already
applied to `scan.c` in §2: everything may depend on core, core depends on
nothing). `device_win32.c` (the actual Win32 enumeration) stays in `platform`
and still reaches `device.c`'s functions via `platform`'s existing link to
`core`. No behavior changed, only which library compiles the file.

## 10. Phase 4 implementation notes

### 10.1 SHA-256 replaces the FNV-1a placeholder

Via Windows CNG (`bcrypt.dll`), not a hand-rolled implementation - a
first-party Windows facility, the same reasoning §7.1 already applied to
preferring SetupAPI/CfgMgr32 over WMI. Streaming (`usbs_platform_hash_begin`/
`_update`/`_finish`/`_abort`), implemented in `fs_win32.c` rather than a third
`windows.h`-including translation unit - this project still has exactly two
(`device_win32.c`, `fs_win32.c`), and that count is worth keeping accurate.
Verified against the published NIST test vectors (`tests/test_hash.c`)
before anything was allowed to depend on it.

**The unconditional whole-volume hashing pass was removed from `scanner.c`,
not merely replaced.** The old traversal opened and read the full content of
every file on the device solely to compute a hash nothing consumed
(`USBS_UNUSED(hash)`), when `usbs_dir_entry_t.size_bytes` already carries the
file size from the directory listing itself, with no file ever opened. The
`file_traversal` check is now metadata-only: it counts files and bytes from
listing data alone. SHA-256 is computed only where a specific detector
targets a specific file (`lnk_inspect.c` hashes the `.lnk` file it is already
reading, for forensic value in its finding - see §10.4). This is also a
resource-exhaustion fix: reading every byte of a large or slow USB volume on
every invocation, for a digest nothing used, was real, avoidable cost against
what §6 of the Phase 4 review named as adversarial-media DoS risk.

One consequence: the per-file "three consecutive I/O failures means the
device is gone" heuristic no longer applies to the general traversal (it had
nothing left to fail on, once file opens were removed from that path) and was
deleted along with it. Device removal during the general traversal is still
caught the same way a subdirectory failing to open was always caught -
directory-listing failure, not file-open failure - which is in fact the more
faithful signal for an actually-disconnected device.

### 10.2 Finding severity

Added `usbs_severity_t` (`info`/`warning`/`high`) and a `severity` field on
`usbs_finding_t` - additive, so `schema_version` stays `1` per the rule
already established in §7.4/§9.2 ("additive changes... do NOT bump it").
Threaded through both the JSON writer and the text renderer
(`report.c`). No generic `details` structure was added: `severity` is the one
deliberate exception to "findings stay detector-defined" (`scan.h`), because
every detector needs the same small triage vocabulary; everything else about
a finding's content stays a human-readable `message` string, as before.

### 10.3 Suspicious filename detector

Metadata-only (`usbs_dir_entry_t.name`/`.is_hidden`; the latter is a new,
essentially-free field - the attribute bits were already being read off
`WIN32_FIND_DATAW` in `fs_win32.c`, just not exposed). No file is ever opened.
Flags four well-documented Windows filename-deception patterns: double
extensions (`invoice.pdf.exe`), a Unicode bidi-override character
(U+202A-U+202E, the "reversed extension" trick), long space-padding before a
hidden extension, and a hidden/system-attributed executable. Ordinary files,
including a lone `.exe` with no disguise pattern, are not flagged - the goal
is signal, not "every executable is suspicious."

### 10.4 LNK (shortcut) inspection detector

Parses the documented `MS-SHLLINK` binary structure defensively: a hard
256 KiB read cap (an oversized "shortcut" is flagged on that basis alone and
never read, let alone parsed); every length/offset field is validated
against the bytes actually in hand before being used to index or copy
anything; nothing extracted from a `.lnk` is ever opened, followed, or
executed - only inspected as text (§1: no sample execution). Flags a
shortcut whose target is a known interpreter/LOLBin (`powershell.exe`,
`cmd.exe`, `mshta.exe`, `rundll32.exe`, and similar) or whose arguments
contain a suspicious marker (`-enc`, `iex`, `frombase64string`, and similar);
an ordinary shortcut produces no finding. Also computes and records the
`.lnk` file's own SHA-256 in its finding, purely as forensic metadata (not
matched against anything - §8 still defers a real signature source); this is
the one real Phase 4 consumer of the SHA-256 primitive from §10.1.

**A real defect was found and fixed by the malformed-input test battery**
(`tests/test_lnk.c`): a `LinkInfo` structure that *declared* a
`LocalBasePathOffset` field present but pointed it outside the structure's
own bounds was silently ignored - correctly never over-read, but the parser
then proceeded as if the file were an ordinary shortcut with no target,
producing zero findings instead of a "malformed" one. Fixed so that once a
field is declared present, every validation step for it must succeed or the
whole parse is rejected - masking declared-but-invalid structure as "nothing
to report" is itself a defect in a parser over hostile input, even though no
memory-safety property was ever actually violated. This is exactly the kind
of thing the test battery exists to catch, and it caught it.

### 10.5 Shared detector-internal traversal

`suspicious_filename.c` and `lnk_inspect.c` both need to walk the volume
looking at more than one file - a genuine second and third consumer (the
first, `autorun.inf`, only ever opens one fixed path). `src/detectors/walk.h`
is a small internal helper (not part of the public surface, like `cli.h`)
factoring out that traversal: read-only, reparse-points skipped, depth
capped, cancellable via `usbs_platform_cancel_requested()` polled between
entries - the same safety properties `scanner.c` applies to its own walk,
reused rather than re-derived twice.

### 10.6 Real-hardware verification

A physical USB device became available partway through this phase and was
used to verify what Phase 2/3 could not: positive `BusTypeUsb` classification
(previously confirmed only negatively, on internal NVMe), VID/PID/serial
extraction via the CfgMgr32 parent walk (`device_win32.c` - never exercised
before this), volume identity distinct from the drive letter, a full scan of
a real FAT32 volume (631 files, ~14.9 GB) with all three detectors running
to completion, and a real report saved under `%LOCALAPPDATA%\USBSentinel`.
Capability probing behaved correctly on real hardware too - `can_read_raw_volume`
was `true` unelevated on this device's FAT32 volume, which is not a
contradiction of §7.3 (raw access was never claimed to *always* require
elevation, only that it *can*); it is the capability-probing design working
exactly as intended, deciding per-device by attempting rather than assuming.

**Still not verified: physical device removal during an active scan.** This
was deliberately not attempted against the available device, which holds the
tester's own real data - forcing a mid-write disconnect is not a risk to take
with someone's actual drive without being asked. `tests/test_scanner.c`
exercises the equivalent code path via a locked-file/vanished-directory
simulation on local disk; that remains the only verification of this
specific path.

## 11. Phase 5 implementation notes

Phase 5's premise: Phase 4 added a second and third `on_file`-shaped
detector (`suspicious_filename`, `lnk_inspection`), each walking the volume
independently via `src/detectors/walk.c`. Combined with `scanner.c`'s own
metadata-counting walk, every scan walked the tree three times. That is
exactly the "wait for a second/third real consumer" trigger this project has
applied every phase (§6's stance on not building a sink abstraction before a
second sink; §9.1's `usbs_platform_write_file` staying separate from the
read-only file API until storage genuinely needed it) - with three walk-
needing consumers now real, consolidating was the justified next step, not a
speculative one.

### 11.1 `run` vs `on_file`: the detector interface split

`usbs_detector_t` (`detector.h`) now carries two optional function pointers
instead of one:

- **`run`** - a whole-check detector invoked once, doing its own targeted
  access. `autorun_inspection` is the only one: a single fixed path is O(1),
  so folding it into a per-file walk would gain nothing and cost a small
  amount of indirection for no reason.
- **`on_file`** - invoked once per file by `scanner`'s single shared walk.
  `suspicious_filename`, `lnk_inspection`, and the new `hash_match_example`
  (§11.3) all use this shape.

A detector sets exactly one of the two. Nothing enforces that at runtime -
`detector.h` documents it as a convention, not machinery, because building a
mutual-exclusion check for a case that has never once arisen among Phase
5's four detectors would be exactly the "unnecessary abstraction" this
project has repeatedly declined to add ahead of a real need. `run_whole_check_detectors`/
`skip_whole_check_detectors` (`scanner.c`) filter by `det->run != NULL`;
`on_file` detectors are prepared, dispatched, and finalized separately
(§11.2). `tests/test_detectors.c`'s registry-shape test asserts the
exclusivity as an invariant of the *current* four, which is a different
thing from enforcing it in the type itself.

`usbs_detector_file_ctx_t` is the context an `on_file` callback receives:
the same `usbs_detect_context_t` (device/volume/capabilities) a `run`
detector gets, plus a pointer to *this detector's own* in-progress
`usbs_check_result_t` - initialized by `scanner` before the walk starts and
pushed after it ends. A callback only ever appends findings to it; it does
not own the result's lifecycle.

### 11.2 Walk ownership moved to `scanner`; `detectors/walk.{h,c}` deleted, not relocated

`src/detectors/walk.h`/`walk.c` (Phase 4's shared detector-internal
traversal helper) no longer exist. This is a deliberate deletion, not a
file move: once `scanner` is the only thing walking the volume, a second,
parallel walk implementation living in `detectors` would just be dead
weight duplicating properties `scanner.c`'s own `walk_dir` already has
(reparse-point skip, depth cap, cancellation, device-removal detection).
`walk_dir` was extended in place: for every file entry, after the existing
metadata counting, it now also dispatches to every prepared `on_file` slot
(`scanner.c`'s `on_file_slot_t` array, one per registered `on_file`
detector, built once per scan by `prepare_on_file_slots`).

This is a real (if narrow) exception to §2's "`detectors` inspect; they do
not own traversal" framing as it stood after Phase 3/4 - worth recording
plainly rather than leaving the diagram looking unchanged when the actual
call graph moved. `detectors` no longer walks anything; `scanner` walks
once and owns dispatch. `suspicious_filename.c` and `lnk_inspect.c` lost
their own walk calls and the small per-detector context wrapper (`lnk_ctx_t`)
that existed only to carry `volume_path` alongside a `usbs_check_result_t*`
- `usbs_detector_file_ctx_t` already carries both, so that wrapper was
redundant once `scanner` owned the walk.

An incomplete scan (root failed to open, cancelled, or device removed
mid-walk) still means every detector - `run` or `on_file` - reports
`skipped`, never a misleading partial `ran`: `on_file` detectors' partial
findings collected before the walk stopped are explicitly discarded
(`usbs_check_result_free` + re-init + `set_skipped`) rather than kept,
preserving the contract `run` detectors already had (§7.3: never simply
absent, and never partial).

### 11.3 `hash_match_example`: a third real consumer for SHA-256, with a hard disclaimer requirement

Scoped exactly as the Phase 4 review named as optional-but-not-required and
this phase's directive made explicit: **one** hardcoded entry - the SHA-256
of the EICAR Standard Anti-Virus Test File, an industry-standard, harmless
68-byte string every AV vendor recognizes, used specifically so detection
capability can be demonstrated without real malware (§1). It is not, and
must not be mistaken for, the real detection-signature source §8 still
defers.

Files larger than 1 MiB are skipped without being opened (checked via
`entry->size_bytes`, no I/O) - deliberately generous relative to the one
68-byte entry, but still bounded, matching §10.1's resource-discipline
reasoning for why unconditional hashing was removed from the general
traversal in the first place.

**The disclaimer is structural, not a comment a future edit could quietly
drop**: `hash_match_on_file` sets its own `usbs_check_result_t.message` to
the non-production disclaimer text on every call, regardless of whether
anything matched. Since `report.c` already prints a `ran` check's message
unconditionally in both JSON and text output, the disclaimer surfaces in
every report this check appears in - it does not depend on a human
remembering to look at the source file's comments.

**A real, unplanned finding surfaced while independently verifying the
EICAR hash for this file**: writing genuine EICAR content to disk and then
reopening it failed on the development machine - Windows Defender's
real-time protection intercepted the file between write and reopen,
exactly the reaction EICAR exists to trigger. The detector's own per-file
error isolation already absorbs this correctly (a file that cannot be
opened is skipped, not a crash or a hang), but it is a genuine practical
consequence worth recording: a real EICAR file present on a scanned device
may go silently unmatched on a machine whose antivirus intercepts it first.
That is a property of the environment, not a defect in this detector.

It also meant the obvious test design - write real EICAR bytes, scan them,
assert a match - was not reliable on this machine. `usbs_hash_match_lookup()`
was factored out (an internal, non-public symbol `tests/` links against
directly, the same pattern already used for `extern const usbs_detector_t`
declarations elsewhere) specifically so the match-lookup logic could be
tested against the known hash *string* without ever writing real EICAR
content to disk; the file-read/hash pipeline is tested separately, against
ordinary non-triggering content. See `src/detectors/hash_match.c`'s own
header comment and `tests/test_hash_match.c`.

### 11.4 Testing strategy

Every existing malformed-input and fixture test (`test_lnk.c`,
`test_detectors.c`'s `suspicious_filename` tests) was adapted to call
`.on_file()` directly against a synthetic `usbs_dir_entry_t`, rather than
`.run()` driving an internal walk. This is more than a mechanical rename:
it is a genuine simplification the interface split enables, not just a
consequence of it. `suspicious_filename` is metadata-only, so its tests no
longer need any real file on disk at all - a synthetic entry with just a
name (and, for the hidden-executable case, `is_hidden`) is a complete,
faithful fixture, and the Win32 `SetFileAttributesW` call the Phase 4
version needed is gone entirely. `lnk_inspect`'s oversized-file test
similarly no longer needs to write an actual 300 KiB file, since the size
check happens before any file is opened. What each test verifies -
correct parsing, correct rejection of malformed input, correct suspicion
heuristics - is unchanged; only how the fixture reaches the detector
changed.

`tests/test_scanner.c` gained a new test
(`test_all_four_detectors_run_in_one_scan`) proving the consolidation
itself: a single scan against a fixture containing one disguised-name file
produces exactly five checks (`file_traversal` plus all four detectors),
with `suspicious_filename` catching the disguised name in the same pass
`lnk_inspection`/`hash_match_example` correctly find nothing in. The
existing cancellation and device-removed tests were extended to assert the
same "skipped, findings discarded" contract now also holds for `on_file`
detectors, not just `autorun_inspection`.

## 12. Phase 6 implementation notes

Phase 6's premise, from the Phase 6 architecture review: of the three
remaining §8 items, real signature sourcing was the only one that deepens
existing, verified machinery (SHA-256, `hash_match_example`) rather than
opening a new subsystem or reopening the read-only/no-remediation
guarantees. Device-arrival notifications and quarantine/remediation remain
explicitly deferred, unchanged - see that review for the reasoning; nothing
here revisits it.

### 12.1 Scope: hash-list signatures only, local file only

`hash_match_example` now loads real signatures from a local, user-supplied
file instead of only its one hardcoded EICAR entry - but deliberately
**only** the hash-list shape (`sha256:size:name` per line). ClamAV's
byte-pattern (`.ndb`) and logical (`.ldb`) signature formats are not
attempted: they need an actual pattern-matching engine with wildcard and
offset semantics, a materially larger undertaking and a higher parser-risk
class than a colon-delimited text format - exactly the kind of scope that
would deserve its own dedicated phase, not a Phase 6 line item.

The format is **ClamAV-inspired, not claimed byte-for-byte compatible**
with any specific ClamAV database version - that would require independent
verification against real ClamAV documentation or sample files, which was
not done, the same discipline the EICAR hash got before being hardcoded in
Phase 5. SHA-256 only, never MD5: adding a second, weaker-for-collision-
resistance crypto primitive purely for format compatibility was rejected in
the Phase 6 review, keeping the project's crypto surface at exactly the one
primitive verified in Phase 4.

**Sourcing stays exactly where §1 and §8 already put it.** `hash_match.c`
parses a file the operator supplies at a local path; it never fetches,
updates, or bundles one. No real vendor database is included in this repo.
A real detection-signature *source* - where an operator's file legitimately
comes from, licensing, and how it would be updated while staying fully
offline - remains the separate, deferred decision §8 already named.

### 12.2 Loader and size-bucketed lookup (`src/detectors/signature_list.{h,c}`)

Internal to `detectors` (not in `include/usbsentinel`, the same pattern the
deleted `walk.h` used) - `usbs_signature_list_load()` parses the file
(bounded read, 64 MiB cap - generous for an operator-supplied file, but
still bounded), skipping malformed lines with a capped, logged warning
rather than failing the whole load over one bad line. `usbs_signature_list_lookup()`
is **not** the linear scan `usbs_hash_match_lookup()`'s single hardcoded
entry could get away with: entries are sorted by size at load time, and
lookup does a binary search for the size, then scans only the (usually
short) run of entries sharing that exact size before comparing hashes -
O(log n + k) rather than O(n). This is a genuine algorithmic requirement,
not premature optimization: a real signature file is plausibly tens of
thousands of entries, and the size-then-hash ordering also means a file
whose size matches nothing loaded is never hash-compared at all.

### 12.3 Two honest report states, not one static disclaimer

`hash_match_on_file` sets its check's message on every call (Phase 5's
structural-disclaimer pattern, unchanged in mechanism) to one of two texts,
chosen by whether a real file was loaded:

- **No file loaded** (the common, out-of-the-box case - missing file,
  unreadable file, or a file with zero valid entries all resolve here):
  exactly Phase 5's original wording, unchanged - "NON-PRODUCTION EXAMPLE...
  EICAR only... NOT a real malware signature database."
- **File loaded**: "Matched against N signature(s) loaded from `<path>`
  - USB Sentinel does not ship, vet, or vouch for this file's contents;
    verify its provenance yourself." A finding from a loaded entry also
  drops the "demonstration match" caveat its EICAR-fallback counterpart
  carries - a real loaded match is not a demonstration.

Getting this binary distinction right was the point: a static disclaimer
that always says "demo" would be dishonest once a real file is loaded; one
that always claims "loaded" would overclaim when nothing was.

### 12.4 `--signatures <path>`: env-var indirection, not a direct call into one detector

`cli/cmd_scan.c` parses `scan [target] [--signatures <path>]` (either order)
and, when given, calls the new `usbs_setenv()` (`core/env.c`) to set
`USBS_HASH_MATCH_SIGNATURES` before scanning; `hash_match.c` checks that
variable first, falling back to `%LOCALAPPDATA%\USBSentinel\signatures.txt`
via the matching `usbs_getenv()`. This was a deliberate choice over having
`cmd_scan.c` call directly into `hash_match.c`'s internals: `cli` and
`scanner` stay ignorant of which individual detectors exist or what they
need, exactly as before Phase 6 - the one thing that changed is that one
detector now has an optional external input, not that `cli` gained
detector-specific knowledge. Environment-variable indirection is also not a
new idiom introduced for this: it is the same arm's-length mechanism
`storage.c` already used for `%LOCALAPPDATA%` itself since Phase 3, now
factored into the shared `usbs_getenv()`/`usbs_setenv()` (`core/env.c`) -
a genuine second and third real consumer of that exact pattern, the bar
this project applies before extracting a shared helper.

### 12.5 Testing: never write real EICAR bytes, for the loaded path either

Every Phase 6 fixture hash is computed via the verified SHA-256 primitive
(`usbs_platform_hash_begin`/`_update`/`_finish`, the same one `test_hash.c`
checked against NIST vectors) applied to an explicitly synthetic marker
string (e.g. `"USB_SENTINEL_PHASE6_TEST_MARKER_NOT_MALWARE"`), never
hardcoded from memory and never resembling EICAR or any real malware
content - the Phase 5 lesson applied proactively to the loaded-file path
too, not just preserved on the fallback path. `tests/test_signature_list.c`
covers the loader/lookup module directly (round-trip, uppercase-hex
normalization, malformed-line isolation, empty/missing file, the
wrong-size-same-hash negative case); `tests/test_hash_match.c` covers the
detector's integration (env-var override, `usbs_hash_match_reset_for_testing()`
- a test-only reset for the process-lifetime load cache, the same
non-public-header `extern` pattern already used for
`usbs_hash_match_lookup()` - fallback-vs-loaded disclaimer state, and a
real end-to-end match against a loaded, non-hardcoded entry). Verified
manually against the real attached USB device too: `--signatures` correctly
switched the disclaimer to the loaded state and the scan completed cleanly
against 631 real files with no signature-file content ever written to the
scanned device itself.

## 13. Phase 7 implementation notes

Two small, bounded fixes, both chosen specifically for what they *avoid*:
no thread pool, no new dependency, no new subsystem, no change to the
read-only guarantee or the privilege model. See the Phase 7 architecture
review for why concurrency, a background monitor, and a curses-based TUI
were all declined in favor of these.

### 13.1 `hash_match_example`'s missing size-prefilter (a real regression, found and fixed)

Phase 6 added the size-bucketed *lookup* (§12.2) but never gated the
*hashing that feeds it* on size: `hash_match_on_file` only rejected files
above the 64 MiB upper cap, then opened and hashed every file up to that
cap regardless of whether its size could possibly match anything loaded.
Once a real signature file was loaded, this was an unintended
reintroduction of the exact whole-volume-hashing cost §10.1 removed from
the general traversal in Phase 4 - found during the Phase 7 architecture
review, before being asked to add concurrency to work around it.

Fixed with `usbs_signature_list_has_size()` (`signature_list.{h,c}`,
sharing the same size-sorted binary search `usbs_signature_list_lookup()`
already does via a factored-out `lower_bound_by_size()`), checked in
`hash_match_on_file` before `usbs_platform_file_open_read` - for **both**
the loaded-file path and the single-entry EICAR fallback (which now only
opens a file that is exactly 68 bytes, not everything up to 64 MiB). A
debug-level log line was added at the skip point, both for genuine
diagnostic value and so `tests/test_hash_match.c` could verify the
prefilter actually fires - not just that end-to-end findings are
unchanged, which was already true before the fix and would not have caught
its absence.

### 13.2 CSV, generated automatically alongside JSON, never a second source of truth

`usbs_report_build_csv()` (`report.h`/`report.c`) is a formatter over the
same `usbs_scan_result_t` the JSON writer and text renderer already read -
no new data, no round-trip, no JSON-to-struct deserializer (deliberately
out of scope; a `report list`/`report show` history browser would need
one, and was declined for exactly that reason - the CSV/JSON files landing
in `%LOCALAPPDATA%\USBSentinel\scans\` are sufficient for external
tool/SIEM integration without it). `cmd_scan.c` saves it as a `.csv`
alongside the `.json` automatically, no flag - the same "just happens"
pattern JSON and the text console output already follow.

One row per `(check, finding)` pair, and - the same "never simply absent"
discipline §7.3 already applies to JSON - exactly one row for a check with
zero findings, carrying the check-level message (a skip reason, a failure
detail, or `hash_match_example`'s disclaimer) in its own `check_message`
column so it is never lost simply because there was nothing to attach it
to. Columns: `scan_id,device_identity,check_id,check_status,skip_reason,
check_message,severity,path,message`.

`storage.h`/`storage.c` gained `usbs_store_write_report_csv()`, sharing a
newly-factored `write_report_file()` internal helper with the existing
JSON writer (same atomic temp-file-then-rename, same directory, same
`<timestamp>-<scan_id>` stem, `.csv` instead of `.json`) rather than
duplicating that logic. It does not itself refresh `index.json` - the
paired JSON write already does, for the same scan.

**Formula-injection mitigation, per the Phase 7 review's explicit
requirement.** `path` and `message` fields can originate from
attacker-controlled content (a crafted filename, LNK-derived text) that
this project has never trusted, going back to §6's LNK-parser discipline.
RFC 4180 quoting (comma/quote/newline triggers quoting, embedded quotes
doubled) is not sufficient on its own against a field beginning with `=`,
`+`, `-`, or `@`, which a spreadsheet application could evaluate as a
formula on open - `csv_write_field()` additionally prefixes such a field
with a leading `'` inside the quotes, a standard, minimal defense that
defangs the interpretation without altering the underlying data.

### 13.3 Testing

`tests/test_hash_match.c` gained a prefilter-specific test that redirects
the logger to a scratch file (the same `usbs_log_set_stream()` pattern
`test_log.c` established) to confirm the skip-without-opening decision
actually fires, not just that findings are unchanged - a test that only
checked end-to-end output would have passed both before and after the fix
existed, which is exactly why it would not have caught the fix's absence.
`tests/test_report.c` gained CSV structural tests (header shape, exactly
one row for a zero-finding check, row count matching finding count) and
escaping tests for both RFC 4180 quoting and the formula-injection prefix,
verified by checking the field content rather than the exact quoted
encoding where that was more robust. `tests/test_storage.c` covers the new
`usbs_store_write_report_csv()`: same stem as its JSON sibling, and -
critically - writing both files for one scan still counts as exactly one
scan in `usbs_store_last_scan()` (already true by construction, since that
function only counts `.json` files, but worth asserting explicitly now
that a second per-scan file exists).

Verified against the real attached USB device: a `scan` (both with and
without `--signatures`) saves matching `.json` and `.csv` files with the
same stem; the CSV's `check_message` column correctly carries each
detector's disclaimer, properly comma-quoted. One genuine, pre-existing
(not Phase-7-introduced) observation surfaced during this verification: an
unusually long `--signatures` path pushed `hash_match_example`'s loaded-
state disclaimer past `USBS_CHECK_MESSAGE_MAX` (256 bytes), truncating it
identically in the JSON, text, and CSV output alike (all three read the
same already-truncated `usbs_check_result_t.message`) - not something
Phase 7 caused or could fix locally, since the truncation happens before
any renderer sees the string; noted here rather than silently observed and
dropped.

## 14. Phase 8 implementation notes

A native Win32 GUI, added as a peer consumer of the scan engine - not a
layer on top of `cli` - so the CLI's verified behavior carries zero
regression risk. See the Phase 8 architecture review for why an embedded
JSON/CSV viewer, device-arrival hot-plug notifications, and multi-device
concurrent scanning were all declined for this phase.

### 14.1 Layering: `gui` as a fifth consumer, `app_gui` as a second empty shell

```
app      ──►  cli  ──►  core
app_gui  ──►  gui  ──┤        ▲
                      platform ─────┤
                      storage  ─────┤
                      scanner  ─────┤
                     detectors ─────┤
                     reporting ─────┘
```

`src/gui/` depends on `core`/`platform`/`scanner`/`storage`/`reporting`
exactly like `cli` does - the same dependency set, one more box beside it,
no new edges. `src/app_gui/main_gui.c` mirrors `src/app/main.c`: it
contains no logic, just `wWinMain` handing off to `gui_window_run()` and
returning its exit code. `usb-sentinel-gui.exe` is a wholly separate
executable target (`add_executable(... WIN32 ...)`, `/SUBSYSTEM:WINDOWS`)
from `usb-sentinel.exe` - the console CLI is untouched by this phase.

One rule needed updating: §2 said `platform` is the *only* module
permitted `<windows.h>`. That is no longer literally true -
`src/gui/gui_worker.c` includes it directly (for the cancel flag's
Interlocked* calls), and `src/gui/gui_window.h` includes it as part of its
own public shape (`gui_window_run()`'s `HINSTANCE` parameter), which pulls
it transitively into every file that includes that header:
`gui_window.c` itself and `src/app_gui/main_gui.c`. Together these are a
second, equally deliberate exception to §2, for the same reason
`platform` was one: GUI creation, message loops, and thread primitives are
inherently Win32, and confining that to one more clearly-bounded module
keeps the rest of the codebase (`core`, `scanner`, `detectors`, `storage`,
`reporting`) portable and unit-testable without a display, exactly as
before.

### 14.2 The progress callback

`scanner.h` gained `usbs_scan_progress_t` (`files_scanned`, `bytes_scanned`)
and `usbs_progress_fn`, a third optional callback alongside
`usbs_cancel_check_fn` on `usbs_scanner_scan()` (now seven parameters).
`scanner.c`'s `walk_dir` calls it, when non-NULL, once per file - the same
granularity cancellation is already polled at - unconditionally, with no
throttling of its own: scanner stays ignorant of who is listening or how
often they want to hear from it. `cmd_scan.c` passes `NULL, NULL` and is
otherwise unchanged. Throttling how often a live UI actually repaints from
this is the *caller's* concern (§14.4).

### 14.3 `gui_worker`: the testable core, split from Win32 window plumbing

`src/gui/gui_worker.h`/`.c` knows how to run one scan and report
progress/completion through plain function-pointer callbacks; it has never
seen an `HWND` and links no window-message code. `gui_window.c` supplies
the `_beginthreadex` thread and `PostMessage`-based marshaling as a thin
layer on top - the same "pure core, thin platform wrapper" split Phase 5
used for `usbs_hash_match_lookup()` (§11.3), applied here so
`tests/test_gui_worker.c` can exercise cancellation and progress/
completion plumbing by calling `gui_worker_run()` directly, synchronously,
on the test's own thread - no window, no real worker thread, no hardware.

`gui_cancel_flag_t` is a `volatile long` toggled with
`InterlockedExchange`/read with `InterlockedCompareExchange` - the only
Win32 this file needs. `gui_worker_run()` always calls `on_done` exactly
once with a heap-allocated `usbs_scan_result_t*` the callback takes
ownership of (or, if `on_done` is NULL, frees itself) - callers never have
to special-case "no result," matching `usbs_scanner_scan()`'s own
always-produces-a-result contract.

### 14.4 `gui_window`: one fixed window, no embedded report viewer

Device dropdown (`CB_ADDSTRING` per scannable USB device, populated at
startup and on Refresh - there is still no hot-plug notification, §8, so
this is the only way to see a device inserted after the window opened),
Scan/Cancel/Refresh/"Open Reports Folder" buttons, a marquee progress bar,
and a read-only multiline edit control. The results box is filled by
`usbs_report_render_text()` unchanged - rendered to a `tmpfile_s()`-backed
buffer instead of `stdout` - not a second renderer. "Open Reports Folder"
calls `ShellExecuteW` on the directory the JSON/CSV pair just landed in,
deliberately **not** an embedded grid view: a real viewer would need a
JSON-to-struct deserializer, already declined once for the history browser
in Phase 7's TASKS.md, and building one here through a GUI side door would
quietly reopen that same declined scope.

The progress bar is marquee (indeterminate), not a percentage - there is
no total file count to divide by until the walk finishes, and a fabricated
percentage would be dishonest data. The status label instead shows live
`files_scanned`/`bytes_scanned` counts from `usbs_progress_fn`, throttled
in `gui_on_progress()` (the worker-thread callback) to at most ~10 posts/
second via `GetTickCount64()`, so a drive with a very large number of
files cannot flood the message queue - `scanner.c` itself does no
throttling (§14.2); this is where that policy choice actually lives.

**Thread discipline.** The worker thread touches the window only through
`PostMessageW(WM_APP_SCAN_PROGRESS / WM_APP_SCAN_DONE, ...)` with a
heap-allocated payload the UI-thread handler frees. Every call into
`storage`/`reporting` - JSON/CSV build and save, text rendering - happens
in those UI-thread handlers, never on the worker thread. This was a
deliberate choice, not an accident: §4's logger is explicitly not
documented as thread-safe ("one global sink... no thread-safety"), and
detectors already call `USBS_LOG_*` during a scan. Keeping every
`storage`/`reporting` call - and, in practice, all `USBS_LOG_*` calls
triggered by GUI code - on one thread sidesteps that gap rather than
requiring a thread-safety guarantee `log.c` does not make. If a future
phase makes the logger genuinely thread-safe, this constraint can be
revisited; until then it is a real, current limitation, recorded here
rather than assumed away.

`WM_CLOSE` refuses to close (a `MessageBoxW` warning instead) while a scan
is running, forcing Cancel first - the alternative, letting the window (and
its `HWND`) be destroyed while a worker thread might still `PostMessage`
to it or hold an open read handle on the device, was rejected as the
riskier path for a small usability cost. `usb-sentinel-gui.exe` links
`comctl32.lib` (the progress bar control) and declares the ComCtl32 v6
manifest dependency via `#pragma comment(linker, "/manifestdependency:...")`
in `main_gui.c` - without it, controls render in the pre-XP visual style
but function identically; this is a cosmetic-only pitfall, not a
correctness one, called out in the Phase 8 review and fixed here rather
than left for a bug report.

### 14.5 Testing

`tests/test_gui_worker.c` (new): runs `gui_worker_run()` against a scratch
directory standing in for a volume root, exactly like
`tests/test_scanner.c` does for the engine itself - no hardware, no
window, no real worker thread, since the function itself makes no
threading decisions. Covers: normal completion with progress calls
observed and a heap-owned result handed to `on_done`; a pre-set cancel
flag producing `USBS_SCAN_ABORTED` (the same contract
`usbs_scanner_scan()` already has for cancellation, §9.3/§11); and every
callback left NULL, which must still run to completion and free the
result itself rather than leak or crash.

`tests/test_scanner.c` gained `test_progress_callback_fires`, asserting
the new callback fires once per file with non-decreasing counts and a
final tally matching `file_traversal`'s own message.

The window procedure itself (`gui_window.c`) is deliberately thin dispatch
with the logic pulled out into the free functions covered above; it is not
covered by CTest. It was verified against the real attached USB device by
driving the actual window - no mock, no fixture - through Windows UI
Automation plus direct `BM_CLICK`: the device dropdown genuinely populated
with the real device identity (matching the CLI's own `devices` output
exactly), clicking Scan produced a real `.json`/`.csv` pair on disk whose
content matches the CLI's own report for the same device (same schema,
same check list, same file/byte counts), and "Open Reports Folder"
correctly went from disabled to enabled only once that save succeeded.
The results text box's *content* specifically could not be read back
through the external UI Automation harness (a limitation of that
harness/session, not of the product - confirmed by temporary in-process
diagnostic logging showing `SetWindowTextW` succeeding with the correct
764-character rendered report and the control still holding it at the end
of the handler); that diagnostic code was removed once it had served its
purpose. Cancel was not exercised this way: this device's scan completes
in well under a second even through the GUI, too fast to reliably land a
click mid-scan by automation, so it still needs a human's manual click
(the same honest gap this project has flagged before, e.g. §10.6). Full
interactive UI testing (every button, resizing edge cases, closing
mid-scan, Cancel) is otherwise a manual, human
verification step this project has always required for real-hardware and
UI behavior (§10.6's precedent) - it is not something an automated test
suite substitutes for.

## 15. Phase 9 implementation notes

Hot-plug detection - the specific GUI-gated feature §8 deferred until "a
service or GUI phase is actually planned," now true - plus two small,
decoupled fixes bundled in alongside it because they were cheap and
already understood: dropdown selection persistence and the
`USBS_CHECK_MESSAGE_MAX` truncation issue observed during Phase 7/8
verification.

### 15.1 `WM_DEVICECHANGE` registration and handling

`gui_window.c` registers a `DEV_BROADCAST_DEVICEINTERFACE_W` filter via
`RegisterDeviceNotificationW`, scoped to `GUID_DEVINTERFACE_VOLUME`
{53f5630d-b6bf-11d0-94f2-00a0c91efb8b} - a stable, publicly documented
Microsoft constant, declared directly in `gui_window.c` rather than
pulling in `<ntddstor.h>` + `<initguid.h>` (which would need `INITGUID`
defined in exactly one translation unit to avoid an unresolved external -
one known GUID value is simpler and needs no new header or link
dependency). This is done right after `CreateWindowExW()` returns in
`gui_window_run()`, by which point `WM_CREATE` has already run
(`CreateWindowExW` dispatches it synchronously) so `GWLP_USERDATA` is
already set; the returned `HDEVNOTIFY` is stored on `gui_state_t` and
released via `UnregisterDeviceNotification()` in `on_destroy`, alongside
the existing worker-thread cleanup. Registration failure is not fatal -
the window still works, just without live updates, exactly the same
"skipped, never silently wrong" degradation this project has always
preferred over a hard failure for a non-essential capability.

The new `WM_DEVICECHANGE` case in `wnd_proc` dispatches on
`DBT_DEVICEARRIVAL`/`DBT_DEVICEREMOVECOMPLETE` to `handle_device_change()`,
which does nothing but call the **existing** `populate_devices()` (guarded
by `!state->scanning`, so an in-progress scan's UI state is never
disturbed) and then, if auto-scan is enabled, run the auto-scan decision
below. No new device-filtering logic was written: `populate_devices()`
already runs every enumerated volume through
`usbs_device_is_scannable_usb()`, so broadly registering for volume
interface changes and filtering afterward, rather than filtering the
registration itself, keeps one filtering implementation instead of two.

### 15.2 Auto-scan: opt-in, pure decision function, per-identity guard

An unchecked-by-default checkbox ("Auto-scan new devices",
`BS_AUTOCHECKBOX`) - explicitly opt-in per the Phase 9 review's "no silent
action" decision (§1): scanning itself is safe and read-only, but
auto-*triggering* it without a click is still a behavior change worth
being visible and reversible. `on_autoscan_toggled()` reads `BM_GETCHECK`
into `gui_state_t.auto_scan_enabled` on every click; nothing else reads
the checkbox's live state directly.

The actual decision - should this arrival start a scan - is
`gui_should_auto_scan()` (`gui_worker.h`/`.c`), a pure function of three
booleans (`auto_scan_enabled`, `already_scanning`,
`already_auto_scanned_this_identity`) with no Win32 dependency, exhaustively
covered by `tests/test_gui_worker.c`'s
`test_should_auto_scan_decision()`. `handle_device_change()` supplies
those three booleans and does the surrounding bookkeeping: a small
fixed-capacity set (`gui_state_t.auto_scanned_identities`,
`GUI_AUTO_SCAN_TRACK_MAX` = 8 - generous for a real session, and simply
stops tracking new identities past that rather than growing a dynamic
list for an unlikely case) tracks which device identities have been
auto-scanned *since they were last seen absent*. This matters for two
reasons: a single physical insert can generate more than one
`WM_DEVICECHANGE` message (a device can expose more than one volume
interface), so the guard prevents scanning the same arrival twice; and
`auto_scan_set_prune_absent()`, called from `populate_devices()` on every
refresh, drops an identity once it is no longer present, so unplugging and
later re-plugging the *same* drive correctly auto-scans it again rather
than being silently ignored forever. Manual Scan and auto-scan now share
one launch path, `start_scan_for_device()` (factored out of what was
`on_scan_clicked()`'s body) - the only difference is how the target device
is chosen (the combo box selection vs. a specific just-arrived device),
not how the scan itself starts.

### 15.3 Dropdown selection persistence

`populate_devices()` now captures the currently selected device's
*identity* (not index) before rebuilding the list, and restores the
matching index afterward if that device is still present, falling back to
index 0 only if it is not. Previously every refresh - including a
hot-plug-triggered one - unconditionally reset the selection to index 0,
which would have yanked a manually-chosen device out from under the user
the moment any other device on the system changed state.

### 15.4 Disclaimer truncation fix

`hash_match.c`'s loaded-state disclaimer (§13's Phase 7 notes already
documented the observed truncation) now shows only the signature file's
last path component (`path_filename()`, a small static helper - no
library needed for this), not the full `--signatures` path. The full path
was never load-bearing information for a human reading the report; it was
only ever incidentally included. This is the fix, not a workaround: it
removes the unbounded-length input from the message entirely rather than
truncating more gracefully or growing `USBS_CHECK_MESSAGE_MAX` (which
would only raise, not remove, the ceiling a long enough path could still
hit).

### 15.5 Testing

`tests/test_gui_worker.c` gained `test_should_auto_scan_decision()`,
exhaustively covering `gui_should_auto_scan()`'s truth table. `tests/
test_hash_match.c`'s `test_loaded_signature_file_matches` was updated to
assert the *absence* of the scratch directory prefix in the disclaimer
(not just the presence of the filename, which the untruncated full path
would also have satisfied) - a real regression test for the fix, not just
an updated expectation.

Real-hardware verification, with two real USB devices attached during
this phase (the original ADATA drive plus a second one that arrived
between Phase 8 and Phase 9's testing):

- **Selection persistence** - confirmed directly: selected the second
  device (index 1) in the dropdown, clicked Refresh, and the selection
  remained on index 1 rather than resetting to 0.
- **Truncation fix** - confirmed end-to-end through the real CLI against
  real hardware with a deliberately constructed 227-character
  `--signatures` path (comfortably long enough that the old "full path in
  the message" format would have exceeded `USBS_CHECK_MESSAGE_MAX` and
  been cut off mid-sentence, as it was when first observed in Phase 7/8).
  The saved JSON's `hash_match_example` message came back at 158 bytes,
  well within the 256-byte limit, ending correctly at "...verify its
  provenance yourself" rather than being cut off.
- **The checkbox and its wiring** - confirmed directly: `BM_CLICK` on the
  auto-scan checkbox toggles its state and reaches `on_autoscan_toggled()`
  (verified via temporary diagnostic logging, since removed).
- **`WM_DEVICECHANGE` itself could not be verified by direct message
  injection**, and this is a real, informative finding, not a gap papered
  over: sending a synthetic `WM_DEVICECHANGE`/`DBT_DEVICEARRIVAL` to the
  real window via `SendMessageW` from an external process was rejected by
  the OS with `ERROR_INVALID_PARAMETER` before it ever reached this
  project's window procedure - Windows validates this particular
  message's parameters at the messaging layer itself (a genuine device
  arrival always carries a real `DEV_BROADCAST_HDR`-derived structure in
  `lParam`, allocated and marshaled by the OS across every recipient
  process; a bare `NULL` from an unrelated process is correctly refused).
  Constructing a fully OS-valid synthetic broadcast would need real
  cross-process memory marshaling disproportionate to what this
  verification pass warrants. The registration call itself
  (`RegisterDeviceNotificationW`) runs without error on every launch in
  this environment, and the handler code
  (`handle_device_change()`/`gui_should_auto_scan()`) is exercised in full
  by the unit test above and by manual code review, but the complete,
  genuine, OS-delivered arrival-to-auto-scan chain could not be verified
  from within this tool-execution environment - the same category of
  gap Phase 8 has for Cancel (§14.5).

**Update, closing this gap:** the user performed the manual test this
section called for - a real physical unplug and replug of a USB device
against the running GUI. The dropdown updated automatically, auto-scan
fired exactly once for the re-inserted device (confirming the
per-identity guard in practice, not just in the unit test), and the
selection-persistence fix (§15.3) held across the hot-plug-triggered
refresh. The full arrival-to-auto-scan chain is now verified end to end.

## 16. Phase 10 implementation notes

Phase 10 adds a per-user NSIS installer, built via CPack, so USB Sentinel
can be used day to day without a Developer PowerShell and a from-source
build. It touches no scanning/detection logic - only the build system
(`install()` rules, a `CPack` configuration block) and one new file,
`packaging/usbs_installer_extra.nsh`.

### 16.1 Why NSIS, and why per-user

Chosen over WiX/MSI for the same reason the GUI uses raw Win32 instead of
a framework: the smallest reasonable footprint. `cpack.exe` already ships
in the same Visual Studio / CMake tree this project has used since Phase
1 (`Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cpack.exe`).
WiX v4/v5 would additionally require installing a full .NET SDK first
(only the `dotnet` runtime shim is present on the development machine,
confirmed by checking directly rather than assumed) before the WiX CLI
itself could even be installed - a heavier prerequisite chain for no
benefit this project needs.

Per-user install (`%LOCALAPPDATA%\Programs\USB Sentinel\`) was chosen
over per-machine (`Program Files`) specifically because it matches the
`asInvoker`, no-elevation runtime model this project has held since
Phase 1 (§1) - the installer itself should not need administrator rights
any more than the scanner does.

### 16.2 A real problem: the stock CPack NSIS template does not give you per-user installs for free

Before writing any configuration, the actual template CPack uses for the
NSIS generator was read directly from the CMake installation in use here
(`Modules/Internal/CPack/NSIS.template.in`, CMake 3.31.6) rather than
assumed from general knowledge of CPack - CPack's NSIS behavior has
changed across versions and is easy to get wrong from memory.

That read turned up a real, load-bearing problem. The stock template:

- Sets `RequestExecutionLevel admin` unconditionally (line 41) - every
  CPack NSIS installer requests elevation by default, regardless of
  install location.
- In its `.onInit` function (run before any wizard page is shown), reads
  `UserInfo::GetAccountType` and, if the installing account is an
  Administrator or Power User (the common case on a personal machine) -
  or if the account-type check fails at all - silently **redirects the
  install directory to `$DOCUMENTS\<PackageInstallDirectory>`** instead
  of the configured `CPACK_NSIS_INSTALL_ROOT`, and calls
  `SetShellVarContext all`, which points Start Menu shortcut creation and
  the `SHCTX` registry pseudo-hive (see below) at the all-users locations
  (`HKLM`, the all-users Start Menu) instead of the current user's.

Left alone, `CPACK_NSIS_INSTALL_ROOT` would only take effect for accounts
the template classifies as genuinely standard (non-admin, non-power) -
silently producing an elevated, all-users, `Documents`-folder install on
most personal machines, directly contradicting the per-user,
no-elevation decision this phase was built around.

### 16.3 The fix

All of the following lives in `packaging/usbs_installer_extra.nsh`,
pulled in via `CPACK_NSIS_DEFINES` as a single `!include` line (see
§16.5 for why it is a real file and not an inline CMake string):

- **`RequestExecutionLevel user`**, declared a second time after the
  stock template's own `admin` declaration. NSIS treats this class of
  single-value script attribute (like `Name`, `OutFile`, `InstallDir`) as
  a plain sequential directive, not a `!define` guarded against
  redefinition - the later declaration in the compiled script wins. This
  is a widely-used, documented workaround for exactly this CPack
  limitation, and is confirmed indirectly here by inspecting the
  generated intermediate script rather than only trusting NSIS's own
  (silent, on this specific point) reference documentation.
- **`!macro UsbsFixInstallContext`**, invoked via
  `CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS` (runs at the top of the install
  Section, after every wizard page including Directory has already run,
  but before any file is copied). It forces `SetShellVarContext current`
  unconditionally, and corrects `$INSTDIR` **only if it still equals the
  stock template's `$DOCUMENTS\USB Sentinel` fallback** - i.e. only when
  the admin/power-user redirect actually fired and the user did not
  deliberately browse to a different folder on the Directory page. A
  real, deliberate user choice made on that page is never overridden;
  only the template's own wrong default is corrected. An earlier,
  simpler version of this fix unconditionally overwrote `$INSTDIR`
  regardless of what the user had chosen - caught and corrected before
  ever being run, since it would have silently discarded a manual
  "Browse..." choice.
- **`!macro UsbsUninstallExtra`**, invoked via
  `CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS`, re-applies
  `SetShellVarContext current` for the uninstaller (which runs its own,
  separately-coded admin/power-user detection in `un.onInit` and would
  otherwise look in the all-users locations for shortcuts and registry
  entries this per-user install never wrote there), and removes the
  optional Startup shortcut unconditionally (deleting a file that does
  not exist is a harmless no-op in NSIS).

This works without ever touching `HKLM` because the stock template's
Apps & Features registration (`WriteRegStr SHCTX ...`, confirmed by
reading the template directly rather than assumed) goes through NSIS's
`SHCTX` pseudo-hive, which resolves to `HKCU` or `HKLM` following
whatever `SetShellVarContext` last set - forcing `current` is sufficient
for the app to register correctly in the per-user Apps & Features list.
`CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL` is deliberately left off:
the "detect a previous install" check in `.onInit` reads from a bare
`HKLM` key (not `SHCTX`), so with a per-user, `HKCU`-registered install
that check would never find anything - enabling it would configure a
feature that silently never engages.

### 16.4 Opt-in "launch at login"

Implemented by repurposing the Modern UI 2 finish-page "Show Readme"
checkbox to call a function instead of opening a file - a documented
NSIS technique (`!define MUI_FINISHPAGE_SHOWREADME` with no value,
`MUI_FINISHPAGE_SHOWREADME_FUNCTION` naming the function,
`MUI_FINISHPAGE_SHOWREADME_NOTCHECKED` for unchecked-by-default),
confirmed against NSIS's own Modern UI documentation before use rather
than assumed. `UsbsCreateStartupShortcut` is only invoked by NSIS when
the box is checked at finish, and does exactly one thing: creates a
`.lnk` in the current user's Startup folder (`$SMSTARTUP`) pointing at
`usb-sentinel-gui.exe`. No tray icon, no scheduled task, no service, and
no scan - it opens the same window a manual launch would, consistent
with §1's no-silent-action posture and with how the GUI's own "Auto-scan
new devices" checkbox (§15.2) was scoped. The two checkboxes are
independent: this one only controls whether the window opens itself at
login, not what happens once it is open.

### 16.5 A CPack limitation worth documenting: CPackConfig.cmake does not round-trip backslashes or quotes

The first implementation embedded the NSIS customizations directly as
CMake string variables (`CPACK_NSIS_DEFINES`,
`CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS`, etc.), using CMake bracket
arguments (`[[...]]`) specifically to avoid CMake's own string-escaping
rules for the embedded backslashes in Windows paths like
`$LOCALAPPDATA\Programs`.

This configured without error, but running `cpack` itself failed with
CMake parse errors like `Invalid escape sequence \U` and `\P` - inside
`CPackConfig.cmake`, a file CPack generates at configure time by dumping
every `CPACK_*` variable back out as a plain `set(VAR "value")` line, to
be `include()`-d by the standalone `cpack` executable. That dump does not
re-escape backslashes (or, discovered next, embedded double quotes) when
writing a string value back out as a quoted literal - so a value that
CMake's own bracket-argument parsing accepted happily in the source
`CMakeLists.txt` came back as an invalid, unparsable literal on the
second pass, through a file this project never directly authored.
Switching the backslash-heavy paths to forward slashes where CPack
itself consumes them directly (`CPACK_NSIS_INSTALL_ROOT`) fixed the
first errors; embedding an escaped `\"..\"` in `CPACK_NSIS_DEFINES` then
surfaced the same class of bug for quotes ("Argument not separated from
preceding token by whitespace").

The actual fix was not more careful escaping - a second and third
attempt at doubling backslashes to survive two rounds of parsing would
have been fragile and hard to visually verify - but moving all the
NSIS-specific script into a real file, `packaging/usbs_installer_extra.nsh`,
referenced from `CMakeLists.txt` by a single unquoted, space-free
`!include` line built from `CMAKE_CURRENT_SOURCE_DIR` (which CMake always
renders with forward slashes, confirmed by inspecting the generated
`CPackConfig.cmake` directly). This sidesteps the round-trip entirely -
no `CPACK_NSIS_*` variable in this project's configuration contains a
backslash or an embedded quote - and is arguably the better design
regardless of the bug: the NSIS script is now real, reviewable code
instead of a string embedded inside a CMake variable.

### 16.6 Uninstall safety

`%LOCALAPPDATA%\USBSentinel\` (scan history under `scans\`, and the
user's own `signatures.txt`) is untouched by uninstall **by
construction, not by a special-cased exclusion**: nothing this installer
or uninstaller does references that directory tree at all. The installed
program files live entirely under
`%LOCALAPPDATA%\Programs\USB Sentinel\`, a disjoint path, and the
uninstaller (like every CPack-generated NSIS uninstaller) only removes
`$INSTDIR` and the specific shortcuts/registry keys this installer itself
created (see §16.3). This is the same "never destroy user data" posture
as the read-only scanning guarantee (§2), extended to uninstall.

### 16.7 Testing

Verified in this environment: `install()` rules added for both
executables (`RUNTIME DESTINATION bin`); a clean, from-scratch Debug and
Release rebuild after every packaging-related `CMakeLists.txt` change,
67/67 targets, zero warnings under `/W4 /permissive- /WX`, 16/16 tests
passing in both configurations - the packaging work touches no compiled
code, and this confirms it introduced no regressions. `cmake --preset
x64-release` reconfigures cleanly with zero CMake warnings of any kind.
Running `cpack` from the Release build directory now fails **only** at
the expected, legitimate point - `CPack Error: Cannot find NSIS compiler
makensis` - with no CMake dev warnings and no parse errors beforehand,
which confirms the entire CPack configuration (including the
`CPackConfig.cmake` round-trip, §16.5) is correct up to the point where
it genuinely needs the external NSIS tool. The generated
`CPackConfig.cmake` was read directly to confirm the exact rendered
values (`CPACK_NSIS_DEFINES`, `CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS`,
`CPACK_PACKAGE_FILE_NAME` = `USB Sentinel-0.1.0-win64`) rather than
assumed from the CMake source alone.

**Update: NSIS became available and closed most of this section's original
gap** (it had been attempted via an automated download that SourceForge's
own site blocked for non-browser clients; the user installed it directly
and it was found at `C:\Program Files (x86)\NSIS`). With a real
`makensis` in hand, `cpack` now produces a genuine
`USB Sentinel-0.1.0-win64.exe`, and two things previously listed as
unverified are now confirmed directly rather than assumed:

- **`RequestExecutionLevel user`'s second-declaration-wins behavior**
  (§16.3) - confirmed by searching the compiled installer's raw bytes for
  its embedded manifest, which reads
  `requestedExecutionLevel level="asInvoker"` (NSIS's manifest term for
  `user`). The later declaration in `usbs_installer_extra.nsh` does win
  over the stock template's `admin`.
- **The `!include` path bug** (§16.8, a real bug this time, found from
  the user's report) - fixed and reconfirmed by inspecting the generated
  `project.nsi` line by line after the fix, not just by a successful
  `cpack` exit code.

**Still not verified, and stated plainly**: the actual install/uninstall
wizard flow (Directory page, Start Menu creation, the finish-page
checkbox and the Startup shortcut it creates, and uninstall) has not been
run - compiling successfully and inspecting the compiled script both
confirm the installer is well-formed, not that running it behaves as
designed end to end. That is the same category of gap as Cancel (§14.5)
and, until Phase 9's user-run test closed it, `WM_DEVICECHANGE` delivery
(§15.5) - deliberately left to the user's own environment rather than
executed here, consistent with treating an actual install/uninstall as
the kind of action that affects real system state.

### 16.8 A real bug from the field: `!include` rejects forward slashes

The first `cpack` run in the user's own environment (once NSIS was
actually installed there) failed differently from anything reproduced
here up to that point:

```
!include: could not find: "C:/Projects/USB-Sentinel/packaging/usbs_installer_extra.nsh"
Error in script "project.nsi" on line 43 -- aborting creation process
```

The path shown is absolute and correctly resolved by `CMAKE_CURRENT_SOURCE_DIR`
- this was not the working-directory problem it first looked like. Root
cause, confirmed by direct isolation testing once `makensis.exe` was
located on the same machine (`C:\Program Files (x86)\NSIS`): four minimal
`.nsi` files, one per combination of forward/backslash and quoted/
unquoted, compiled directly with `makensis`. Both forward-slash variants
failed with the exact same "could not find" error regardless of quoting;
both backslash variants succeeded. `!include` is a compile-time directive
handled by NSIS's own script compiler, unlike the runtime path
instructions this project already uses (`CreateShortCut`, `StrCpy`,
`Delete`) which go through Win32 APIs that *are* tolerant of `/` - the
assumption that NSIS is uniformly slash-tolerant, made when §16.5's fix
was written, was wrong specifically for this one directive.

Switching the `!include` line back to a backslash path would reintroduce
exactly the `CPackConfig.cmake` round-trip bug §16.5 already fixed (a raw
backslash in a `CPACK_NSIS_*` value does not survive CPack's own
non-re-escaping dump-and-reload). The two constraints only look like they
conflict: `!include` needs a real backslash in the *final* compiled
script, while what actually breaks the round-trip is a value that
contains only a *single* backslash at the point CPack dumps it verbatim.
A value containing a *doubled* backslash survives: CPack writes it out
unchanged as `\\`, and CMake's normal string parsing on the second load
(`cpack` reading its own generated `CPackConfig.cmake`) collapses `\\`
back down to one real backslash - which is exactly what `!include` needs.

The fix, built with `file(TO_NATIVE_PATH ...)` and `string(REPLACE "\\"
"\\\\" ...)` rather than hand-typed backslash counts (four literal
backslashes to get two stored, easy to miscount and hard to verify by
eye): `CPACK_NSIS_DEFINES` now escapes the include path this way, and
`CPACK_NSIS_INSTALL_ROOT` was changed the same way as a related fix (see
below) rather than left as a second, easy-to-miss instance of the same
class of bug. Verified in three concrete steps rather than trusting a
clean `cpack` exit code alone: the CMake-stored value, the text CPack
actually dumps into `CPackConfig.cmake` (confirmed doubled, `\\`), and
the final compiled `project.nsi` (confirmed single-backslash, matching
the isolation test's known-working form) - each read directly.

**A second issue, found proactively while investigating the first, not
reported by the user**: `CPACK_NSIS_INSTALL_ROOT` was still set to
`$LOCALAPPDATA/Programs` (forward slash), which compiles without error
into `InstallDir "$LOCALAPPDATA/Programs\USB Sentinel"` - a *mixed*
separator string. `UsbsFixInstallContext` (§16.3) happens to overwrite
`$INSTDIR` with a clean, hand-typed, all-backslash value before any file
is written, but only on the branch that fires for an Administrator/Power
User account. For a genuinely standard account, that mixed-separator
string would be the one actually used for every file write and
`CreateDirectory` call. Rather than assume Win32's general `/`-tolerance
extends cleanly to a *mixed*-separator string in every NSIS runtime
instruction that touches `$INSTDIR` - having just been wrong once already
in this same investigation about NSIS's slash tolerance - it was
eliminated instead of trusted: `CPACK_NSIS_INSTALL_ROOT` now goes through
the same escaped, all-backslash construction, confirmed by reading the
compiled `InstallDir` line afterward (`"$LOCALAPPDATA\Programs\USB
Sentinel"`, single separator style throughout).

### 16.9 A second real bug from the field: files and the Start Menu shortcut disagreed on where they were

With the `!include` fix in place, the user ran the real installer and it
installed without elevation - but launching from the Start Menu produced
Windows' "Problem with Shortcut... has been modified or moved" dialog.
The shortcut and the files it pointed at had landed in two different
places.

Root cause, found by reading the stock template's install Section body
in full (`Section "-Core installation"`, not just the single line around
the `CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS` placeholder examined for the
first bug):

```
Section "-Core installation"
  SetOutPath "$INSTDIR"
  @CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS@
  @CPACK_NSIS_FULL_INSTALL@
  ...
  CreateShortCut ... "$INSTDIR\bin\usb-sentinel-gui.exe"
```

`@CPACK_NSIS_FULL_INSTALL@` (confirmed by reading the actual compiled
`project.nsi`, not assumed) expands to one line: `File /r
"${INST_DIR}\*.*"` - a single recursive copy of the whole staged tree.
`SetOutPath` is not a live reference to `$INSTDIR`; it evaluates the
variable once, at the moment it runs, and that resolved string is where
every subsequent `File` command writes until the next `SetOutPath`. The
bare `SetOutPath "$INSTDIR"` at the top of the section runs *before*
`CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS` - i.e. before
`UsbsFixInstallContext` corrects `$INSTDIR` for an Administrator account
- so it snapshots the *pre-correction* value (the stock template's
`$DOCUMENTS\USB Sentinel` fallback). The `File /r` that follows writes
there. Every later use of `$INSTDIR` as a plain string argument -
`CreateShortCut`, `WriteUninstaller`, the registry entries - re-reads the
variable fresh at that point and correctly gets the corrected value.
Files in one directory, shortcut pointing at another: exactly the
reported dialog.

Fixed with one added line at the end of `UsbsFixInstallContext`: another
`SetOutPath "$INSTDIR"`, re-snapshotting the output path from the
now-corrected variable, immediately before `@CPACK_NSIS_FULL_INSTALL@`'s
`File /r` runs.

Verified beyond "it still compiles" this time, since that was already
true of the original, broken ordering: two minimal, disposable, silent
NSIS installers were built and *actually run* (writing only into throwaway
`%TEMP%` subdirectories, never touching a real install location) -
one reproducing the exact buggy sequence (`SetOutPath` /
`StrCpy $INSTDIR` / `File`), one with the fix
(`SetOutPath` / `StrCpy $INSTDIR` / `SetOutPath` / `File`). The buggy
version's file landed at the pre-correction path and not the corrected
one; the fixed version's file landed at the corrected path and not the
pre-correction one - confirmed directly with `Test-Path` on all four
possible locations, not inferred from exit codes. This is a stronger
class of verification than §16.8's (which stopped at reading the
compiled script), because it exercises actual NSIS runtime semantics
rather than only the compiler accepting the syntax.

## 17. Phase 11 implementation notes

Phase 11 is a presentation-layer phase: a readable, sectioned report with
colour-coded threat highlighting, a determinate progress bar, and an
application icon. It touches no scanning, detection, storage or reporting
logic - `usbs_report_render_text()`, `usbs_report_build_json()` and
`usbs_report_build_csv()` are all unchanged, and so is every byte the CLI
prints. New files: `src/gui/gui_report_view.{h,c}`,
`src/gui/usbs_gui_resource.h`, `resources/usb_sentinel_gui.rc.in`,
`resources/make_icon.ps1`, `resources/usb-sentinel.ico`,
`tests/test_gui_report_view.c`.

### 17.1 RichEdit, not EDIT

A Win32 `EDIT` control has exactly one text colour for its entire
content: `WM_CTLCOLOREDIT` hands back a single foreground colour and a
single background brush for the whole control, and `EDIT` does not
support owner-draw. Colouring one finding red inside an `EDIT` is
therefore not awkward, it is impossible short of writing a replacement
control from scratch - which would mean hand-implementing wrapping,
scrolling, selection and caret handling, far more new surface than this
phase is worth.

RichEdit 4.1 (`MSFTEDIT_CLASS`, from `Msftedit.dll`) supports per-run
formatting through `CHARFORMAT2W` + `EM_SETCHARFORMAT(SCF_SELECTION)`,
costs one runtime `LoadLibraryW`, and adds no link-time dependency. It
has shipped with Windows since XP SP1.

Four mechanical details that are each easy to get wrong, handled
explicitly in `create_results_control()`/`results_render()`:

- **Text limit.** A RichEdit defaults to roughly a 32 KB limit and
  silently truncates beyond it. `EM_EXLIMITTEXT` raises it. A report
  from a device with many findings can plausibly exceed 32 KB, and the
  failure mode - a report that just stops mid-sentence - is exactly the
  kind of quiet wrongness this project treats as a defect.
- **Background.** `ES_READONLY` otherwise picks a system colour that
  does not match the paper colour the styles are designed against;
  `EM_SETBKGNDCOLOR` sets it explicitly.
- **Autoscroll and flicker.** Every `EM_REPLACESEL` scrolls the caret
  into view, so a report built from ~200 runs would scroll ~200 times
  and repaint each time. `WM_SETREDRAW` is turned off for the build and
  back on once, followed by an explicit scroll back to the top.
- **Undo.** The inserts accumulate an undo buffer a read-only control has
  no use for; `EM_EMPTYUNDOBUFFER` drops it.

`_RICHEDIT_VER` must be defined as `0x0500` *before* including
`richedit.h`: the header's own default is `0x0300`, under which
`MSFTEDIT_CLASS` is simply not declared. Because this file has a
plain-`EDIT` fallback path, forgetting that define would not fail the
build - it would silently compile to the degraded path, and nobody would
notice until they wondered why nothing was coloured.

**Fallback.** If `Msftedit.dll` cannot be loaded, or the control fails to
create, the window creates a plain `EDIT` and renders the same report
text into it without colour (`rich_sink_t.rich`). A colourless report is
a degraded experience; a blank results pane would be a broken one. Same
capability-based-degradation stance as §7.3.

### 17.2 A third formatter, not a second source of truth

`gui_report_view.c` walks the same `usbs_scan_result_t` the JSON, CSV and
text renderers walk, and emits `(style, UTF-8 text)` runs through a
callback. It is a *third formatter over one structure* - the arrangement
§7.4 already describes - not a second model of what a scan found.

It is deliberately free of `<windows.h>`, HWNDs and colour values. It
emits *semantic* styles (`GUI_STYLE_THREAT`, `GUI_STYLE_GOOD`, ...) and
`gui_window.c` owns the palette. That is what lets
`tests/test_gui_report_view.c` assert on meaning - "the finding text is
emitted in the threat style" - without a window, a control, or an RGB
value: the same pure-core/thin-wrapper split as `gui_worker.c` (§14.3)
and `usbs_hash_match_lookup()` (§11.3).

Non-ASCII punctuation (bullets, middle dots) is written as explicit UTF-8
byte escapes rather than as literal characters. MSVC reads a BOM-less
source file in the system ANSI code page, so literal UTF-8 bullets would
be mangled into mojibake on any machine whose code page is not 65001 - a
defect that appears only on someone else's computer.

### 17.3 When the GUI is allowed to say "All Clear"

`GUI_VERDICT_CLEAN` - the only green state - requires *all* of:

- the scan completed (`USBS_SCAN_COMPLETED`), and
- no check was skipped, and
- no check failed, and
- nothing above `USBS_SEVERITY_INFO` was found.

Anything else with no findings is `GUI_VERDICT_INCOMPLETE`, styled as a
warning, and it says which of the three reasons applies. This is §7.3's
"a silent capability gap is worse than no report" carried into the UI,
and it matters *more* here than in a text report: a colour is read at a
glance and believed, often without the sentence beside it being read at
all. Green over a cancelled scan would be a false statement made in the
most persuasive form the product has.

Severity outranks completeness: a high-severity finding collected before
a scan was cancelled still yields `GUI_VERDICT_THREAT`, because burying
it under "incomplete" would demote the single most important thing on
screen.

One consequence worth stating because it looks like an oversight: the
scan's own `Outcome: Completed` line is **not** styled green. Green is
reserved throughout the view for exactly one claim - "nothing bad was
found" - so that green never needs its surrounding context read to be
understood. A scan that mechanically finished while finding a
known-malicious file is not good news, and a green word on a red-bannered
report is precisely the mixed signal that gets misread. This was caught
by a test asserting "nothing green anywhere in a threat report", which
failed on its first run against the obvious `completed ? GOOD : WARNING`
implementation.

### 17.4 The progress bar, and why a percentage is honest now

§14 used a marquee, reasoning that "there is no total file count to make
it determinate - a fake percentage would be dishonest data". The
principle was right; the premise was incomplete. `usbs_device_t` already
carries `capacity_bytes` and `free_bytes`, both straight from
`GetDiskFreeSpaceExW`, so **bytes in use** is a real figure the
filesystem reports, and `usbs_scan_progress_t.bytes_scanned` can be
measured against it.

It is an estimate, not an identity: the denominator includes filesystem
metadata and slack, and the numerator omits files the walk could not
open. So the ratio is clamped at 100% and forced monotonic - a bar that
stalls just short of the end is acceptable, a bar that jumps backwards
looks broken - and `progress_end()` lands it on exactly full before
hiding it. Where the denominator is unavailable (`capacity_bytes == 0`,
or `free_bytes > capacity_bytes`), the bar reverts to a marquee rather
than inventing a number. That is §14's principle preserved and applied to
better information, not overturned.

`PBM_SETPOS` is silently ignored while `PBS_MARQUEE` is set, so switching
modes edits the window style via `SetWindowLongPtr(GWL_STYLE)` rather
than only sending a different message.

### 17.5 A throttle must not decide what the report says happened

Phase 8's progress callback throttles UI updates to ~10/second so a drive
with many files cannot flood the message queue. That is correct and
unchanged. Phase 11 initially reused the last *posted* snapshot as the
finished report's "files scanned" figure. That was wrong, and wrong in
the way that matters most for a security tool: it under-reports coverage.

The walk is metadata-only (§10), so a 631-file volume completes inside
the *first* 100 ms throttle window. Every subsequent progress callback
was dropped, and the window confidently reported **"1 file(s), 12 B
examined"** for a scan that had actually covered **631 files and
14,870,278,601 bytes**. The scan itself was correct throughout - the
saved JSON/CSV for that very same scan carried the right numbers - only
the on-screen summary lied.

This was not found by reading the code. It was found by running the real
GUI against the real device and comparing the window against the report
it had just saved for that same scan; the discrepancy is invisible from
either artifact alone. Same lesson as §14.5's `tmpfile_s()` bug: a GUI
can be confidently and specifically wrong while every test passes.

Fixed by recording the snapshot on *every* callback, before the throttle
decides whether to post it, and reading it on the UI thread only after
`WaitForSingleObject()` on the worker has returned - thread exit
happens-before a successful join, so the cross-thread read needs no
further synchronization. The rule: throttling may drop a repaint, never a
fact.

### 17.6 Icon and resources

`resources/usb-sentinel.ico` is committed (it is a build input for both
the executable's `.rc` and the NSIS installer) but *generated* by
`resources/make_icon.ps1`, so the artwork is reviewable as code rather
than as an opaque binary. Seven sizes (16-256) are each rendered natively
at their own resolution rather than downscaled from one large bitmap, so
the small entries Explorer and the taskbar actually use stay crisp.
Sub-256 entries are BMP/DIB payloads with the doubled `biHeight` and the
(all-zero, but mandatory) AND mask the format requires; the 256 entry is
PNG, as every modern icon toolchain writes it.

Verified with the real Win32 loader (`LoadImageW` + `GetIconInfo`) at
every size rather than with `System.Drawing.Icon`, which silently falls
back to the 128 entry when asked for 256 - a .NET limitation that, taken
at face value, looks exactly like a malformed file.

The `.rc` is generated by `configure_file` so both the icon and the
shared id header can be referenced by **absolute** path: the resource
compiler then needs no include directory of its own. Backslashes are
doubled because a backslash is an escape character inside an RC string
literal. Same escaping discipline - and the same refusal to assume a tool
is separator-tolerant - that §16.8 arrived at the hard way.
`enable_language(RC)` is guarded by `if(WIN32)` so a non-Windows
configure of the portable core still succeeds.

For the installer, `CPACK_NSIS_MUI_ICON`/`MUI_UNIICON` need the *doubled*
backslash treatment for the `CPackConfig.cmake` round trip described in
§16.5; confirmed by reading the generated `project.nsi` and watching the
doubled values collapse back to single backslashes. Note that CPack maps
`CPACK_NSIS_MUI_UNIICON` onto NSIS's differently-spelled `MUI_UNICON`.
`CPACK_NSIS_INSTALLED_ICON_NAME` points the Settings > Apps entry at the
installed executable, so there is one icon with one source.

### 17.7 Not done, deliberately

**Per-monitor DPI awareness.** The window uses unscaled pixel metrics and
has no DPI-awareness manifest, so Windows bitmap-scales it on a high-DPI
display: usable, slightly soft. Doing this properly needs a real
application manifest plus a full relayout on `WM_DPICHANGED` and
DPI-scaled fonts and metrics throughout - a larger change than the rest
of this phase combined, and one that would want its own verification pass
on an actual high-DPI monitor.

**A report history browser.** Still declined, for the third time, for the
same reason as §14.4 and Phase 7: it needs a JSON-to-struct deserializer
that does not exist. Note that `gui_report_view.c` would now make the
*rendering* half trivial, which makes it more tempting, not less - the
missing piece is still the parser.

The window did gain a resizable frame (`WS_OVERLAPPEDWINDOW` plus one
`layout_controls()` called from `WM_SIZE`, with a minimum enforced in
`WM_GETMINMAXINFO`). A fixed 580x500 frame made a long report needlessly
hard to read, and a single layout function is a smaller change than the
alternative of guessing at a taller fixed size.

## 18. Phase 12: code hardening and edge cases

Not a new feature phase. The Phase 12 review named the codebase as
functionally complete and asked for a hardening pass before v1.0: an
AddressSanitizer build, a static-analysis (`/analyze`) audit triaged to
fixed-or-documented, explicit lifetime handling for two loose ends Phase
11 left behind (the `LoadImageW` icon handles, the three progress-throttle
statics), and grown malformed-input/fuzz batteries for `signature_list`
and `json`, plus two named stress tests. No scanning/detection behavior
changed; every fix here is either a genuine defect this pass found or an
explicit lifetime/ownership tightening.

### 18.1 ASan build (`x64-asan` preset)

MSVC's native `/fsanitize=address`, not a second toolchain: `USBS_ASAN`
(CMakeLists.txt) adds the flag to `usbs_options` and strips `/RTC1` from
the Debug flags, since MSVC refuses to combine `/RTC1` with
`/fsanitize=address` and ASan is the strictly stronger check of the two.

**Linking needed more than the compile flag.** CMake's Ninja/MSVC
generator links via `link.exe` directly rather than through the `cl.exe`
driver, so the automatic ASan-runtime-library selection `cl.exe` normally
performs at link time does not happen here. Verified empirically against
this toolchain's actual `VC\Tools\MSVC\<ver>\lib\x64` contents (not
assumed from documentation): the correct dynamic-CRT runtime import
library per configuration
(`clang_rt.asan_dbg_dynamic-x86_64.lib`/`clang_rt.asan_dynamic-x86_64.lib`),
one shared runtime-thunk library pulled in with `/wholearchive:` (Microsoft's
documented workaround for a DLL-initialization-order issue under `/MD`/`/MDd`),
and `/INCREMENTAL:NO` (incompatible with ASan's instrumentation) are all
added explicitly in `CMakeLists.txt` rather than assumed to happen
automatically.

**A real environment finding, not a build bug:** an ASan-built executable
run outside a `vcvars`-loaded shell fails immediately with
`STATUS_DLL_NOT_FOUND` (`clang_rt.asan_dynamic-x86_64.dll` is not on `PATH`
by default) - confirmed directly, then resolved by adding
`VC\Tools\MSVC\<ver>\bin\Hostx64\x64` to `PATH` before running. This has no
effect on a normal Debug/Release build, which links no ASan runtime at
all; it only matters for someone running an `x64-asan` binary directly
rather than through `ctest --preset x64-asan`.

**Verification.** `ctest --preset x64-asan`: 17/17, zero ASan reports.
Then, with the real ADATA USB device attached (the same one used since
Phase 4): the CLI (`usb-sentinel.exe scan E:`) completed cleanly under
ASan (916 files, 4,759,379,016 bytes, exit 0, no ASan report); the GUI
(`usb-sentinel-gui.exe`) was driven through a real Scan click via Windows
UI Automation - `AutomationElement.FromHandle` resolved every control to
`ControlType.Pane` rather than a proper Button/Text type (this
environment's UIA-to-Win32 bridge did not expose `InvokePattern`), worked
around by reading each control's real native `HWND` via
`AutomationElement.Current.NativeWindowHandle` and driving it directly
with `SendMessage(BM_CLICK)`/`WM_CLOSE` - and completed a full scan
("Scan complete - 1 finding(s) across 5 check(s)", the same
`hash_match_example` EICAR-fallback finding the CLI's own scans of this
device have shown since Phase 4) and closed cleanly, exit 0, no ASan
report. Note ASan's actual coverage claim here: Windows ASan targets heap
memory-safety (overflows, use-after-free), not GDI/USER handle leaks - it
would not by itself have caught the icon-handle issue in §18.3; that one
needed the `/analyze` pass and inspection instead.

### 18.2 `/analyze` (PREfast) audit (`x64-analyze` preset)

`USBS_ANALYZE` adds `/analyze /analyze:external-` (the latter keeps
PREfast from reporting inside angle-bracket system/SDK headers - this
project's own code is what the audit is for). Full clean build across
every target, triaged warning-by-warning; the closed list:

| Location | Diagnostic | Disposition |
| --- | --- | --- |
| `json.c`, `\u`-escape decode (two sites) | C6308: `buf = realloc(buf, ...)` overwrites `buf` before the NULL check, leaking the original block on OOM | **Fixed** - both sites now use a `grown` temporary and `free(buf)` on failure, matching the pattern already used two lines below in the same function |
| `json.c`, `usbs_json_free()` (object case) | C6001: "using uninitialized memory" for `items[i].key` | **False positive, documented and suppressed** (`#pragma warning(suppress:6001)`, with the reasoning inline) - PREfast cannot see that `object_push()` always sets `.key` and `.value` together before incrementing `.count`, so every index below `.count` is genuinely initialized; verified by inspection, not assumed |
| `hash_match.c`, `hash_match_on_file()` | C6262: 66,468 bytes of stack (a `unsigned char buf[65536]` read-chunk local) | **Fixed** - heap-allocated (`malloc`/`free` around the read loop), the same pattern `lnk_inspect.c` already uses for its own read buffer |
| `main_gui.c`, `wWinMain` | C28251: annotation mismatch against the SDK's own `wWinMain` prototype (`winbase.h`) | **Fixed** - the definition now carries the same `_In_`/`_In_opt_` SAL annotations as the SDK declaration |
| `gui_window.c` | (none) | Confirms the §18.3/§18.4 changes below compile clean under `/analyze`, not just under the ordinary warning set |
| `test_gui_report_view.c`, six render tests | C6262: ~98-99 KB of stack (a `capture_t` local with three 32 KB capture buffers) | **Reviewed, not changed** - test-only code, never shipped, runs single-threaded on the default 1 MB test-process stack with no recursion; converting a test fixture to heap allocation purely to satisfy the analyzer would add complexity for no real safety benefit |
| `test_scanner.c`, `test_locked_files_do_not_affect_traversal()` | C6001: "using uninitialized memory" for `handles[BYTE:0]` | **Reviewed, not changed** - false positive: `USBS_CHECK` (tests/test_util.h) never aborts on failure, so every `handles[i]` is unconditionally assigned by `CreateFileW` in the first loop before the second loop's `CloseHandle(handles[i])`, regardless of whether that call succeeded (`INVALID_HANDLE_VALUE` is itself a defined value, not indeterminate memory) |

Debug and Release rebuilt and retested clean afterward (17/17, zero
regressions) - the two production fixes above changed real code, not just
analyzer-satisfying noise, so they needed the same verification any other
change in this project gets.

### 18.3 Icon handle lifetime

`register_class()` (`gui_window.c`) calls `LoadImageW()` twice with no
`LR_SHARED` flag, so each call returns a private `HICON` this process
owns - previously never freed, relying on process-exit cleanup. Since this
process creates exactly one window for its entire lifetime, "leak until
exit" was harmless in practice, but PREfast's Phase 12 pass and this
review's explicit ask both treated it as worth closing rather than
documenting away.

`register_class()` now takes `HICON *out_icon_large, HICON *out_icon_small`
out-parameters; `gui_window_run()` holds them and calls `DestroyIcon()` on
each (if non-`NULL`) after the message loop ends, and on every early-return
path before that point too. The *shared* system fallback
(`LoadIconW(NULL, IDI_APPLICATION)`, used when `LoadImageW` fails) is
never passed to `DestroyIcon` - only the two out-parameters are, and they
are `NULL` exactly when that fallback was the one actually in use, so
there is no risk of double-destroying or destroying a handle this process
does not own.

### 18.4 The three Phase 11 progress-throttle statics moved into `gui_state_t`

`s_last_progress_tick`, `s_final_progress`, and `s_have_final_progress`
(added in Phase 11, §17.5) were file-scope statics rather than fields on
the per-scan `gui_state_t`. Correct today - only one scan and one window
exist at a time - but a static's lifetime is the *process*, not the scan,
which is exactly the kind of coupling that becomes a real bug the day a
second window or a queued-scan feature is added, and cheapest to fix while
nothing yet depends on the wrong scope.

Moved verbatim into `gui_state_t` with no behavior change: `gui_on_progress()`'s
`progress_ctx` is now the `gui_state_t*` (previously the raw `HWND`,
recovered from `state->hwnd` instead), so the worker thread writes
directly into the state its own scan owns. The safety argument from §17.5
is unchanged, just re-anchored: only one scan runs at a time, so these
fields still need no synchronization; the worker thread writes them, the
UI thread reads them in `handle_scan_done()` only after
`WaitForSingleObject()` has joined that thread, and thread exit
happens-before a successful join.

### 18.5 Extended fuzzing and stress tests

**`tests/test_signature_list.c`**: a wider malformed-line battery (hash
too short/long, invalid hex digit, empty size field, an oversized size
field rejected by the 32-byte line-buffer cap, trailing garbage after a
numeric size, whitespace-only and indented-comment lines) beyond the
handful `test_malformed_lines_skipped_good_lines_kept()` already covered;
CRLF line endings and a file whose last line has no trailing newline at
all; duplicate entries (both load, neither is deduplicated - documented
actual behavior, not assumed); a 4,000-entry stress load with 80 groups of
50 entries deliberately sharing one size each, to exercise the
size-bucketed lookup's "scan the short same-size run" step at real scale
rather than the 1-2 entries the original tests used; and a 200-trial fixed-seed
random-binary fuzz sweep asserting the loader never crashes or fails on
arbitrary bytes (malformed lines are always skipped, never fatal, per
§12.2's original design).

**`tests/test_json.c`**: an extended malformed-input battery (truncated
and invalid `\u` escapes, an unknown escape letter, doubled/lone number
signs, two decimal points, an exponent with no digits, mismatched closing
brackets, empty-comma containers, a truncated literal, raw binary garbage,
and two concatenated documents); a depth-limit test using nested
*objects* rather than only arrays, including an exact-boundary case (31
levels succeeds, 40 fails) - which caught a real off-by-one in the test
itself, not the parser: the depth check in `parse_value()` runs on *every*
call, including a leaf value's own, so an object chain's innermost literal
is one level "deeper" than the same count of empty, leaf-free nested
arrays; a 3,000-repetition stress test forcing the `\u`-escape buffer
through both fixed realloc sites from §18.2 many times over (the ASCII and
2-byte-UTF-8 branches), verifying the *fix* still decodes correctly rather
than merely not leaking; a 5,000-element wide (not deep) document
round-tripped through the writer and reader together; and a 500-trial
fixed-seed random-binary fuzz sweep against the reader.

Every fuzz/stress test above uses a **fixed seed**, not a time-based one:
a failure needs to be reproducible on the next run, not a one-time report
that cannot be chased down.

**`tests/test_scanner.c`**: `test_deep_nesting_stops_at_scan_max_depth()`.
`USBS_SCAN_MAX_DEPTH` (scanner.c) is 64, and `walk_dir()`'s guard is
`depth > 64`, so a directory is still opened at depth 64 (the 65th
directory in a chain rooted at depth 0, which is what `usbs_scanner_scan()`
starts at) and refused only from depth 65 onward - a boundary easy to get
off-by-one on by inspection alone. The test builds a 70-level chain with
one file per level and asserts exactly 65 files are counted (depths 0
through 64), confirmed directly against the real traversal rather than
only reasoned about from reading the guard.

**`tests/test_report.c`**: `test_oversized_finding_truncation_boundary()`.
`usbs_finding_t.message`/`.path` are fixed-size buffers
(`USBS_FINDING_MESSAGE_MAX`/`USBS_FINDING_PATH_MAX`, `scan.h`) a
detector's own `snprintf()` already truncates safely - this is not a
buffer-overflow hunt. What it verifies is the property §13.3 documented
informally after a real oversized `--signatures` path truncated a
check-level message: whatever content survives truncation must come
through JSON, CSV, and the text renderer *identically*, since all three
read the same already-truncated field, and content past the cutoff must
never leak through any of the three renderers. Two cases against the same
field: one byte over capacity (must truncate at exactly `capacity - 1`
characters; a marker placed only past that cutoff must never appear in
any rendering) and exactly `capacity - 1` characters (must **not**
truncate at all; a marker placed at the very last byte must survive
intact) - testing only the over-limit case would miss an off-by-one that
truncates a byte too early.

### 18.6 Verification

Every one of the four presets (`x64-debug`, `x64-release`, `x64-asan`,
`x64-analyze`) builds clean and passes its full CTest suite after every
change in this section, not only after the last one - each fix in §18.2
through §18.4 and each test file in §18.5 was verified individually before
moving to the next, the same incremental discipline every prior phase in
this document has used. Final count: 21 test executables' worth of
coverage across the same 17 CTest targets (no new test *executables* were
added; the new coverage grew inside `test_json`, `test_signature_list`,
`test_scanner`, and `test_report`). CLI and JSON/CSV schema output are
untouched byte-for-byte - every change in this phase is internal to
`hash_match.c`, `json.c`, `gui_window.c`, `main_gui.c`, the build system,
and test code.

One flaky, non-reproducing `test_scanner` failure was observed once under
`x64-debug` during this phase's verification and did not reproduce on
immediate rerun (17/17 clean, and the same binary run standalone showed 0
failures) - consistent with this project's prior, documented experience of
real-time antivirus occasionally interacting with freshly-written scratch
test files (§11.3), not a regression from any change in this phase.

## 19. Phase 13: v1.0 release prep and tagging

Purely administrative: no scanning/detection/reporting/GUI code changed.
Three decisions worth recording, since "just write a README and commit"
hides a few real judgment calls.

### 19.1 One version number, not a reconstructed history

Every phase in this document, `PROGRESS.md`, and `TASKS.md` up to this
point shipped straight to an uncommitted working tree - twelve phases of
real, verified, individually-tested work with no git history behind any
of it (`git log` on this repository has always reported "no commits
yet"). `CHANGELOG.md` presents that history as a single `[1.0.0]` entry
with phase-by-phase subsections, deliberately **not** as twelve backdated
tags or a sequence of invented "v0.x" releases: no such versions were
ever built, installed, or referenced by anyone, and fabricating a release
history that did not happen would be a worse kind of dishonesty than
having no history at all. The phase numbering itself is preserved exactly
as it already existed in `PROGRESS.md`/`TASKS.md`, since that numbering
is real and is how every prior section of this document already refers to
its own decisions.

### 19.2 A single initial commit

For the same reason: this phase creates one git commit covering the
entire existing working tree, not an attempt to split twelve phases of
already-completed work into twelve retroactive commits with invented
timestamps and diffs reverse-engineered from `PROGRESS.md`. A fabricated
commit-per-phase history would look more thorough than the truth and
would be less honest than it. The commit message and the annotated
`v1.0.0` tag both point at `CHANGELOG.md` for the real phase-by-phase
detail instead.

### 19.3 Documentation restructuring, not new decisions

The README rewrite (installation, building, CLI usage, GUI usage, a
dedicated signature-list-format section, a dedicated reports/storage
section) consolidates information that was already accurate and present
in this document and in the pre-Phase-13 README - reorganized for a
first-time reader assembling a mental model top to bottom, not a
developer already holding this file's context. Nothing in the README
rewrite states a fact that contradicts §1 through §18; where the two
differ in wording, this document is authoritative.

`TASKS.md`'s trailing deferred-work section was renamed from "Phase 13+"
to "Post-v1.0" (Phase 13 now names a real, completed phase, so the old
header would have been actively wrong) and one item that was previously
only implicit - a background service or continuous monitoring, distinct
from the GUI's already-shipped foreground auto-scan-on-insert - was named
explicitly rather than left folded into "concurrency beyond the GUI's
UI-local worker thread". This is a real, if small, scoping decision: a
persistent background listener is a materially different threat profile
from the GUI's current one-shot-per-launch model (§7.3's reasoning
against an elevated helper process applies just as much to an unelevated
long-running one - it needs its own privilege and IPC design, not an
extension of the existing worker-thread model), so it is worth being able
to point at by name the next time it comes up rather than rediscovering
the distinction from scratch.
