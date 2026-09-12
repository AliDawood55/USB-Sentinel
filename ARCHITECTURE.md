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

## 20. Phase 14: cross-platform support (POSIX)

Phase 14 makes the portable core genuinely portable: the full test suite
and `usb-sentinel scan <path>` running on Linux and macOS, with CI proving
it on every push. It is deliberately **additive**, not a rewrite, and the
reason is §2's layering rule doing exactly what it was written to do.

An audit before any code was written found `wchar_t`/`WCHAR`/`LPCWSTR` in
exactly four files - `platform/device_win32.c`, `platform/fs_win32.c`,
`gui/gui_window.c`, and one test fixture - and in no public header. The
UTF-8-in/UTF-8-out contract `platform.h` declares was actually being
honoured, so the wide-string refactor that a port like this usually
begins with is simply not needed: POSIX is natively UTF-8 and the new
backend converts nothing. Both platform translation units were also
*already* shaped as `#if defined(_WIN32) ... #else <unsupported stubs>`,
so the filesystem work fills in declared, already-compiling seams. The
detectors (`autorun`, `suspicious_filename`, `lnk_inspect`, `hash_match`)
are byte-level parsers over `usbs_platform_file_read` and need no change
at all - roughly 1,200 lines of detection logic that ports for free.

What did *not* survive contact with POSIX was a set of buffer sizes in a
header that had no `#ifdef` in it and therefore looked portable. That is
§20.1, and it is the reason this phase starts with a Windows-only commit.

### 20.1 The portable header was sized for Win32

`device.h` carried three constants cut to the exact shape of the Win32
values they happened to hold:

```c
#define USBS_VOLUME_PATH_MAX  64   /* "\\?\Volume{GUID}\" is 49 + NUL */
#define USBS_MOUNT_POINT_MAX  8    /* "E:" */
```

Neither survives a POSIX host. There is no volume GUID; the volume path
*is* a mount path (`/media/alice/SANDISK_ULTRA_64GB`,
`/Volumes/Untitled 1`), routinely past 64 bytes, and a mount point is a
full path rather than a two-character drive name. Both are now 512.

Two things make this worth a section rather than a one-line diff.

**It was already a bug on Windows.** `USBS_MOUNT_POINT_MAX` of 8 was not
merely POSIX-hostile: a volume mounted into a folder rather than a drive
letter - `C:\Mounts\MyUSB`, which Windows has supported for two decades -
was being silently truncated to seven characters by `fill_mount_points()`
in `device_win32.c`. The constant was sized for the common case and the
uncommon case degraded quietly. So this is a latent-bug fix on the
current platform as much as preparation for the next one, and it is the
clearest argument available for doing the resize *first*, on Windows,
with the existing suite green, rather than folding it into a POSIX commit
where it would have read as porting noise.

**It silently un-guaranteed something two headers away.**
`usbs_device_identity()` builds a `"volume:<volume_path>"` key as its last
resort, into a caller-supplied buffer that every call site sizes with
`USBS_IDENTITY_MAX`. While `volume_path` was 64, `7 + 63 + NUL` fit
inside a literal 160 with room to spare - the fallback was infallible, but
only *by accident*, because two unrelated numbers happened to be far
enough apart. At 512 the same literal starts returning
`USBS_ERR_NO_MEMORY` for ordinary POSIX mount paths, which takes out the
storage key and the report with it, and surfaces as a failed scan
pointing nowhere near this header.

`USBS_IDENTITY_MAX` is therefore now *derived* rather than a round number:

```c
#define USBS_IDENTITY_MAX (USBS_VOLUME_PATH_MAX + 32)
```

which makes "the fallback always fits" a property of the header instead
of a coincidence. `test_device.c` asserts it against a deliberately
maximum-length `volume_path`, so raising one constant without the other
fails immediately and in the right place. That test was confirmed
non-vacuous by reverting the derivation to the old literal and watching it
fail, rather than by assuming it would.

**512, not `PATH_MAX`.** `usbs_device_t` is a flat by-value POD pushed
into `usbs_device_list_t`, so every byte is multiplied by
`USBS_MOUNT_POINTS_MAX` and again by the device count. 512 covers every
real mount path while keeping the struct near 2.5 KB; `PATH_MAX` (4096 on
Linux) would put it past 16 KB for no practical gain. Paths longer than
the bound are truncated exactly as before - bounded truncation, never
overflow.

**`schema_version` deliberately stays 1.** The planning note for this
phase proposed bumping the report schema to 2 alongside the resize. That
was wrong, and the rule already recorded in §7.4/§9.2 - "additive
changes... do NOT bump it" - is what makes it wrong. Widening a C buffer
changes no byte of JSON output: the writer emits the string value, not
the field's capacity, so a consumer parsing a Windows report before and
after this commit sees identical bytes. Bumping would have announced a
format change that did not occur, and broken `test_report.c`'s
`schema_version == 1` assertion to do it. The genuine question - whether
`mount_points` carrying `/media/alice/USB` instead of `E:` is a
*semantic* break for consumers - belongs to Phase 14b, where POSIX
enumeration actually lands and where there will be something real to
decide about. It is not settled here by anticipation.

Confirmed on `x64-debug`, `x64-release` and `x64-analyze`: 17/17 tests
pass, and `x64-analyze` reports the same warning set as the pre-change
baseline (six pre-existing `C6262` stack-size notes and one `C6001`, all
in `tests/`, all unchanged in file, line and code; only the reported byte
counts move, by the expected ~2.5 KB).

### 20.2 CI first, before the POSIX code it exists to check

`.github/workflows/ci.yml` builds on Windows (MSVC), Linux (GCC and
Clang) and macOS (Clang) on every push. It landed *second*, immediately
after §20.1 and before a line of POSIX implementation, because its main
value is not re-running a Windows suite that already passes: it is
putting GCC and Clang in front of ~18,000 lines of C that had never been
compiled by anything but MSVC. That paid for itself on the first run -
see the defect list below.

**Windows-only targets are gated, not ported.** `src/gui` and
`src/app_gui` are excluded from a non-Windows configure: `gui_window.c` is
one of the three files that include `<windows.h>`, and `app_gui` builds a
`WIN32` executable from a generated `.rc`. The CPack/NSIS block is gated
for the same reason. `usbs_cli` and `usb-sentinel` *do* build on POSIX -
they link the platform stubs and report `USBS_ERR_UNSUPPORTED` at
runtime, which is the honest degradation §20 is working to remove.

**The `core_only` label.** Until `fs_posix.c` exists, any test that
reaches `platform.h` fails on POSIX for a reason that says nothing about
the code under test. `tests/CMakeLists.txt` labels the seven tests that
touch no platform entry point at all - `test_version`, `test_error`,
`test_log`, `test_json`, `test_env`, `test_device`, `test_report` - and CI
runs `-L core_only` on POSIX while Windows runs the full suite. The set
was confirmed by running the whole suite under Linux in a container and
observing that exactly those seven pass and the other eight fail on
stubs, rather than by predicting it. The label is named for what the
tests *are*, not for which platform runs them, so when step 4 widens the
POSIX jobs to the full suite the label stops carrying scheduling meaning
without becoming a lie.

**No third-party actions.** Only `actions/checkout`, plus the CMake and
CTest already present on the runner images - the same "take no dependency
you do not need" stance §7.1 applies to SetupAPI-over-WMI and §10.1 to
CNG-over-a-crypto-library. Windows uses the Visual Studio generator
rather than the repository's Ninja presets, because Ninja needs `cl.exe`
on `PATH`, which needs a developer command prompt, which on a hosted
runner means either a third-party action or a hard-coded Visual Studio
edition path that differs between images. Same compiler either way; local
development keeps using `CMakePresets.json`.

**What the first non-MSVC compile found.** Two were fixed in the same
commit:

- `core/json.c` carried a bare `#pragma warning(suppress : 6001)` - a
  PREfast directive, in the *portable core*, unguarded. Every non-MSVC
  compiler reports it as an unknown pragma under `-Wall`. Now wrapped in
  `#if defined(_MSC_VER)`.
- `tests/test_platform.c` declared a loop counter used only on the
  Windows branch, so `-Wextra` flagged it as unused on POSIX.

Five `-Wformat-truncation` warnings remain, all GCC-only (Clang reports
none) and all pre-existing rather than introduced here:
`detectors/lnk_inspect.c:507` and `storage/storage.c:410` in product
code, plus three in tests that construct deliberately oversized strings
*in order to* assert that truncation happens. They are recorded rather
than silenced: `storage.c:410` (`"%s.tmp"` on a path that may already
fill its buffer) is the one with real, if unlikely, consequence, and the
right time to deal with it is step 4, when POSIX path handling is written
and `USBS_STORE_PATH_MAX` is revisited anyway. `USBS_WERROR` therefore
stays `OFF` in CI for now; turning it on is the natural close-out of
step 4.

**Local Linux loop.** Verification during this phase runs GCC and Clang
against the real tree in a container before anything is pushed, which is
also how the `core_only` set was established. CI is the gate, not the
first place a POSIX compiler sees the code.

**The Windows job is the one that broke.** Worth recording, because the
expectation was the opposite. All three POSIX jobs passed on the first
run; Windows failed at `Configure`, because the workflow pinned
`-G "Visual Studio 17 2022"` and the hosted image no longer matched. The
fix is to name no generator at all and let CMake select the newest
installed Visual Studio, which is the same reasoning already applied to
the vcvars path one paragraph up - and the job now records
`vswhere -latest -property installationVersion` so the next such failure
is readable from the log instead of inferred. The compiler selection also
moved from a `CC` environment variable into each matrix entry's
`CMAKE_C_COMPILER`, so the Windows entry - which names no compiler - no
longer ends up with `CC` set to the empty string.

### 20.3 Case-insensitivity belongs to the detector, not the filesystem

`autorun.c` opened `"<volume>autorun.inf"` directly. That is
case-insensitive only because NTFS and FAT are. On ext4 - and on APFS
formatted case-sensitive - the same open matches nothing but the exact
lowercase spelling, while the autorun.inf specification is
case-insensitive and `AUTORUN.INF` in capitals is the historically common
form in precisely the malware this detector exists to find.

The failure mode this produces is the worst available one for a forensic
tool: the identical stick reports a finding on Windows and silently
reports *nothing* on Linux. Not an error, not a skipped check - a clean
negative result that is wrong. Detection semantics must therefore be
fixed in the detector rather than inherited from whatever filesystem
happens to be underneath.

The implementation lists the volume root once and compares entry names
case-insensitively, rather than probing a list of candidate spellings
(there are 2<sup>11</sup> of them, and any table of two or three is a
guess about which ones matter). Folding is ASCII-only, matching the
`contains_ci` helper already used for the file's *contents*, which is all
`autorun.inf` needs and keeps locale-dependent case rules out of a
detection decision. If the root cannot be listed, the lookup falls back to
the canonical lowercase name, so behaviour on a volume that resists
listing is exactly what it was before.

Two smaller things came with it. The finding now reports the *real*
on-disk spelling rather than the canonical one - `AUTORUN.INF` and
`autorun.inf` are different facts about a volume, and a report should say
which was actually there. And the path buffer, a flat `char path[600]`,
was resized to `USBS_VOLUME_PATH_MAX + USBS_NAME_MAX` with a real
truncation check: 600 was comfortable only while a volume path was a
49-character Windows GUID, and after §20.1 a 511-character volume path
plus a 259-character name overflows it. The previous check tested
`snprintf` for encoding failure but not for truncation.

Tested with `AUTORUN.INF` and `AutoRun.Inf` fixtures. Both assertions
bite on Windows too, despite NTFS making the *open* succeed either way,
because they assert the reported path and NTFS preserves creation case -
so a detector that hardcodes the canonical spelling fails them.

### 20.4 POSIX traversal policies, decided before the code is written

Two hazards in `fs_posix.c` are easier to get right by deciding them in
advance than by noticing them in review. Recording them here so step 4
implements a written policy rather than inventing one mid-file.

**Symlink loops.** `usbs_dir_entry_t.is_reparse_point` must be filled
from `lstat`/`fstatat(AT_SYMLINK_NOFOLLOW)`, never `stat`. This is not a
portability detail but a safety property: §9.3 already guarantees that
reparse points are never followed, and `stat` silently inverts that
guarantee into "follow every symlink" - on media supplied by an
untrusted party, which is this tool's entire threat model. A symlinked
cycle would then be an unbounded walk, and a symlink to `/` an escape
from the scanned volume entirely.

Skipping symlinks outright already makes symlink cycles unreachable, so
`(st_dev, st_ino)` tracking is defence in depth rather than the primary
control - it covers the cases skipping does not, such as bind mounts and
directory hard links. It is worth having because the cost is a small set
of visited pairs and the failure it prevents is a hang on hostile input.

**Filenames are bytes, not text.** This is the exact inverse of the
Windows problem §20 opens with. Win32 hands back UTF-16 that converts
cleanly; POSIX hands back an arbitrary byte string with no encoding
guarantee, and `usbs_dir_entry_t.name` is *declared* UTF-8 and flows
directly into the JSON writer. A stick carrying a Latin-1 or deliberately
malformed filename would therefore produce invalid-UTF-8 JSON - which on
a tool whose input is attacker-supplied media is a malformed-output bug
reachable by anyone who can hand someone a USB stick.

Policy: validate and sanitise to U+FFFD at the `fs_posix.c` boundary, so
the invariant holds at the point where it is declared rather than being
patched further up in `report.c`. The alternative - rejecting such
entries - would let an attacker hide a file from the scan by giving it an
invalid name, which is strictly worse than reporting it with substitution
characters.

### 20.5 One backend per host, selected by CMake

Both §20.4 policies are implemented in `fs_posix.c`, alongside
`device_posix.c` (cancellation), `hash_posix.c` and `sha256.c`. The
structural change that came with them is that **CMake now selects the
platform sources** instead of compiling the Win32 files everywhere.

The old shape existed for a good reason: `fs_win32.c` and
`device_win32.c` were compiled unconditionally, so each carried an
`#else` half of `USBS_ERR_UNSUPPORTED` stubs purely so a non-Windows
build could link. That was the right call when there was no POSIX
implementation. Keeping it would now mean two live implementations
interleaved by preprocessor inside one file, which is the shape that
makes platform code unreadable. Selecting sources keeps every file a
single implementation, and `platform_unsupported.c` preserves the exact
property the `#else` branches provided: an unfamiliar host still
configures, compiles and links, with a CMake `WARNING` rather than a wall
of undefined symbols.

`CMAKE_SYSTEM_NAME`/`UNIX`/`APPLE` rather than CMake's `LINUX` variable,
which needs CMake 3.25 while this project declares 3.21.

Two contract details surfaced while doing this, both fixed in the
implementations rather than papered over in the tests:

- `usbs_platform_probe_capabilities()` must return
  `USBS_ERR_INVALID_ARG` for a NULL argument *before* it returns
  `USBS_ERR_UNSUPPORTED`. Argument validation is platform-independent -
  a NULL pointer is a caller's bug on every host, whereas "unsupported"
  describes the operation. The old POSIX stub returned `UNSUPPORTED`
  unconditionally, which told callers the wrong thing about their own bug
  and made platform.h's documented contract true only on Windows.
- `usbs_platform_status_from_win32(0)` must **not** return `USBS_OK` on
  POSIX. There is no errno corresponding to a Win32 code, so the whole
  translation is unsupported there - including for zero, which would
  otherwise be mistaken for a successful translation.

### 20.6 SHA-256: CNG, CommonCrypto, and one vendored primitive

Per host, in order of preference for a first-party facility:

| Host | Provider | Why |
|---|---|---|
| Windows | CNG (`bcrypt`) | unchanged from Phase 4 |
| macOS | CommonCrypto | first-party, in libSystem, no link flag, no package |
| Linux | vendored `sha256.c` | no first-party equivalent exists |
| Linux (opt-in) | OpenSSL | `-DUSBS_USE_OPENSSL=ON`, for packagers |

Linux is the only real decision. There is no system SHA-256 there, so the
choice is a third-party dependency or ~180 lines of vendored primitive,
and this project has consistently taken the second where the alternative
is small and verifiable - SetupAPI over WMI (§7.1), CNG over a crypto
library (§10.1), no unit-test framework at all (§6).

"Don't hand-roll crypto" is a good rule that does not apply here, and it
is worth being precise about why rather than waving it away. The rule
protects against subtle failures with security consequences: key
handling, timing side channels, nonce reuse, padding oracles. This code
has none of those surfaces - it hashes file contents, there are no keys
and no secrets, and nothing is required to be constant-time. What remains
is a deterministic function with published NIST test vectors, which
`tests/test_hash.c` already asserts against and which now runs on every
platform in CI. Correctness here is *checked*, not trusted. `sha256.h`
states the limits so a future reader does not mistake it for a
general-purpose primitive.

The vendored implementation is written to be read against FIPS 180-4
rather than to be fast: hashing is bounded by file I/O, and an unrolled
or SIMD variant would trade away the one property that makes vendoring
defensible. It loads blocks byte by byte rather than casting to a
`usbs_u32 *`, which would be both an alignment violation and wrong on a
little-endian host, and it zeroes its context on finish because that
context holds a tail of file content.

`USBS_USE_OPENSSL` exists so a distribution whose policy forbids vendored
crypto has a supported path, and is the project's only optional
third-party runtime dependency.

### 20.7 Paths: separators and the per-user data directory

Two things were spelled Windows-only in otherwise portable code.

**The separator.** `"\\"` was typed directly into format strings in
`scanner.c`, `storage.c`, `hash_match.c`, `cli.c` and six test scratch
roots. `include/usbsentinel/path.h` now provides `USBS_PATH_SEP` and
`usbs_path_join()`; five real consumers is comfortably past this
project's usual bar for extracting a helper.

Windows genuinely cannot just accept `"/"` everywhere, which would have
been the cheaper fix: Win32 tolerates forward slashes in ordinary paths
but **not** in the `\\?\` long-path and volume-GUID forms, and
`usbs_device_t.volume_path` is exactly such a form (§7.2).

`usbs_path_is_separator()` is deliberately asymmetric - both characters
on Windows, only `/` on POSIX - because a backslash is a legal byte in a
POSIX filename, so treating it as a separator there would mangle the
basename of a file named `a\b.txt`. `hash_match.c`'s `path_filename()`
had exactly that bug. Content parsed *out of* a file is a separate case
and was deliberately left alone: the target and argument strings inside a
`.lnk` are Windows-shaped no matter which host reads them, so
`lnk_inspect.c` still tests for a backslash directly, and the tests that
build `.lnk` fixtures still use `C:\...` strings.

**The data directory.** `%LOCALAPPDATA%` was read directly in
`storage.c` and `hash_match.c`. `usbs_user_data_dir()` (core/env.c) now
resolves the platform convention:

| Host | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\USBSentinel` |
| macOS | `~/Library/Application Support/USBSentinel` |
| Linux | `$XDG_DATA_HOME/usb-sentinel`, else `~/.local/share/usb-sentinel` |

The Linux name is lowercase-hyphenated and the other two title-cased,
deliberately not unified: matching each platform's own convention matters
more than matching ourselves across platforms, and on Windows the
existing directory already holds v1.0.0 users' reports. Honouring
`XDG_DATA_HOME` rather than hardcoding `~/.local/share` is also what lets
a sandboxed or containerised run redirect the store without touching a
real home directory.

Help text is the one place a platform-specific string is the *correct*
answer rather than something to abstract: a Linux user told to look in
`%LOCALAPPDATA%` has been given a wrong instruction, not a portable one.
`cli.c` therefore carries a per-platform hint string, kept in step with
`usbs_user_data_dir()`.

**Result.** The full suite passes on Linux under both GCC and Clang -
15/15, including `test_scanner`, `test_storage`, `test_detectors` and
`test_hash` - and Windows is unchanged at 17/17. CI's POSIX jobs no
longer filter on `core_only` and now run everything.

`USBS_NAME_MAX` also moved from 260 to 1024 here. 260 was `MAX_PATH`,
which counts UTF-16 code units rather than UTF-8 bytes, so a Windows
filename of 100 CJK characters (300 bytes) already failed conversion and
was stored as an *empty* name - a current-platform bug for anyone whose
filenames are not Latin, found by porting rather than by anyone
complaining. U+FFFD substitution needs the same headroom for the
unrelated reason that it can triple a name's length.

One test-harness change came out of the same work: `USBS_REQUIRE`, a
check that abandons the current test function instead of continuing into
a dereference it was guarding. A failed `count == 1` followed by
`items[0]` is a segfault, and a segfault takes down the whole executable,
so CTest reports one crashed binary instead of one failed assertion plus
every later test's result - turning a small regression into a blind spot
exactly when the remaining results are most worth seeing.

### 20.8 Sanitizers on POSIX, and what they found immediately

CI gained a fifth job: the full suite under Clang's AddressSanitizer and
UndefinedBehaviorSanitizer, with `detect_leaks=1`. The project already ran
MSVC's ASan through its `x64-asan` preset (§18); this is the POSIX
counterpart, and it additionally covers UBSan, which MSVC has no
equivalent of.

It earned the slot on its first run, in pre-existing code rather than in
anything Phase 14 wrote:

```
signature_list.c:283: runtime error: null pointer passed as argument 1,
                      which is declared to never be null
    qsort(list->entries, list->count, ...)
```

When a signature file parses to zero valid entries - which the fuzz test
reaches routinely - `entries` is still NULL and `count` is 0. Every real
`qsort` returns immediately for a count of zero, so this never
misbehaved and no amount of passing tests would ever have surfaced it,
but it is undefined behaviour by the standard and the standard is what a
future libc is entitled to follow. Guarded, and recorded here as the
concrete answer to "what is a sanitizer job actually worth".

With that fixed, the whole suite is clean under ASan + UBSan + leak
detection: 15/15, including the new `fs_posix.c` UTF-8 scanner,
`sha256.c`'s block handling and `hash_posix.c`'s allocation paths - the
parts of this phase most likely to contain exactly the class of defect
these tools find.

### 20.9 What Phase 14 initially did not deliver, and why that changed

When this section was first written, the engine was portable and
CI-verified on three platforms, but the CLI was not usable end to end on
two of them: `usbs_cli_cmd_scan()` resolved its target only by calling
`usbs_device_enumerate()` and matching among attached USB volumes, which
returns `USBS_ERR_UNSUPPORTED` on POSIX (§20.5). Every layer beneath the
device layer worked and was tested there; the CLI simply had no way to
name a target without enumeration.

Two ways to close that were identified, described here as they were at
the time because the reasoning is still the relevant part:

1. **Phase 14b** implements enumeration (sysfs, IOKit + DiskArbitration)
   and the CLI works unchanged. Deferred precisely because it is the one
   part of the port that cannot be verified without real removable
   hardware.
2. **A path target for `scan`** - `usb-sentinel scan /media/alice/USB` -
   would make the engine reachable immediately, on every platform, and
   would be useful on Windows too (a volume mounted into a folder). But
   it is a new user-facing mode, not a port mechanic, and it carries a
   real reporting question: a directory that was never enumerated has no
   bus type, no serial and no USB ids, so its report would honestly have
   to say `bus_type: unknown` and key it as `volume:<path>`.

Option 2 was initially deferred: Phase 14's agreed scope was "portable
core + POSIX filesystem + CI", and adding a CLI mode to it would have
widened that scope on the strength of the porting work rather than on
its own merits. That was a decision for whoever owns the product to make
explicitly, not one to make silently while heads-down in the port - so it
was surfaced rather than taken, and the reporting question above was
answered by design (`bus_type: unknown`, `volume:<path>`) but left
unimplemented pending that call.

The call came back the same day: implement it now. §20.11 is that
implementation - the reporting semantics are exactly as designed above,
unchanged by the wait.

### 20.10 Warnings deliberately left

**`USBS_WERROR` stays OFF.** Four `-Wformat-truncation` warnings remain
under GCC (Clang reports none), and none of them should be silenced:
three are in tests that construct deliberately oversized strings *in
order to* assert that truncation happens, and restructuring those to
satisfy the heuristic would weaken the tests they belong to. The fourth,
`lnk_inspect.c:507`, is a human-readable message being assembled into a
fixed buffer, where truncation is the designed behaviour. The two that
did carry real consequence were fixed rather than suppressed:
`storage.c`'s `"%s.tmp"` now checks for truncation - a silently shortened
temp path would be written to and then renamed over the wrong file, which
is data loss in the report store rather than a missing suffix - and
`USBS_FINDING_PATH_MAX` was raised to 1024 to match `USBS_NAME_MAX`, so a
single long filename at the volume root is no longer truncated in a
report.

### 20.11 `scan <path>`: a fallback, not a bypass

Implements option 2 from §20.9. `cmd_scan.c`'s device-matching loop is
unchanged and still runs first: a target that matches an enumerated
USB volume by mount point or identity substring is scanned exactly as
before. Only when nothing matches - including when `usbs_device_enumerate()`
itself returns `USBS_ERR_UNSUPPORTED`, the ordinary state on POSIX until
Phase 14b - is `target` tried as a directory path
(`usbs_cli_build_path_device()`), and only if a target was actually given;
`scan` with no arguments still requires enumeration, since there is
nothing to fall back to.

**Honesty over inference**, matching the wording promised in §20.9: the
synthetic device's `bus_type` is `USBS_BUS_UNKNOWN` and every USB-specific
field (vendor, product, serial, VID/PID, capacity) stays at
`usbs_device_init()`'s zeroed default, because none of it was queried. A
bare directory was never enumerated, so reporting otherwise would be
exactly the confident-but-wrong answer §7.3 already refuses for real
devices. `usbs_device_identity()` then takes its own already-existing
"volume:<path>" fallback path unchanged - no new identity logic was
needed, because §7.2's precedence order already handles "nothing more
specific is known" correctly.

**Validated before scanner.c ever sees it.** `usbs_cli_build_path_device()`
normalizes the path (`usbs_path_join(path, "")`, reusing §20.7's helper
to add exactly one trailing separator without doubling one already there)
and opens it as a directory, closing the handle immediately - existence
and "is a directory, not a file" are both confirmed at this front door,
so a bad target gets one specific error here instead of a walk failure
several layers down. The length check runs *before* the filesystem call:
a path too long for `USBS_VOLUME_PATH_MAX` is rejected as
`USBS_ERR_NO_MEMORY` without a wasted syscall, rather than surfacing as a
confusing "not found" for a path that might exist but simply cannot be
stored.

**A small, deliberate widening.** Path mode does not filter by bus type
the way automatic selection does - `scan /any/directory` will scan a
non-removable path too, including (on Windows) a plain fixed-drive letter
that failed the enumerated-device match. This was considered against
§1's safety model and found not to touch it: every constraint there
(read-only, no network, no execution, no silent action) is enforced by
what the platform layer's file-open calls actually request, unconditionally,
regardless of what path they are given - not by restricting which paths
may be named. Explicitly typing a path is exactly the "explicit, opt-in"
action the safety model is built around, not an exception to it.

**Not exercised via a full CLI test.** `usbs_cli_cmd_scan()` calls
`usbs_store_open()`, which resolves the real per-user data directory
(§20.7) - a test must not touch that. `usbs_cli_build_path_device()` is
instead exposed non-static and un-declared in any header, the same
pattern `hash_match.c` uses for `usbs_hash_match_lookup()`, and
`tests/test_cmd_scan.c` exercises it directly: normalization with and
without a trailing separator, honest zeroed fields, identity fallback,
rejection of a nonexistent path and of a plain file, `NULL` arguments,
and a too-long path. End-to-end behaviour (`scan <path>` producing and
saving a real report; `scan` with no target and no enumeration printing
the new guidance message; a nonexistent path's error text) was checked
by hand on both Windows and Linux rather than left to the unit test alone,
precisely because the unit test cannot reach `usbs_store_open()`.

Verified: 18/18 on Windows (17 plus the new test), 16/16 on Linux under
GCC and Clang, and clean under ASan + UBSan + leak detection. No new
`/W4` or PREfast diagnostics on either new file.

## 21. Phase 14b: device enumeration (Linux, then macOS)

Where Phase 14 made the engine portable, Phase 14b makes `usb-sentinel
devices` and automatic `usb-sentinel scan` selection work without a path
argument, on Linux and macOS. It is sequenced Linux-first, each step its
own verified commit, matching Phase 14's own rhythm.

**Real-hardware verification is not available for this phase.** The
maintainer's own hardware is Windows-only - no Linux machine/VM, no Mac.
Following the same honest-boundary discipline §10.6 established for the
original Windows enumeration work (a physical device became available
mid-phase there, was used for exactly what CI could not verify, and the
write-up said precisely what was and was not checked): CI proves what CI
genuinely can - the algorithms run correctly against real, if non-USB,
block devices and disk images - and real hardware verification is
deferred to community beta testers (§21.4), not simulated or asserted
without evidence.

### 21.1 Linux block enumeration + capacity (bus_type deliberately unknown)

`device_linux.c`, alongside a restructuring of the Linux/macOS platform
sources this makes necessary.

**The split this required.** Before this commit, `device_posix.c` held
three things: the `status_from_win32` stub, cancellation (both genuinely
OS-independent), and enumeration/capability-probing stubs (genuinely
OS-specific, previously stubbed only because no real backend existed
yet). Giving Linux a real backend meant `device_linux.c` needed to define
`usbs_platform_device_source()` etc. itself - which meant `device_posix.c`
could no longer define them too, on pain of duplicate symbols. So
`device_posix.c` is now trimmed to just the OS-independent half, and a
new `device_posix_unsupported.c` carries the enumeration/capability stubs
forward for any UNIX host without its own backend - which, for now,
includes Apple: `device_macos.c` does not exist until §21.3, and an early
draft of this commit's CMake logic routed Apple straight at it anyway,
which would have broken the macOS CI job's configure step immediately.
Caught by dry-running the CMake configure with `-DCMAKE_SYSTEM_NAME=Darwin`
before pushing (not a real cross-compile - just confirming which sources
CMake selects) rather than by waiting for CI to fail. Until §21.3,
`elseif(APPLE)` is deliberately not yet in `platform/CMakeLists.txt`; that
asymmetry is temporary, not a design decision, and is recorded as such
in the CMake comment itself so it reads as intentional-for-now rather
than as an oversight.

**Strategy**, mirroring `device_win32.c`'s shape: `/sys/class/block`
enumerates (Windows: `FindFirstVolumeW`); a later step's sysfs ancestry
walk will decide bus type (Windows: `IOCTL_STORAGE_QUERY_PROPERTY`, never
`GetDriveType`); `/proc/self/mountinfo` will supply mount points and
filesystem type (Windows: `GetVolumePathNamesForVolumeNameW` /
`GetVolumeInformationW`).

**This commit's deliberate scope**: block discovery and `capacity_bytes`
only. `bus_type` stays `USBS_BUS_UNKNOWN`; `media_present`, `mount_points`,
`filesystem`, and `label` all stay at `usbs_device_init()`'s zeroed
defaults - honestly incomplete, not guessed. Because `bus_type` is never
`USBS_BUS_USB` yet, no device from this step can look "scannable" to
`cmd_scan.c`/`cmd_devices.c`'s existing filters - this step is provably
inert from the CLI's perspective until §21.2 lands, which is exactly what
makes it safe to land on its own.

**Partition vs. whole disk.** A block entry with its own `partition`
attribute file is a partition, always enumerated. A whole-disk entry
(`sdb`) with partition children (`sdb1`, `sdb2`, ...) is skipped - its
partitions are separately enumerated as their own top-level `sysfs`
entries. An unpartitioned whole disk (a "superfloppy"-formatted USB
stick, filesystem directly on the disk) has no partition children and is
itself the volume.

**`removable` lives on the whole disk, never on a partition** - reached
via `"<partition_dir>/../removable"` rather than by parsing the parent
disk's name out of the partition's own name. That distinction matters:
partition-naming schemes vary (`sdb1`, `nvme0n1p1`, `mmcblk0p1`), and a
string-parsing rule would need a case for each. `"sdb1/.."` works
regardless of naming scheme because `sdb1` is a symlink whose target is
nested inside `sdb`'s own real directory, and POSIX path resolution
follows a symlink component fully before applying a trailing `..` - the
same idiom tools like `lsblk` already rely on. `"size"` is always
512-byte sectors regardless of the device's actual sector size, a stable
part of the kernel's sysfs block ABI, not an assumption about any one
device.

**A real bug, found before it ran once.** `/sys/class/block/*` entries
are themselves symlinks (how sysfs's flat "class" aggregation works).
`fs_posix.c`'s directory iterator deliberately reports a symlink AS a
symlink (`fstatat(AT_SYMLINK_NOFOLLOW)`) rather than as whatever it
points at - exactly the guarantee §9.3 needs against a hostile scanned
volume. Reusing it to list `/sys/class/block` would have reported every
single entry as "not a directory," and enumeration would have silently
found nothing - a bug that would have looked, from the outside, exactly
like "no devices attached," the worst possible failure mode for this
tool. The fix is a small, self-contained, raw `opendir`/`readdir`/`stat`
listing (`stat`, not `lstat` - the entire point) used for exactly this
one call; every other directory this file lists holds genuine
subdirectories, not further symlinks, so `usbs_platform_dir_open()`/
`dir_next()` are correct and used normally everywhere else. Caught by
building and running the real test suite against Linux before writing a
line of documentation about it, not by inspection - the discipline this
whole phase has followed since §20's CI-first decision.

**Capability probing is deliberately deferred for the whole of Phase
14b**, not just this step - a small, explicit scoping decision. Every
caller already degrades gracefully without it (`scanner.c` logs a warning
and leaves capabilities zeroed; `cmd_devices.c` prints "unavailable"),
and it needs a device-node path (`/dev/<name>`) this file does not yet
track anywhere. Recorded rather than silently left unaddressed.

**Testability.** `usbs_platform_device_source()` (real `"/sys"`) is one
line over `usbs_linux_device_source_at()`, not declared in any header -
the same pattern `hash_match.c` and `cmd_scan.c` already use for their
own internal test surfaces - which takes an injectable sysfs root
instead. The root is passed as the source's own `ctx` directly (a
`const char *`, no wrapping struct or static storage), matching how every
caller in this codebase already uses a device source: constructed and
consumed together, in the same scope. `tests/test_platform.c`'s existing
`test_live_enumeration()` runs against the REAL `/sys` of whatever
machine executes it - a CI runner's actual root/boot disks, not a
fixture - so it is real integration coverage of the algorithm against an
unpredictable, real disk layout, distinct from the deterministic
fake-tree tests §21.2 adds once there is a positive USB case worth
constructing a fixture for.

Verified: 16/16 on Linux under GCC and Clang (including
`test_live_enumeration` against the CI container's real, if non-removable,
disks), clean under ASan + UBSan + leak detection, and Windows unaffected
at 18/18. The `-DCMAKE_SYSTEM_NAME=Darwin` dry run above confirmed the
macOS path before any real macOS CI run was needed to find the same bug
the hard way.

### 21.2 Linux bus-type ancestry walk, mountinfo, and label

Completes every field 14b.1 left at its honest zeroed default:
`bus_type`/vendor/product/serial/VID-PID via the sysfs ancestry walk;
`mount_points`/`volume_path`/`filesystem`/`free_bytes` via
`/proc/self/mountinfo` and `statvfs()`; `label` and a `media_present`
signal via `/dev/disk/by-label` and `/dev/disk/by-uuid`.

**The ancestry walk.** Starting from the whole disk's own `device`
symlink (a partition shares its whole disk's device-tree ancestry - it
has none of its own, so `whole_disk_dir()` from §21.1 is reused
unchanged to find the right starting point), `realpath()` resolves every
symlink component and canonicalizes away every `..` in one step. The walk
then climbs parent directories via plain string truncation - correct only
because `realpath()`'s output is guaranteed absolute and symlink-free, a
precondition the code states explicitly rather than leaving implicit -
checking each level's `subsystem` symlink target. A level whose target's
basename is `usb` **and** which carries an `idVendor` file is the actual
USB device node; one with `usb` but no `idVendor` is a USB *interface*
node (a mass-storage device's real tree is typically
`.../usb1/1-1/1-1:1.0/host.../target.../<disk>`, where `1-1:1.0` is the
interface and `1-1`, one level up, is the device) and the walk continues
past it. No SATA/NVMe/SCSI classification is attempted for a non-USB
device - a deliberate scope limit: the CLI's own filtering only ever
needs "is this USB", and libata's SATA-via-SCSI translation makes a
reliable SATA/SCSI distinction from sysfs alone a materially bigger
undertaking than this phase's scope, matching §21.1's identical
reasoning for deferring capability probing.

**`realpath()` found a real, silent pointer-truncation bug.** Its
prototype was implicitly declared under this project's
`-std=c17 -D_POSIX_C_SOURCE=200809L` (`fs_posix.c`/`hash_posix.c`'s other
POSIX calls are all visible under those same flags - confirmed
empirically, not assumed - so this was a reasonable expectation that
turned out wrong specifically for this one XSI function), meaning the
compiler assumed a `-1`-returning `int` and **silently truncated the
returned pointer to 32 bits**, corrupting it on this 64-bit host. Every
symptom looked like a segfault deep in `usb_walk_up()`, several calls away
from the actual cause. Root-caused by compiling a five-line isolated
`realpath()` reproduction under several feature-macro combinations, not
by staring at the crash site: `_XOPEN_SOURCE=700` (aligned with
POSIX.1-2008, so it narrows nothing `_POSIX_C_SOURCE=200809L` already
granted) is the macro glibc actually gates `realpath()` behind on this
version, and is now defined project-wide in the root `CMakeLists.txt`
rather than locally, since any future POSIX file needing another
XSI-only function would hit the identical trap. The fix also stopped
depending on `realpath(path, NULL)`'s glibc/BSD extension of allocating
the buffer itself - a caller-supplied `DEVICE_LINUX_PATH_MAX` buffer needs
no malloc-failure handling and depends on nothing but the POSIX-mandated
two-argument form. `DEVICE_LINUX_PATH_MAX` was in turn widened to track
`PATH_MAX` when the latter exceeds it, since `realpath()`'s contract
requires the caller's buffer be at least `PATH_MAX` bytes with no way for
`realpath()` to check a smaller one itself.

**A classic `for`-loop bug broke every mountinfo match, silently.**
Splitting a mountinfo line's first six whitespace-delimited fields was
originally written as
`for (tok = strtok_r(...); tok != NULL && count < 6; tok = strtok_r(...))`.
That shape calls `strtok_r()` in the increment clause **before** the
condition check can reject it - so on the iteration that finally fails
`count < 6`, the loop has already consumed one token too many, silently
discarding it. That discarded token was always the line's own `"-"`
optional-fields separator, which the code immediately after the loop
depends on finding next - so it never did, every line was treated as
malformed, and mountinfo matching failed **silently and completely**,
for every device, on every run. `test_live_enumeration` still reported
success throughout, because its 14b.1-era assertions still asserted
`mount_point_count == 0` - the very state 14b.2 was supposed to have
moved past - which is exactly the risk of not updating a test's
invariants alongside the code they are meant to check: a stale assertion
does not merely fail to catch a regression, it can make a real one look
like continued success. Found only by adding temporary trace output and
walking the actual token stream by hand against real mountinfo content,
not by re-reading the code - rewritten as an explicit
`for (count = 0; count < 6; ++count) { tok = strtok_r(...); if (!tok) break; ...}`,
which calls `strtok_r()` exactly six times, never seven.

**A second, independent bug in the same investigation**: the original
implementation accumulated `/proc/self/mountinfo`'s content across a
*loop* of `read()` calls. `mountinfo` is kernel `seq_file` content,
generated on demand rather than stored, and a multi-call accumulation
loop is not guaranteed a consistent snapshot if the mount table changes
between two of those calls - a documented `seq_file` property, not a
defect in this file's own logic, and a real one hit during this exact
investigation (this project's own heavily container-churning development
VM produced genuinely interleaved, garbled lines from two different
reads). Fixed by reading in exactly one generously-sized call, the same
approach every real tool that reads this file (`mount`, `findmnt`,
`systemd`) already takes - the industry answer to a known kernel-interface
property, not a project-specific workaround. This bug and the `for`-loop
bug were independent and compounded: fixing only one still left matching
broken.

**A real, if narrow, correctness case the live host itself supplied**:
choosing "the first mountinfo match" as `volume_path` initially had no
directory check. Docker's own container runtime bind-mounts individual
config files (`/etc/resolv.conf`, `/etc/hostname`, `/etc/hosts`) from a
real block device onto plain **files**, not directories - a real
mountinfo shape this project's own CI/development container supplied,
not a hypothetical one. `volume_path` must be something
`usbs_platform_dir_open()` can actually walk, so a match is now accepted
for `volume_path` only when `stat()` confirms it is a directory;
`mount_points[]` still records every match regardless (matching
`GetVolumePathNamesForVolumeNameW`'s own behavior on Windows, which
likewise does not filter by directory-ness).

**`media_present`** is derived rather than directly readable the way
Windows's `GetVolumeInformationW` provides it in one call: `true` if the
device is currently mounted (definitive), or - for an unmounted device -
if a `/dev/disk/by-uuid` entry matches it (udev's own signal that a
filesystem was recognized there, standing in for the one case Windows
can answer that a bare mounted-or-not check cannot).

**`/dev/disk/by-label`/`by-uuid` are the one piece not reachable through
the injectable-root testing seam** (§21.1): they live under `/dev`, a
separate tree from `/sys`, populated by udev from real device nodes, and
a fixture cannot construct a matching entry without a real block special
file (`mknod`), which needs privilege a test should not require.
`tests/test_device_linux.c` therefore does not exercise this specific
match; `test_live_enumeration` exercises it for real (proving at least
that it does not crash and degrades to an empty label when nothing
matches), and real positive-match verification is exactly what §21.4's
beta-tester template asks for.

**Testing.** `tests/test_device_linux.c` (Linux-only, built only when
`CMAKE_SYSTEM_NAME STREQUAL "Linux"`) builds a real, if fake, sysfs tree
under a scratch directory - real symlinks via raw `symlink()` (fixture
setup, not product code, the same license `test_scanner.c` already
uses for its own OS-level fixture needs), nested realistically enough
(an actual interface subdirectory nested inside an actual device
directory) to exercise the real ancestor-walk code rather than a
simplified stand-in for it - covering: an unpartitioned whole disk
enumerated as itself; a disk-with-partition correctly skipped in favor
of its partition (the two rules are mutually exclusive, so two distinct
fixtures prove them, not one fixture asked to prove both); the ancestor
walk's negative path (no USB ancestor - stays `UNKNOWN`) and positive
path (a real symlinked USB device+interface chain - `bus_type`,
VID/PID, vendor/product/serial all read correctly); a directory
mountinfo match; the file-bind-mount case that must NOT become
`volume_path`; escaped-space unescaping; and error handling.

A CI-only, real-hardware-adjacent proof rounds this out: a new
`linux-loopdev-negative-path` job creates a genuine loop-backed block
device (`losetup`, `mkfs.ext4`, `mount`), runs the actual built
`usb-sentinel devices --all`, and asserts its output reports that device
as `bus: unknown` - never USB. A loop device has no bus ancestor by
construction, so this is real coverage of the negative path the fixture
tests above already cover deterministically, now against the genuine
kernel interface rather than a fake tree - and, run against a real
formatted-and-mounted device, incidentally re-confirms the whole
mountinfo pipeline (`filesystem: ext4`, correct capacity/free space) end
to end. A separate job, not folded into `linux-gcc`: it calls `sudo` and
manipulates real kernel block-device state, which is a different kind of
step from "build and run the unit tests," and a failure here should never
be mistaken for an ordinary test regression.

Verified: 17/17 on Linux under GCC and Clang (16 plus the new
`test_device_linux`), clean under ASan + UBSan + leak detection, Windows
unaffected at 18/18, and the loop-device job confirmed locally (a
privileged container standing in for the real VM-based GitHub runner,
which needs no such flag) before being trusted to CI.

### 21.3 macOS: DiskArbitration + IOKit

`device_macos.c`, linked against IOKit, DiskArbitration and
CoreFoundation - first-party Apple frameworks, always present with the
OS, the same "OS import libraries only, no new dependency" stance the
Windows branch already takes for setupapi/cfgmgr32/bcrypt.

**This is the one file in Phase 14b that could not be verified before
being pushed.** Every other step in this phase - Linux's two commits, the
CMake restructuring - was built, run, and iterated on locally against a
real (if containerized) Linux environment, multiple times, with real bugs
caught and fixed before ever reaching CI. There is no Mac available here
at all: not for real hardware, and not even to check that this file
*compiles*. That is a materially different, and materially riskier,
starting point than everything else in this phase, and it is worth being
explicit about rather than presenting this section with the same
confidence as §21.1/§21.2.

**Division of labor between the two frameworks** mirrors
`device_linux.c`'s own shape even though the concrete APIs share nothing:
`DADiskCopyDescription()` resolves mount point, label, filesystem,
capacity, removable, and - via `kDADiskDescriptionDeviceProtocolKey` - the
bus protocol itself, all in one call. IOKit's registry is walked
separately, and only for what DiskArbitration does not expose: USB
VID/PID/serial, via `DADiskCopyIOMedia()` bridging back to the same IOKit
object DiskArbitration's own enumeration came from. Unlike Linux, the full
bus-type set (SATA/NVMe/SCSI, not only USB) is mapped from
`DeviceProtocol`: Linux's decision to classify only "is this USB" was
driven specifically by libata's SATA-via-SCSI translation making a
reliable distinction from sysfs alone a materially bigger undertaking than
that phase's scope; macOS's `DeviceProtocol` is a single field the OS has
already resolved, not something this project has to derive itself the way
the sysfs ancestry walk does, so that reason for holding back does not
carry over.

**Two explicitly different confidence levels, stated in the file's own
header comment rather than left for a reader to guess at:**

- IOKit/DiskArbitration/CoreFoundation **key constants**
  (`kIOMediaLeafKey`, `kDADiskDescriptionVolumePathKey`, and the rest) are
  the SDK's own named symbols, not hand-typed strings. If a name is wrong
  or has moved, this **fails to compile** on the macOS CI job - a loud,
  specific, fixable signal, not a silent runtime misbehavior. This is the
  identical reasoning `device_linux.c`'s own comments already give for
  preferring a compile error over an assumption, applied to a file where
  it is the *only* verification available before pushing.
- The USB device's own property **keys** (`"idVendor"`, `"idProduct"`,
  `"USB Serial Number"`, `"USB Vendor Name"`, `"USB Product Name"`) have no
  stable symbolic constant available and are plain string literals,
  matched against what `ioreg -p IOUSB -l` shows on real hardware and what
  other open-source USB tooling already relies on. Reasonably high
  confidence, but neither compiler-checked nor run against a real USB
  device by this project - exactly the gap §21.4's beta-tester process
  exists to close, and the one part of this file most likely to need a
  correction once real feedback arrives.

**The IOKit ancestry walk** starts from `DADiskCopyIOMedia()`'s
`io_service_t` and climbs `IORegistryEntryGetParentEntry()` looking for a
node conforming to `"IOUSBHostDevice"` (modern, macOS 10.11+) or
`"IOUSBDevice"` (legacy) - both checked, since either can be present
depending on OS version and controller, mirroring `device_linux.c`'s own
"walk past the interface node to the device node" logic
(`.../usb1/1-1/1-1:1.0/.../<disk>`: `1-1:1.0` is the interface, `1-1` is
the device) even though IOKit expresses the distinction via class
conformance rather than a `subsystem`-symlink-plus-`idVendor` check.
Bounded to 20 levels (Windows's PnP walk uses 8; IOKit registry paths run
a few levels deeper) purely as a defensive bound against a registry shape
this file did not anticipate, the same reasoning `device_linux.c`'s own
12-level bound already gives.

**Free space** needed its own `statvfs()` call on the resolved mount
point, the identical call `device_linux.c` makes and for the identical
reason: `DADiskCopyDescription()`'s `MediaSize` is the whole device's
capacity, and there is no DiskArbitration key for free space specifically.
macOS implements POSIX `statvfs()`, so this is the same call, not a
BSD-specific `statfs()` substitute - keeping the two platform files as
structurally parallel as their genuinely different underlying APIs allow.

**Capability probing remains deferred**, on every platform, for the
identical reason §21.1 already gives.

**Testing.** A `macos-hdiutil-negative-path` CI job is the direct macOS
analogue of Linux's loop-device job: `hdiutil create` + `hdiutil attach`
produces a real (if virtual) mounted volume with a real `DeviceProtocol`
of its own - never `"USB"`, since a disk image has no USB ancestor by
construction, the identical structural guarantee a loop device has on
Linux - and the job asserts the built `usb-sentinel devices --all`
reports it as anything but USB. Parsing `hdiutil attach`'s output greps
for the `/Volumes/...` substring directly rather than assuming a fixed
column position, since the column count before the mount path varies with
how many partition/container lines precede it (a GPT scheme line, an APFS
container line, ...) - a lesson already learned the hard way once this
phase, in `fill_mount_info()`'s own mountinfo parsing (§21.2).

This job is the **only** verification `device_macos.c` receives before
being trusted at all - unlike every other piece of this phase, there was
no local build-and-iterate cycle first. If this job's Build step fails,
that is the expected, most likely outcome to investigate, not the
negative-path assertion after it; a compile failure here is not a
regression in working code, it is the first real compiler this file has
ever seen.

**Deliberately not attempted**: verifying the *positive* USB path (real
VID/PID/serial extraction against an actual USB device) or the exact
correctness of the USB property key strings against a real IORegistry.
Both need real Apple hardware, which CI does not have and this
environment does not have either. §21.4's beta-tester process is how that
gap gets closed - not by this project asserting confidence it has no way
to back up.

### 21.4 Closing the gap CI cannot: a beta-tester issue template

`.github/ISSUE_TEMPLATE/beta-test-device-enumeration.yml`, a GitHub issue
form rather than a plain markdown template - structured fields (OS/distro,
what device was plugged in, the full `devices --all` output, a direct
"was it classified correctly" dropdown) are easier for a non-technical
tester to fill in correctly and easier for a maintainer to triage at a
glance than free-form prose would be.

Asks specifically for the **entire** `devices --all` output, not just the
one entry for the tester's own USB device: seeing every entry is what
lets a maintainer confirm the device was correctly picked out from
everything else present, not merely that its own entry looks plausible
in isolation - the same "prove the negative case, not only the positive
one" discipline this whole phase has followed elsewhere, applied here to
what a *human* reporter can usefully attest to.

Deliberately requests raw, unedited output even when something looks
wrong or the tool crashes: a "this looks broken" report is exactly as
useful as a "this looks correct" one, and is often more useful, since it
is the only way §21.2's and §21.3's remaining unverified pieces (the USB
property key strings on macOS specifically) get checked against reality
at all.

README.md's Platform support table now links directly to this template
from the one row that still reads "implemented, unverified on real
hardware" - the honest state this phase closes with, not silently
smoothed over into an unqualified checkmark.
