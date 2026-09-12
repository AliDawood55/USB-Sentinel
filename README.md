# USB Sentinel

An offline-first USB malware scanning engine, written in C17. Windows is
the released and fully supported platform; the portable core, the
detection engine and the CLI now also build and pass their full test
suite on Linux and macOS — see [Platform support](#platform-support).

## Download & Install

**[⬇ Download the latest release](https://github.com/AliDawood55/USB-Sentinel/releases/latest)**
— grab `USB Sentinel-1.0.0-win64.exe` from the Assets section and run it.
No Administrator rights are needed or requested; see
[Installation](#installation) below for what the installer does.

> **A security warning is expected — here's why.** This is a free,
> open-source project without a paid code-signing certificate, so
> Windows SmartScreen or your browser (Chrome/Edge) will likely flag the
> installer as coming from an "unrecognized publisher." This is normal
> for unsigned open-source software and not a sign the file is unsafe:
>
> - **Browser download warning:** click **Keep** (or "Keep anyway") when
>   Chrome/Edge flags the download.
> - **Windows SmartScreen:** click **More info**, then **Run anyway**.
>
> You can verify the source yourself — this is an open-source project,
> so the full code behind the release is right here in this repository.

**Status: v1.0.0.** USB Sentinel enumerates USB devices, scans them
read-only, and produces a JSON + CSV + text report — from either the CLI
(`usb-sentinel.exe`) or a native GUI (`usb-sentinel-gui.exe`), two
independent consumers of the same scan engine; running one never affects
the other. Four detectors run on every scan: `autorun.inf` inspection,
suspicious-filename detection (disguised executables), `.lnk` shortcut
inspection, and a hash-match detector against a signature file you
supply. The GUI's device list updates live on insert/removal and can
optionally auto-scan a newly inserted device (opt-in, off by default).
The codebase has been through a dedicated hardening pass — an
AddressSanitizer build and a full MSVC static-analysis (`/analyze`) audit,
both clean — on top of the detector-level defensive parsing already in
place for `.lnk` files and JSON. See [CHANGELOG.md](CHANGELOG.md) for the
full phase-by-phase history and [ARCHITECTURE.md](ARCHITECTURE.md) for
the reasoning behind every design decision.

**Known validation gaps**, stated plainly rather than left implicit:
physical device removal during an active scan has been verified only by
local simulation, not against real hardware (`ARCHITECTURE.md` §10.6).
Genuine `WM_DEVICECHANGE` delivery *was* confirmed against real
hardware — a real physical unplug/replug, by hand — after an automated
synthetic injection attempt was correctly rejected by Windows itself
before reaching this project's code (§15.5). Per-monitor DPI awareness is
not implemented (§17.7); the window is usable but slightly soft on a
high-DPI display via Windows' own bitmap scaling. See
[TASKS.md](TASKS.md)'s "Post-v1.0" section for the full list of what is
deliberately out of scope for this release.

## Safety policy

These are hard design constraints, not future goals:

- **Read-only by default.** USB Sentinel does not delete, quarantine, move, or
  modify user files.
- **Fully offline.** No network access, no cloud lookups, no telemetry.
- **No sample execution.** Suspect files are inspected as data, never run.
- **No silent action.** Anything beyond read-only inspection (the GUI's
  auto-scan, the installer's launch-at-login shortcut) is explicit,
  opt-in, and off by default.

## Table of contents

- [Download & Install](#download--install)
- [Installation](#installation)
- [Building from source](#building-from-source)
- [CLI usage](#cli-usage)
- [GUI usage](#gui-usage)
- [Signature list setup](#signature-list-setup)
- [Reports](#reports)
- [Privileges](#privileges)
- [Tests and hardening builds](#tests-and-hardening-builds)
- [Layout](#layout)
- [License](#license)

## Installation

For everyday use, a per-user installer is available via `cpack` — no
Administrator rights needed, and none requested. It needs
[NSIS](https://nsis.sourceforge.io/Download) 3.03 or newer installed
separately; neither CMake nor Visual Studio bundles it.

```powershell
cmake --preset x64-release
cmake --build --preset x64-release
cd build\x64-release
cpack
```

This produces `USB Sentinel-1.0.0-win64.exe` in `build\x64-release\`.
Running it installs both executables under
`%LOCALAPPDATA%\Programs\USB Sentinel\bin\`, adds a Start Menu shortcut
for the GUI, and never requests elevation — the installer itself runs
unelevated, matching the tool's own `asInvoker`, no-elevation model. An
optional checkbox on the last page, **unchecked by default** ("Launch
USB Sentinel when I log in"), adds a Startup-folder shortcut that opens
the GUI window at login — nothing more. It does not enable auto-scan or
start any background process; the GUI's own "Auto-scan new devices"
checkbox (see [GUI usage](#gui-usage) below) is a separate, independent,
also-off-by-default decision.

Uninstalling (Settings → Apps, or the Start Menu shortcut) removes only
what the installer placed under `%LOCALAPPDATA%\Programs\USB Sentinel\`
plus the Start Menu / Startup shortcuts — it never touches
`%LOCALAPPDATA%\USBSentinel\` (your scan history and signatures file), a
separate directory tree the uninstaller has no reference to.

The installer is unsigned — there is no code-signing certificate for
this project — so Windows SmartScreen will likely warn on first run; see
[Download & Install](#download--install) above for how to get past that
warning. See `ARCHITECTURE.md` §16 for the full packaging design,
including a real CPack/NSIS pitfall found and worked around during
development.

## Platform support

Phase 14 made the core cross-platform. Being precise about what that does
and does not yet mean, because "cross-platform" is easy to over-claim:

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Portable core, detectors, reporting | ✅ | ✅ | ✅ |
| Filesystem traversal, hashing, cancellation | ✅ | ✅ | ✅ |
| Full test suite in CI | ✅ 18/18 | ✅ 17/17 | ✅ (build + negative-path only) |
| `scan <path>`, given a directory | ✅ | ✅ | ✅ |
| USB device enumeration (`devices`, automatic `scan`) | ✅ real hardware | ✅ real hardware | ⚠️ implemented, unverified on real hardware |
| GUI | ✅ | ❌ deferred | ❌ deferred |
| Installer / released binary | ✅ | ❌ | ❌ |

**What this means in practice today.** Enumeration is implemented on all
three platforms: sysfs + `/proc/self/mountinfo` on Linux, IOKit +
DiskArbitration on macOS. Linux's is verified against real hardware in
the sense that matters most for CI - a real, if virtual, block device
(a loop device) proves the classification logic is not fooled by a
non-USB device, alongside deterministic fixture tests exercising the
ancestry walk directly. **macOS's is not**: no Mac was available to build
or test it here at all, so it has only ever compiled (hopefully) and run
its own negative-path proof (a `hdiutil` disk image, correctly not
misclassified) in CI - never against an actual USB device. If you have a
Mac, **[testing this takes about 5 minutes and is genuinely useful]
(https://github.com/AliDawood55/USB-Sentinel/issues/new?template=beta-test-device-enumeration.yml)** -
run `usb-sentinel devices --all` with a USB stick plugged in and share
the output. `usb-sentinel scan <path>`, given an explicit directory, does
not depend on any of this and works identically on all three platforms
today (see the row above).

SHA-256 comes from Windows CNG, Apple's CommonCrypto, or a vendored
implementation on Linux (which has no first-party provider); configure
with `-DUSBS_USE_OPENSSL=ON` to link the system crypto library instead.
There are no other third-party dependencies on any platform.

## Building from source

### Prerequisites

#### Linux and macOS

A C17 compiler and CMake 3.21 or newer — nothing else. Verified in CI on
every push against GCC 13 and Clang 18 (Ubuntu) and Apple Clang (macOS):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The Windows-only GUI and its installer are excluded automatically; the
core, CLI and full test suite are what build here.

#### Windows

Verified on the development machine for this project:

| Requirement | Version used |
| --- | --- |
| Windows | 11 Pro (10.0.26200) |
| Visual Studio 2022 | Community 17.14 |
| MSVC toolset | 14.44.35207 (`cl.exe` 19.44.35228, x64) |
| Windows SDK | 10.0.26100.0 |
| CMake | 3.31.6-msvc6 |
| Ninja | 1.12.1 |
| Git | 2.54.0 |

CMake and Ninja are **not installed by default** with Visual Studio. Install
them through the Visual Studio Installer:

> Visual Studio Installer → Modify (VS 2022) → Individual components →
> **C++ CMake tools for Windows**

This places `cmake.exe`, `ctest.exe`, and `ninja.exe` inside the Visual Studio
tree. They are **not added to the system PATH**, so all build commands must run
inside a Visual Studio developer environment (see below). The optional
AddressSanitizer preset (below) additionally needs the **C++
AddressSanitizer** individual component.

### Build

Open **Developer PowerShell for VS 2022** (Start menu), then:

```powershell
cd C:\Projects\USB-Sentinel

# Debug
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug

# Release
cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release
```

From an ordinary PowerShell prompt, enter the developer environment first:

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64
```

Build output lands in `build/<preset>/`. The CLI executable is at
`build/<preset>/src/app/usb-sentinel.exe`; the GUI is at
`build/<preset>/src/app_gui/usb-sentinel-gui.exe`.

### Build options and presets

| Option | Default | Effect |
| --- | --- | --- |
| `USBS_WERROR` | `OFF` | Treat compiler warnings as errors (`/WX`) |
| `USBS_ASAN` | `OFF` | Build with MSVC's native AddressSanitizer (`/fsanitize=address`) |
| `USBS_ANALYZE` | `OFF` | Build with MSVC static analysis (`/analyze`, PREfast) |

```powershell
cmake --preset x64-debug -DUSBS_WERROR=ON
```

Two extra presets exist specifically for the hardening builds described
in `ARCHITECTURE.md` §18 — not needed for day-to-day development, but
useful before a release or after touching parser/detector code:

```powershell
# AddressSanitizer: run the ASan runtime DLL's directory needs to be on
# PATH (see below) or a fresh ASan build will fail with STATUS_DLL_NOT_FOUND.
cmake --preset x64-asan
cmake --build --preset x64-asan
$env:PATH = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\<version>\bin\Hostx64\x64;$env:PATH"
ctest --preset x64-asan

# Static analysis
cmake --preset x64-analyze
cmake --build --preset x64-analyze
```

## CLI usage

```powershell
.\build\x64-debug\src\app\usb-sentinel.exe devices
.\build\x64-debug\src\app\usb-sentinel.exe devices --all
.\build\x64-debug\src\app\usb-sentinel.exe scan
.\build\x64-debug\src\app\usb-sentinel.exe scan E:
.\build\x64-debug\src\app\usb-sentinel.exe scan --signatures C:\path\to\signatures.txt
.\build\x64-debug\src\app\usb-sentinel.exe version
.\build\x64-debug\src\app\usb-sentinel.exe help
```

- `devices` lists every USB storage device currently attached (bus type,
  hardware strings, VID/PID/serial-derived identity, mount points,
  filesystem, capacity, and which raw-access capabilities are available
  unelevated). `--all` also lists non-USB volumes, for comparison.
- `scan [target] [--signatures <path>]` — `target` is optional (the first
  scannable USB device found), a drive letter (`E:`), or a substring of a
  device identity. The scan walks the device read-only, runs every
  registered detector, prints a text report, and saves the same report as
  JSON and CSV (see [Reports](#reports)). `--signatures <path>` is
  documented under [Signature list setup](#signature-list-setup).
- `version` / `help` are self-explanatory.

Ctrl+C cancels an in-progress scan cleanly — the report is still produced
and saved, marked `aborted`, with every check that didn't get to run
recorded as `skipped`, never silently missing.

Exit code is `0` on success, `1` on any error, and also `1` when a scan
completes but is marked `aborted` (cancelled, or the device was
disconnected mid-scan) — the report itself is still valid and saved
either way.

## GUI usage

```powershell
.\build\x64-debug\src\app_gui\usb-sentinel-gui.exe
```

A native window: pick a device from the dropdown (or click Refresh — the
list also updates on its own when a USB device is inserted or removed),
click Scan, watch the progress bar and live file/byte count while it
runs, Cancel to stop early. The progress bar is only on screen while a
scan is actually running, and fills against the volume's
filesystem-reported bytes-in-use; where that figure is unavailable it
falls back to an indeterminate marquee rather than showing an invented
percentage.

Results are shown as a sectioned, bulleted report with severity
colouring, under a banner carrying the overall verdict. **Green "ALL
CLEAR" is deliberately hard to earn:** it requires the scan to have
completed *and* every check to have run *and* nothing above
informational severity to have been found. A cancelled scan, a
disconnected device, or a check that was skipped or failed produces
"SCAN INCOMPLETE" with the specific reason instead — zero findings is not
the same claim as a clean device, and that distinction is worth more than
a reassuring colour (`ARCHITECTURE.md` §17.3).

"Open Reports Folder" opens the exact folder the `.json`/`.csv` pair for
that scan just landed in — the GUI does not attempt to display JSON/CSV
content directly (`ARCHITECTURE.md` §14.4). "Auto-scan new devices" (off
by default) scans a newly inserted device automatically instead of
waiting for a click — the same read-only scan either way, just started
without a Scan click, so it is opt-in per the safety policy's "no silent
action" posture. It is a second, independent consumer of the same scan
engine the CLI uses, not a layer on top of the CLI: `usb-sentinel.exe` is
unaffected by anything in this section.

## Signature list setup

The hash-match detector matches file content by SHA-256 against a list
you provide — it does **not** ship, fetch, or vet a signature database
itself. Point it at a file with `--signatures <path>`, or place one at
the default location, `%LOCALAPPDATA%\USBSentinel\signatures.txt`. If
neither is found, it falls back to one hardcoded entry (the SHA-256 of
the industry-standard EICAR test string) purely to demonstrate the
detection path without needing real malware. **The report's disclaimer
always states honestly which of the two states applied** — a real file
loaded (with its path and entry count) or the built-in fallback — never
silently one or the other.

File format, one entry per line:

```
sha256:size:name
```

- `sha256` — the file's SHA-256 hash, 64 lowercase or uppercase hex
  characters (case-insensitive; normalized to lowercase on load).
- `size` — the exact file size in bytes. Size is genuinely part of the
  match key, not decoration: a right hash at the wrong size never
  matches, and files are size-filtered before ever being opened/hashed,
  so a signature list with many entries does not mean hashing every file
  on the device (`ARCHITECTURE.md` §13.1).
- `name` — a free-text label shown in the finding if this entry matches.

Blank lines and lines starting with `#` (optionally after leading
whitespace) are comments. A malformed line is skipped with a logged
warning; it never fails the whole load. Files up to 64 MiB are read; a
larger file is truncated at that point, with a warning.

```
# signatures.txt
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:EICAR test file
```

The format is **ClamAV-inspired, not a verified byte-for-byte ClamAV
implementation** — it has not been independently checked against real
ClamAV database files, and only the hash-list shape is supported (no
`.ndb`/`.ldb` byte-pattern or logical signature parsing; see
`ARCHITECTURE.md` §12.1 and `TASKS.md`'s "Post-v1.0" section). SHA-256
only, never MD5.

Sourcing, licensing, and how such a file would legitimately be kept
up to date while the tool stays fully offline are outside this project's
scope — USB Sentinel parses whatever local file you hand it and nothing
else.

## Reports

Every scan saves a matching JSON and CSV file under
`%LOCALAPPDATA%\USBSentinel\scans\<device-id>\<timestamp>-<scan-id>.json`
(and `.csv`, same stem) — one subdirectory per device identity (durable
across drive-letter changes; derived from USB VID/PID/serial, or the
volume GUID if no serial is exposed), one pair of files per scan. Writes
are atomic (temp file + rename), so a crash or a device pulled mid-write
never leaves a corrupt or partial report on disk.

- **JSON** is the primary, schema-versioned format
  (`schema_version: 1`): scan metadata, device identity, which
  capabilities were available, and every check explicitly marked `ran`,
  `skipped`, or `failed` — a check is never simply absent from the
  report, even when it found nothing or couldn't run.
- **CSV** is a flattened view of the same data (one row per finding, plus
  exactly one row for a check with zero findings, carrying its
  check-level message) generated automatically alongside the JSON — handy
  for a spreadsheet or feeding another tool. Fields are RFC 4180-quoted,
  with a formula-injection mitigation (a leading `=`, `+`, `-`, or `@` in
  attacker-influenced content gets a defanging leading `'` inside the
  quotes).
- **Text** is what the CLI prints to the console and what the GUI's
  results pane shows — rendered from the same underlying data as JSON and
  CSV, not a separate source of truth.

`%LOCALAPPDATA%\USBSentinel\index.json` is a self-healing cache of
"last scan per device", rewritten after every scan. It is deliberately
**not** authoritative: a missing or corrupted `index.json` only means it
gets silently rebuilt on the next write, never a wrong answer about scan
history. There is currently no built-in report browser (`report
list`/`report show`) — open the folder (the GUI's "Open Reports Folder"
button, or the path above) and use the JSON/CSV files directly, or feed
them to your own tooling.

## Privileges

USB Sentinel runs **unelevated** and never requests elevation. Enumeration,
identification, and file-level scanning all work as a standard user.

Only raw block access — boot sector and partition-table inspection — requires
Administrator (no detector uses it yet). When unavailable, `devices` prints
`raw volume unavailable (requires elevation)`, and a `scan` report's
`capabilities` field and any dependent check's `skip_reason` record the same
thing — **skipped, never silently dropped**. To enable raw access, re-run the
tool from an elevated Developer PowerShell deliberately; it will not prompt.

## Tests and hardening builds

Tests use a small in-repo harness (`tests/test_util.h`) and are registered
with CTest — no external test dependency, 17 executables covering the
portable core, the Win32 platform boundary, every detector (including
malformed-input and fuzz batteries for the `.lnk` parser, the JSON
reader/writer, and the signature-list loader), the scanner, storage, and
the GUI's testable core.

```powershell
ctest --preset x64-debug --output-on-failure
```

Before a release, or after touching any parsing code, the two hardening
presets from [Build options and presets](#build-options-and-presets) are
worth running too: `x64-asan` (memory-safety) and `x64-analyze`
(MSVC's static analyzer). Both are part of this project's own release
checklist — see `ARCHITECTURE.md` §18 for what they found and how each
finding was resolved.

## Layout

```
include/usbsentinel/   Public headers (the cross-module surface)
src/core/              Types, status codes, logging, version, JSON, env vars
src/cli/               Command dispatch
src/app/               CLI entry point (usb-sentinel.exe)
src/gui/               Native Win32 GUI: worker (testable) + window + report view
src/app_gui/           GUI entry point (usb-sentinel-gui.exe)
src/platform/          Device enumeration, Win32 boundary, capabilities
src/storage/           Report persistence (%LOCALAPPDATA%\USBSentinel)
src/scanner/           Traversal, hashing, orchestration
src/detectors/         Detector registry (autorun.inf, suspicious filenames, .lnk, hash-match)
src/reporting/         JSON/CSV report builders + text renderer
tests/                 CTest executables
packaging/             NSIS installer script included via CPack
resources/             Application icon source + generator script
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for design decisions,
[TASKS.md](TASKS.md) for phase tracking and what's deliberately out of
scope, [PROGRESS.md](PROGRESS.md) for the detailed work log, and
[CHANGELOG.md](CHANGELOG.md) for a summary of the full v1.0.0 development
history.

## License

MIT — see [LICENSE](LICENSE).
