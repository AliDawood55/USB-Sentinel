/*
 * USB Sentinel - location policy for internal-drive scans (Phase 17.1,
 * ARCHITECTURE.md section 24).
 *
 * Every heuristic detector was tuned for a USB stick, where a filename such
 * as "invoice.pdf.lnk" has one plausible explanation. On a system drive the
 * same shape is produced routinely by the OS and by developer tooling:
 * Windows writes "<document>.<ext>.lnk" into Recent Items for every file a
 * user opens, Start Menu shortcuts legitimately launch cmd.exe and
 * powershell.exe, and npm packages ship files like "Iterator.zip.js". This
 * module says *where* a path is, so detectors can decide how much a match
 * there means.
 *
 * Deliberately NOT a skip list. A path's location changes how a finding is
 * weighed, never whether the volume is examined, with one exception:
 * USBS_LOCATION_SELF_TEST_FIXTURES, which is this project's own test
 * scratch data. Every other location is still inspected in full, and
 * detectors report what the policy suppressed or lowered (see
 * usbs_check_result_t's policy counters).
 *
 * The policy applies only to a device on a *known non-USB* bus. A USB stick,
 * including an external USB disk, keeps the strict rules, because its
 * filenames are exactly what an attacker controls. So does an unknown-bus
 * `scan <path>` target: the policy is never a default someone could meet by
 * accident.
 *
 * Portable C17, pure string matching, no filesystem access. Paths are
 * relative to the volume root. Both '\' and '/' separate components, and
 * component matching is ASCII case-insensitive (Windows paths).
 */
#ifndef USBSENTINEL_LOCATION_H
#define USBSENTINEL_LOCATION_H

#include "usbsentinel/device.h"
#include "usbsentinel/types.h"

typedef enum usbs_location_kind {
    USBS_LOCATION_ORDINARY = 0,

    /* Where a user meets a file first, and where a disguised file is aimed:
     * Users\<u>\Desktop and Downloads (also under OneDrive),
     * Users\<u>\AppData\Local\Temp (opened attachments and archives extract
     * there), and both Start Menu "Startup" folders (a classic persistence
     * location, MITRE ATT&CK T1547.001). Heuristics keep full severity. */
    USBS_LOCATION_USER_EXPOSED,

    /* Start Menu program shortcuts, per-user and all-users, excluding
     * Startup (which is USER_EXPOSED). */
    USBS_LOCATION_OS_SHORTCUTS,

    /* Windows\WinSxS: the TrustedInstaller-owned component store. It holds
     * OS shortcut payloads and delta-compressed files that merely end in
     * ".lnk". */
    USBS_LOCATION_OS_COMPONENT_STORE,

    /* A "Recent" folder under Users\<u>\AppData\Roaming: Windows' Recent
     * Items (Microsoft\Windows\Recent), Office's, and applications' own
     * recent-file folders (e.g. Autodesk\...\Recent). Shortcuts there are
     * generated as "<opened file name>.lnk". */
    USBS_LOCATION_RECENT_ITEMS,

    /* Package-manager and build-intermediate trees: node_modules,
     * site-packages, .gradle, .m2, and build\[<module>\]intermediates
     * (Gradle, and Flutter's nested Android build).
     * Third-party files whose names the user did not choose. */
    USBS_LOCATION_DEPENDENCY_TREE,

    /* This project's own test scratch directories,
     * "...\build\...\tests\test_<name>_scratch_<8 hex>\". Their disguised
     * names are deliberate fixtures, so the walk does not descend into
     * them. */
    USBS_LOCATION_SELF_TEST_FIXTURES
} usbs_location_kind_t;

/* True when location-aware tuning applies to scans of `device`: a known
 * non-USB bus (SATA, NVMe, SCSI, SD, other, network). False for USB, for an
 * unknown bus, and for NULL. */
usbs_bool usbs_location_policy_applies(const usbs_device_t *device);

/* Classifies `relative_path` (a file or directory path relative to the
 * volume root). Precedence, first match wins:
 * SELF_TEST_FIXTURES, USER_EXPOSED, DEPENDENCY_TREE, RECENT_ITEMS,
 * OS_COMPONENT_STORE, OS_SHORTCUTS, ORDINARY. USER_EXPOSED outranks the
 * tuned kinds on purpose, so a Startup folder inside the Start Menu, or a
 * node_modules tree inside Downloads, keeps full severity. NULL is
 * ORDINARY. */
usbs_location_kind_t usbs_location_classify(const char *relative_path);

/* A short human-readable label, e.g. "Windows Recent Items". Never NULL. */
const char *usbs_location_kind_string(usbs_location_kind_t kind);

/* `full_path` with a leading `volume_path` prefix removed, when present;
 * otherwise `full_path` itself. NULL-safe for `volume_path`. */
const char *usbs_location_relative(const char *volume_path, const char *full_path);

#endif /* USBSENTINEL_LOCATION_H */
