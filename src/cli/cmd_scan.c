/*
 * `usb-sentinel scan [target]` - orchestrates platform + scanner + storage +
 * reporting for one device. `target`, if given, matches a mount point (e.g.
 * "E:") or a substring of the device identity; with no target, the first
 * USB device with media present is scanned.
 *
 * Phase 14 (ARCHITECTURE.md section 20.11): if `target` matches no
 * enumerated device - including when enumeration itself is unsupported,
 * which is the normal state on POSIX until Phase 14b implements it - and it
 * names an openable directory, that directory is scanned directly. This is
 * what makes `scan` usable at all on a host with no enumeration backend, and
 * is equally useful on Windows for a volume mounted into a folder rather
 * than a drive letter. Device matching is tried first and always wins: a
 * path is a fallback for when nothing enumerated matches, not a way to
 * bypass it.
 */
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "usbsentinel/env.h"
#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/report.h"
#include "usbsentinel/scanner.h"
#include "usbsentinel/storage.h"

/* Must match hash_match.c's HASH_MATCH_SIGNATURES_ENV_OVERRIDE - duplicated
 * here rather than shared via a header, since this is the one, deliberate,
 * narrow point where cli passes a value down to a specific detector without
 * knowing anything else about it (ARCHITECTURE.md's Phase 6 notes). */
#define HASH_MATCH_SIGNATURES_ENV_OVERRIDE "USBS_HASH_MATCH_SIGNATURES"

static usbs_bool cli_cancel_check(void *ctx)
{
    USBS_UNUSED(ctx);
    return usbs_platform_cancel_requested();
}

static usbs_bool device_matches(const usbs_device_t *device, const char *target)
{
    usbs_u32 i;
    char     identity[USBS_IDENTITY_MAX];

    if (target == NULL) {
        return true;
    }
    for (i = 0; i < device->mount_point_count; ++i) {
        if (strcmp(device->mount_points[i], target) == 0) {
            return true;
        }
    }
    if (usbs_ok(usbs_device_identity(device, identity, sizeof(identity))) &&
        strstr(identity, target) != NULL) {
        return true;
    }
    return false;
}

/*
 * Not declared in any public header - the same pattern hash_match.c uses
 * for usbs_hash_match_lookup(): an internal surface tests/test_cmd_scan.c
 * links against directly, so the path-target logic below is exercised
 * without a test having to mock usbs_store_open() (which resolves the real
 * per-user data directory) or an enumeration source.
 *
 * Builds a synthetic device for a target that is a filesystem path rather
 * than an enumerated USB volume.
 *
 * Deliberately honest rather than inferred: bus_type stays USBS_BUS_UNKNOWN
 * and vendor/product/serial/usb_vid/usb_pid/capacity_bytes/free_bytes all
 * stay at usbs_device_init()'s zeroed defaults, because none of it was
 * actually queried - a bare directory was never enumerated, so claiming
 * otherwise would be exactly the confident-but-wrong answer
 * ARCHITECTURE.md section 7.3 exists to prevent for a real device.
 * usbs_device_identity() then falls back to "volume:<path>", a less
 * specific but honest identity - see ARCHITECTURE.md section 20.11.
 */
usbs_status_t usbs_cli_build_path_device(const char *path, usbs_device_t *out_device)
{
    usbs_dir_iter_t *probe = NULL;
    usbs_status_t    status;

    if (path == NULL || out_device == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    usbs_device_init(out_device);

    /* Bounds first, filesystem second: a path too long for volume_path is
     * rejected without ever touching the filesystem, rather than failing
     * with a confusing "not found" for a path that might well exist but
     * simply cannot be stored. volume_path carries a trailing separator by
     * definition (device.h) - scanner.c's walk and every detector's
     * path-building rely on it. usbs_path_join(..., "") is a reuse, not a
     * new idiom: with an empty leaf it appends exactly one separator when
     * `path` lacks one and leaves it alone when `path` already ends with
     * one. */
    status = usbs_path_join(out_device->volume_path, sizeof(out_device->volume_path),
                            path, "");
    if (!usbs_ok(status)) {
        return status; /* USBS_ERR_NO_MEMORY: path too long for volume_path */
    }

    /* Confirms the path is actually an openable directory before scanner.c
     * ever sees it, so a bad path gets one clear, specific error here
     * rather than a walk failure several layers in. Rejects a plain file
     * too: opendir()/FindFirstFileW("...\*") both fail on one. Checked
     * against the now-normalized volume_path rather than the raw `path`
     * argument - the trailing separator path_join may have appended does
     * not change what directory is being named. */
    status = usbs_platform_dir_open(out_device->volume_path, &probe);
    if (!usbs_ok(status)) {
        return status;
    }
    usbs_platform_dir_close(probe);

    out_device->bus_type      = USBS_BUS_UNKNOWN;
    out_device->media_present = true;

    /* Decorative (shown in output, not part of usbs_device_identity()'s
     * key), so truncation of an implausibly long path here is acceptable. */
    snprintf(out_device->mount_points[0], sizeof(out_device->mount_points[0]),
             "%s", path);
    out_device->mount_point_count = 1;

    return USBS_OK;
}

usbs_status_t usbs_cli_cmd_scan(int argc, char **argv)
{
    const char           *target          = NULL;
    const char           *signatures_path = NULL;
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *chosen = NULL;
    usbs_device_t         path_device; /* backing storage when `chosen` falls
                                        * back to a path target below */
    usbs_status_t         status;
    usbs_status_t         enum_status;
    usbs_store_t          store;
    usbs_scan_result_t    result;
    int                   arg;
    size_t                i;
    usbs_bool             success;
    usbs_enum_mode_t      mode = USBS_ENUM_USB_ONLY;

    for (arg = 2; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--all") == 0) {
            mode = USBS_ENUM_ALL_VOLUMES;
        } else if (strcmp(argv[arg], "--signatures") == 0) {
            if (arg + 1 >= argc) {
                fprintf(stderr, "scan: --signatures requires a path\n");
                return USBS_ERR_INVALID_ARG;
            }
            signatures_path = argv[++arg];
        } else if (target == NULL) {
            target = argv[arg];
        } else {
            fprintf(stderr, "scan: unexpected argument: %s\n", argv[arg]);
            return USBS_ERR_INVALID_ARG;
        }
    }

    /* Phase 17: with no target, `scan` picks the first match. That is the
     * right default among USB sticks and exactly the wrong one among every
     * volume, where "first" is whatever FindFirstVolumeW returns (usually
     * the system drive). A multi-hour scan of C: is never an implicit
     * choice. */
    if (mode == USBS_ENUM_ALL_VOLUMES && target == NULL) {
        fprintf(stderr, "scan: --all requires a target, e.g. \"usb-sentinel scan C: --all\"\n");
        return USBS_ERR_INVALID_ARG;
    }

    if (signatures_path != NULL) {
        /* Env-var indirection, not a direct call into hash_match.c: cli
         * stays ignorant of which detector (if any) consumes this -
         * hash_match.c's own header comment explains the reasoning. */
        if (!usbs_ok(usbs_setenv(HASH_MATCH_SIGNATURES_ENV_OVERRIDE, signatures_path))) {
            fprintf(stderr, "scan: could not set the signature file path\n");
            return USBS_ERR_INTERNAL;
        }
    }

    /*
     * Enumeration failing here (USBS_ERR_UNSUPPORTED, the normal state on
     * POSIX until Phase 14b) is not treated as a hard error: out_list is
     * still initialized to empty per usbs_device_enumerate()'s contract, so
     * the matching loop below simply finds nothing, and a path target still
     * gets its chance further down. Only when there is neither a match nor
     * a target to fall back on does enum_status become part of the error
     * message.
     */
    source = usbs_platform_device_source_ex(mode);
    enum_status = usbs_device_enumerate(&source, &list);

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];
        if (!usbs_device_is_scannable(device, mode)) {
            continue;
        }
        if (!device_matches(device, target)) {
            continue;
        }
        chosen = device;
        break;
    }

    if (chosen == NULL && target != NULL) {
        /* No enumerated device matched (or none could be enumerated at
         * all) - fall back to treating `target` as a directory to scan
         * directly. See this file's header comment and ARCHITECTURE.md
         * section 20.11. */
        if (usbs_ok(usbs_cli_build_path_device(target, &path_device))) {
            chosen = &path_device;
        }
    }

    if (chosen == NULL) {
        if (target != NULL) {
            fprintf(stderr,
                    "scan: no %s matching \"%s\" found, and it is not "
                    "a directory that can be scanned\n",
                    (mode == USBS_ENUM_ALL_VOLUMES) ? "volume" : "USB device", target);
        } else if (!usbs_ok(enum_status)) {
            fprintf(stderr,
                    "scan: automatic USB device detection is unavailable on "
                    "this platform (%s)\n"
                    "scan: pass a directory path to scan explicitly, e.g. "
                    "\"usb-sentinel scan /path/to/volume\"\n",
                    usbs_status_string(enum_status));
        } else {
            fprintf(stderr, "scan: no USB device found\n");
        }
        usbs_device_list_free(&list);
        return usbs_ok(enum_status) ? USBS_ERR_NOT_FOUND : enum_status;
    }

    status = usbs_store_open(&store);
    if (!usbs_ok(status)) {
        fprintf(stderr, "scan: could not open the report store: %s\n",
                usbs_status_string(status));
        usbs_device_list_free(&list);
        return status;
    }

    if (!usbs_ok(usbs_platform_install_cancel_handler())) {
        USBS_LOG_W("Ctrl+C cancellation is unavailable on this platform");
    }
    printf("Scanning... (Ctrl+C to cancel)\n\n");

    /* `chosen` points either into `list` or at the local `path_device`;
     * either way it stays valid for the whole scan (usbs_scanner_scan()
     * copies *device before returning) and is not referenced again after
     * this call. */
    status = usbs_scanner_scan(chosen, &store, cli_cancel_check, NULL, NULL, NULL, &result);
    usbs_device_list_free(&list);
    chosen = NULL;

    if (!usbs_ok(status)) {
        fprintf(stderr, "scan: failed: %s\n", usbs_status_string(status));
        return status;
    }

    usbs_report_render_text(&result, stdout);

    {
        char       identity[USBS_IDENTITY_MAX];
        usbs_bool  have_identity =
            usbs_ok(usbs_device_identity(&result.device, identity, sizeof(identity)));

        {
            char   *json_text = NULL;
            size_t  json_len  = 0;

            status = usbs_report_build_json(&result, &json_text, &json_len);
            if (usbs_ok(status)) {
                if (have_identity) {
                    char          saved_path[USBS_STORE_PATH_MAX];
                    usbs_status_t write_status = usbs_store_write_report(
                        &store, identity, result.scan_id, result.started_at,
                        json_text, json_len, saved_path, sizeof(saved_path));
                    if (usbs_ok(write_status)) {
                        printf("\nReport saved: %s\n", saved_path);
                    } else {
                        fprintf(stderr, "scan: could not save report: %s\n",
                                usbs_status_string(write_status));
                    }
                }
                free(json_text);
            } else {
                fprintf(stderr, "scan: could not build report: %s\n", usbs_status_string(status));
            }
        }

        /* CSV is a companion to the JSON report, not a replacement - saved
         * alongside it automatically, the same way JSON and the text
         * console output already both happen without a flag. */
        {
            char   *csv_text = NULL;
            size_t  csv_len  = 0;

            status = usbs_report_build_csv(&result, &csv_text, &csv_len);
            if (usbs_ok(status)) {
                if (have_identity) {
                    char          saved_path[USBS_STORE_PATH_MAX];
                    usbs_status_t write_status = usbs_store_write_report_csv(
                        &store, identity, result.scan_id, result.started_at,
                        csv_text, csv_len, saved_path, sizeof(saved_path));
                    if (usbs_ok(write_status)) {
                        printf("CSV saved:    %s\n", saved_path);
                    } else {
                        fprintf(stderr, "scan: could not save CSV report: %s\n",
                                usbs_status_string(write_status));
                    }
                }
                free(csv_text);
            } else {
                fprintf(stderr, "scan: could not build CSV report: %s\n",
                        usbs_status_string(status));
            }
        }
    }

    success = (result.status == USBS_SCAN_COMPLETED);
    usbs_scan_result_free(&result);

    /* An aborted (cancelled or device-removed) scan still produced and saved
     * a valid, honest report; the non-zero exit code just tells scripts it
     * did not run to completion. */
    return success ? USBS_OK : USBS_ERR_IO;
}
