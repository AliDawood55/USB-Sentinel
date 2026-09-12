/*
 * `usb-sentinel scan [target]` - orchestrates platform + scanner + storage +
 * reporting for one device. `target`, if given, matches a mount point (e.g.
 * "E:") or a substring of the device identity; with no target, the first
 * USB device with media present is scanned.
 */
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "usbsentinel/env.h"
#include "usbsentinel/log.h"
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

usbs_status_t usbs_cli_cmd_scan(int argc, char **argv)
{
    const char           *target          = NULL;
    const char           *signatures_path = NULL;
    usbs_device_source_t  source;
    usbs_device_list_t    list;
    const usbs_device_t  *chosen = NULL;
    usbs_status_t         status;
    usbs_store_t          store;
    usbs_scan_result_t    result;
    int                   arg;
    size_t                i;
    usbs_bool             success;

    for (arg = 2; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--signatures") == 0) {
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

    if (signatures_path != NULL) {
        /* Env-var indirection, not a direct call into hash_match.c: cli
         * stays ignorant of which detector (if any) consumes this -
         * hash_match.c's own header comment explains the reasoning. */
        if (!usbs_ok(usbs_setenv(HASH_MATCH_SIGNATURES_ENV_OVERRIDE, signatures_path))) {
            fprintf(stderr, "scan: could not set the signature file path\n");
            return USBS_ERR_INTERNAL;
        }
    }

    source = usbs_platform_device_source();
    status = usbs_device_enumerate(&source, &list);
    if (!usbs_ok(status)) {
        fprintf(stderr, "scan: enumeration failed: %s\n", usbs_status_string(status));
        return status;
    }

    for (i = 0; i < list.count; ++i) {
        const usbs_device_t *device = &list.items[i];
        if (device->bus_type != USBS_BUS_USB || !device->media_present) {
            continue;
        }
        if (!device_matches(device, target)) {
            continue;
        }
        chosen = device;
        break;
    }

    if (chosen == NULL) {
        if (target != NULL) {
            fprintf(stderr, "scan: no USB device matching \"%s\" found\n", target);
        } else {
            fprintf(stderr, "scan: no USB device found\n");
        }
        usbs_device_list_free(&list);
        return USBS_ERR_NOT_FOUND;
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

    /* `chosen` points into `list`; it stays valid for the whole scan and is
     * not referenced again after usbs_scanner_scan() returns. */
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
