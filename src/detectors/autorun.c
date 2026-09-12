/*
 * autorun.inf inspection.
 *
 * Historically the primary USB autorun-malware vector: an autorun.inf at the
 * volume root naming a program to launch via an "open="/"shellexecute="
 * directive. Windows has ignored autorun.inf-driven autoplay for non-optical
 * media since Vista SP2, but the file's presence and content remain a
 * well-known indicator worth recording for a forensic tool - this detector
 * only reads and inspects text, never executes anything (ARCHITECTURE.md
 * section 1: no sample execution).
 */
#include <stdio.h>
#include <string.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/platform.h"

#define AUTORUN_ID          "autorun_inspection"
#define AUTORUN_MAX_READ     8192 /* a legitimate autorun.inf is a few hundred bytes */

static usbs_bool contains_ci(const char *haystack, const char *needle)
{
    size_t h_len = strlen(haystack);
    size_t n_len = strlen(needle);
    size_t i;

    if (n_len == 0 || n_len > h_len) {
        return false;
    }
    for (i = 0; i + n_len <= h_len; ++i) {
        size_t j;
        usbs_bool match = true;
        for (j = 0; j < n_len; ++j) {
            char a = haystack[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

static usbs_status_t detect_autorun(const usbs_detect_context_t *ctx,
                                    usbs_check_result_t         *out_result)
{
    char          path[600];
    usbs_file_t  *file;
    usbs_status_t status;
    char          buf[AUTORUN_MAX_READ + 1];
    size_t        total = 0;

    if (ctx == NULL || out_result == NULL || ctx->volume_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_check_result_init(out_result, AUTORUN_ID);

    if (snprintf(path, sizeof(path), "%sautorun.inf", ctx->volume_path) < 0) {
        usbs_check_result_set_failed(out_result, "path too long");
        return USBS_OK;
    }

    status = usbs_platform_file_open_read(path, &file);
    if (status == USBS_ERR_NOT_FOUND) {
        /* No autorun.inf present: a completed, negative result. */
        return USBS_OK;
    }
    if (!usbs_ok(status)) {
        usbs_check_result_set_failed(out_result, usbs_status_string(status));
        return USBS_OK;
    }

    for (;;) {
        size_t read = 0;
        if (total >= AUTORUN_MAX_READ) {
            break;
        }
        status = usbs_platform_file_read(file, buf + total, AUTORUN_MAX_READ - total, &read);
        if (!usbs_ok(status)) {
            usbs_platform_file_close(file);
            usbs_check_result_set_failed(out_result, usbs_status_string(status));
            return USBS_OK;
        }
        if (read == 0) {
            break;
        }
        total += read;
    }
    usbs_platform_file_close(file);
    buf[total] = '\0';

    {
        usbs_finding_t finding;
        usbs_bool      has_open       = contains_ci(buf, "open=");
        usbs_bool      has_shellexec  = contains_ci(buf, "shellexecute=");

        memset(&finding, 0, sizeof(finding));
        snprintf(finding.path, sizeof(finding.path), "autorun.inf");

        if (has_open || has_shellexec) {
            finding.severity = USBS_SEVERITY_WARNING;
            snprintf(finding.message, sizeof(finding.message),
                     "autorun.inf present and specifies a launch command (%s)",
                     has_open ? "open=" : "shellexecute=");
        } else {
            finding.severity = USBS_SEVERITY_INFO;
            snprintf(finding.message, sizeof(finding.message),
                     "autorun.inf present (%zu bytes), no launch command found",
                     total);
        }
        usbs_finding_list_push(&out_result->findings, &finding);
    }

    return USBS_OK;
}

const usbs_detector_t usbs_detector_autorun = {
    .id          = AUTORUN_ID,
    .description = "Inspects autorun.inf at the volume root for a launch directive",
    .run         = detect_autorun,
    /* .on_file omitted: a single fixed path is O(1), no walk needed. */
};
