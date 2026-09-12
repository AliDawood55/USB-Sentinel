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
#define AUTORUN_FILENAME    "autorun.inf"

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

/* ASCII case-insensitive equality, matching contains_ci's folding. */
static usbs_bool equals_ci(const char *a, const char *b)
{
    size_t i;

    for (i = 0; a[i] != '\0' && b[i] != '\0'; ++i) {
        char x = a[i];
        char y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) {
            return false;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

/*
 * Finds the volume root's autorun.inf whatever its on-disk capitalisation,
 * writing the real spelling into `out_name`.
 *
 * Opening "<volume>autorun.inf" directly - what this detector did before
 * Phase 14 - is only case-insensitive because NTFS and FAT are. On a
 * case-sensitive filesystem (ext4, and APFS when formatted case-sensitive)
 * that open matches nothing but the exact lowercase spelling, while the
 * autorun.inf specification is case-insensitive and the uppercase
 * AUTORUN.INF is the historically common form in precisely the malware this
 * detector exists to find. Inheriting case-sensitivity from the host
 * filesystem would mean the same stick reports a finding on Windows and
 * silently reports nothing on Linux, which is the worst available outcome
 * for a forensic tool.
 *
 * So detection semantics are fixed in the detector: list the root once and
 * compare names case-insensitively, rather than guess at spellings (there
 * are 2^11 of them) or trust the filesystem. Folding is ASCII-only, which is
 * all "autorun.inf" needs and avoids pulling locale-dependent case rules
 * into a detection decision.
 *
 * Returns false if the listing fails or no match exists; the caller then
 * falls back to the literal lowercase name, preserving the old behaviour.
 */
static usbs_bool find_autorun_name(const char *volume_path, char *out_name,
                                   size_t cap)
{
    usbs_dir_iter_t *iter = NULL;
    usbs_dir_entry_t entry;

    if (!usbs_ok(usbs_platform_dir_open(volume_path, &iter))) {
        return false;
    }

    while (usbs_ok(usbs_platform_dir_next(iter, &entry))) {
        if (entry.is_directory) {
            continue;
        }
        if (equals_ci(entry.name, AUTORUN_FILENAME)) {
            int written = snprintf(out_name, cap, "%s", entry.name);
            usbs_platform_dir_close(iter);
            return written > 0 && (size_t)written < cap;
        }
    }

    usbs_platform_dir_close(iter);
    return false;
}

static usbs_status_t detect_autorun(const usbs_detect_context_t *ctx,
                                    usbs_check_result_t         *out_result)
{
    /* Sized from the two bounds it actually concatenates. The previous flat
     * 600 was comfortable only while a volume path was a 49-character
     * Windows volume GUID; see ARCHITECTURE.md section 20.1. */
    char          path[USBS_VOLUME_PATH_MAX + USBS_NAME_MAX];
    char          name[USBS_NAME_MAX];
    usbs_file_t  *file;
    usbs_status_t status;
    char          buf[AUTORUN_MAX_READ + 1];
    size_t        total = 0;
    int           written;

    if (ctx == NULL || out_result == NULL || ctx->volume_path == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    usbs_check_result_init(out_result, AUTORUN_ID);

    if (!find_autorun_name(ctx->volume_path, name, sizeof(name))) {
        /* The root could not be listed, or holds no autorun.inf under any
         * capitalisation. Fall back to the canonical spelling so a volume
         * whose root resists listing behaves exactly as it did before, and
         * so a genuinely absent file still surfaces as USBS_ERR_NOT_FOUND
         * from the open below rather than as a check failure. */
        snprintf(name, sizeof(name), "%s", AUTORUN_FILENAME);
    }

    /* Truncation is now checked, not just encoding failure: `path` holds a
     * volume path plus a filename, and both bounds grew in Phase 14. */
    written = snprintf(path, sizeof(path), "%s%s", ctx->volume_path, name);
    if (written < 0 || (size_t)written >= sizeof(path)) {
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
        /* The real on-disk spelling, not the canonical one - "AUTORUN.INF"
         * and "autorun.inf" are different facts about the volume, and a
         * forensic report should say which was actually there. */
        snprintf(finding.path, sizeof(finding.path), "%s", name);

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
