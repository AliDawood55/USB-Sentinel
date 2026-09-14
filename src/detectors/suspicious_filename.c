/*
 * Suspicious filename inspection - metadata only, never opens file content.
 * Every check here reads from usbs_dir_entry_t (name, is_hidden), already
 * populated by the directory listing itself (ARCHITECTURE.md's Phase 4
 * notes on decoupling metadata from content reads).
 *
 * Covers well-documented Windows filename deception techniques used to
 * disguise an executable as something else:
 *   - a double extension (invoice.pdf.exe)
 *   - a Unicode bidi-override character (U+202E and friends) reversing how
 *     the name displays, e.g. making "cod.exe" show as "exe.doc"
 *   - long space-padding before a hidden extension, pushing the visible
 *     (truncated) name to look like it ends somewhere it doesn't
 *   - a hidden/system-attributed executable
 *
 * Phase 17.1 (ARCHITECTURE.md section 24.3): on an internal drive the
 * double-extension rule is weighted by location (usbsentinel/location.h),
 * because there the shape is mostly produced by Windows (Recent Items) and
 * by package managers (node_modules), not by an attacker. The other three
 * rules have no benign producer anywhere and stay HIGH everywhere. On a USB
 * device nothing here changed.
 */
#include <stdio.h>
#include <string.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/location.h"

#define SUSPICIOUS_FILENAME_ID "suspicious_filename"

static const char *const k_executable_extensions[] = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "ps1", "lnk", "hta", "jar", "cpl", "msc", "reg",
};

/* The subset of k_executable_extensions that is a native binary or installer
 * rather than a script, archive-hosted code, or shortcut. A document name
 * wrapped around one of these ("invoice.pdf.exe") has no benign producer in
 * a package tree, so Phase 17.1 never lowers it below WARNING there. */
static const char *const k_native_binary_extensions[] = {
    "exe", "scr", "com", "pif", "cpl", "msi",
};

static const char *const k_document_extensions[] = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mov",
    "zip", "rar", "7z",
};

static usbs_bool str_ieq(const char *a, const char *b)
{
    for (;; ++a, ++b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) {
            return false;
        }
        if (ca == '\0') {
            return true;
        }
    }
}

static usbs_bool in_set(const char *value, const char *const *set, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        if (str_ieq(value, set[i])) {
            return true;
        }
    }
    return false;
}

/* Finds the Nth-from-the-end '.' in `name` (1 = last, 2 = second-to-last),
 * returning a pointer to the character after it, or NULL if there are fewer
 * than `n` dot-separated segments. Never returns a pointer to the leading
 * dot of a dotfile-style name (a bare "." at position 0 is not a separator
 * here, matching how Windows treats a name with no real extension). */
static const char *nth_extension_from_end(const char *name, int n)
{
    const char *result = NULL;
    const char *p;
    int         seen = 0;

    for (p = name + strlen(name); p > name; --p) {
        if (*(p - 1) == '.') {
            ++seen;
            if (seen == n) {
                result = p;
                break;
            }
        }
    }
    return result;
}

static usbs_bool has_double_extension_disguise(const char *name, char *reason, size_t cap)
{
    const char *last_ext  = nth_extension_from_end(name, 1);
    const char *second_ext_start;
    char        second_ext[16];
    const char *second_ext_end;
    size_t      len;

    if (last_ext == NULL || !in_set(last_ext, k_executable_extensions,
                                    USBS_ARRAY_LEN(k_executable_extensions))) {
        return false;
    }

    second_ext_start = nth_extension_from_end(name, 2);
    if (second_ext_start == NULL) {
        return false;
    }
    second_ext_end = last_ext - 1; /* the '.' before the executable extension */
    if (second_ext_end <= second_ext_start) {
        return false;
    }

    len = (size_t)(second_ext_end - second_ext_start);
    if (len == 0 || len >= sizeof(second_ext)) {
        return false;
    }
    memcpy(second_ext, second_ext_start, len);
    second_ext[len] = '\0';

    if (!in_set(second_ext, k_document_extensions, USBS_ARRAY_LEN(k_document_extensions))) {
        return false;
    }

    snprintf(reason, cap, "double extension disguise (.%s.%s)", second_ext, last_ext);
    return true;
}

/* U+202A-U+202E (LRE/RLE/PDF/LRO/RLO) all encode as E2 80 [AA-AE] in UTF-8. */
static usbs_bool has_bidi_override(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    for (; p[0] != '\0' && p[1] != '\0' && p[2] != '\0'; ++p) {
        if (p[0] == 0xE2 && p[1] == 0x80 && p[2] >= 0xAA && p[2] <= 0xAE) {
            return true;
        }
    }
    return false;
}

static usbs_bool has_space_padding_before_hidden_extension(const char *name)
{
    const char *last_ext = nth_extension_from_end(name, 1);
    size_t      run      = 0;
    const char *p;

    if (last_ext == NULL || !in_set(last_ext, k_executable_extensions,
                                    USBS_ARRAY_LEN(k_executable_extensions))) {
        return false;
    }
    for (p = name; p < last_ext; ++p) {
        if (*p == ' ') {
            ++run;
            if (run >= 4) {
                return true;
            }
        } else {
            run = 0;
        }
    }
    return false;
}

/* Outcome of weighing a double-extension match by location. */
typedef enum double_ext_verdict {
    DOUBLE_EXT_REPORT_DEFAULT = 0, /* HIGH, as on a USB device */
    DOUBLE_EXT_REPORT_LOWERED,     /* reported, at `severity` below HIGH */
    DOUBLE_EXT_SUPPRESSED          /* not reported; counted */
} double_ext_verdict_t;

/*
 * The internal-drive rule table for a double extension (ARCHITECTURE.md
 * section 24.3). Only reached when usbs_location_policy_applies().
 *
 *   user-facing (Desktop, Downloads, Temp, Startup)  HIGH, unchanged
 *   Recent Items, and the name ends in .lnk          not reported
 *   dependency tree, script-type or .lnk extension   INFO
 *   dependency tree, native binary (exe, scr, ...)   WARNING
 *   anywhere else on the drive                       WARNING
 *
 * Recent Items only suppresses names ending in ".lnk": Windows names every
 * entry there "<opened file name>.lnk", so ".pdf.lnk" is the folder's
 * normal shape. An "invoice.pdf.exe" in that folder is not a shape Windows
 * produces, and falls through to the drive-wide WARNING. The shortcut's
 * *content* is still parsed by lnk_inspection, which applies no Recent
 * Items tuning, so a Recent Items shortcut that launches powershell with
 * an encoded command is still HIGH.
 */
static double_ext_verdict_t weigh_double_extension(usbs_location_kind_t kind,
                                                   const char          *last_ext,
                                                   usbs_severity_t     *out_severity)
{
    usbs_bool native = in_set(last_ext, k_native_binary_extensions,
                              USBS_ARRAY_LEN(k_native_binary_extensions));

    switch (kind) {
    case USBS_LOCATION_USER_EXPOSED:
        *out_severity = USBS_SEVERITY_HIGH;
        return DOUBLE_EXT_REPORT_DEFAULT;
    case USBS_LOCATION_RECENT_ITEMS:
        if (str_ieq(last_ext, "lnk")) {
            return DOUBLE_EXT_SUPPRESSED;
        }
        *out_severity = USBS_SEVERITY_WARNING;
        return DOUBLE_EXT_REPORT_LOWERED;
    case USBS_LOCATION_DEPENDENCY_TREE:
        *out_severity = native ? USBS_SEVERITY_WARNING : USBS_SEVERITY_INFO;
        return DOUBLE_EXT_REPORT_LOWERED;
    case USBS_LOCATION_ORDINARY:
    case USBS_LOCATION_OS_SHORTCUTS:
    case USBS_LOCATION_OS_COMPONENT_STORE:
    case USBS_LOCATION_SELF_TEST_FIXTURES: /* never walked; handled like ordinary */
    default:
        *out_severity = USBS_SEVERITY_WARNING;
        return DOUBLE_EXT_REPORT_LOWERED;
    }
}

static usbs_status_t suspicious_filename_on_file(usbs_detector_file_ctx_t *ctx,
                                                 const char               *full_path,
                                                 const usbs_dir_entry_t   *entry)
{
    usbs_check_result_t *result;
    char                  reasons[USBS_FINDING_MESSAGE_MAX];
    size_t                reasons_len = 0;
    char                  buf[128];
    const char           *last_ext;
    const char           *relative;
    usbs_bool             tuned;
    usbs_location_kind_t  kind = USBS_LOCATION_ORDINARY;
    usbs_severity_t       severity  = USBS_SEVERITY_INFO; /* max over the reasons found */
    usbs_bool             any_high_rule = false;
    usbs_bool             lowered = false;
    usbs_bool             suppressed = false;

    if (ctx == NULL || full_path == NULL || entry == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    result = ctx->result;
    reasons[0] = '\0';

    /* detect_ctx (and its device) may be absent in a unit test that drives
     * this callback directly; no device means no tuning, i.e. the strict
     * USB rules. */
    relative = usbs_location_relative(ctx->detect_ctx != NULL ? ctx->detect_ctx->volume_path : NULL,
                                      full_path);
    tuned = ctx->detect_ctx != NULL && usbs_location_policy_applies(ctx->detect_ctx->device);
    if (tuned) {
        kind = usbs_location_classify(relative);
    }

#define APPEND_REASON(text)                                                    \
    do {                                                                       \
        int n = snprintf(reasons + reasons_len, sizeof(reasons) - reasons_len, \
                         "%s%s", reasons_len > 0 ? "; " : "", (text));         \
        if (n > 0 && (size_t)n < sizeof(reasons) - reasons_len) {              \
            reasons_len += (size_t)n;                                         \
        }                                                                      \
    } while (0)

    last_ext = nth_extension_from_end(entry->name, 1);

    if (has_double_extension_disguise(entry->name, buf, sizeof(buf))) {
        if (!tuned) {
            any_high_rule = true;
            APPEND_REASON(buf);
        } else {
            usbs_severity_t      weighed = USBS_SEVERITY_HIGH;
            double_ext_verdict_t verdict = weigh_double_extension(kind, last_ext, &weighed);

            if (verdict == DOUBLE_EXT_SUPPRESSED) {
                suppressed = true;
            } else {
                char annotated[192];
                if (verdict == DOUBLE_EXT_REPORT_LOWERED) {
                    /* Say why the severity is not the USB default, in the
                     * finding itself. */
                    snprintf(annotated, sizeof(annotated), "%s [internal drive, %s]",
                             buf, usbs_location_kind_string(kind));
                    lowered = true;
                } else {
                    snprintf(annotated, sizeof(annotated), "%s", buf);
                }
                if (weighed == USBS_SEVERITY_HIGH) {
                    any_high_rule = true;
                } else if (weighed > severity) {
                    severity = weighed;
                }
                APPEND_REASON(annotated);
            }
        }
    }
    /* No benign producer anywhere: HIGH on every device and in every
     * location. */
    if (has_bidi_override(entry->name)) {
        any_high_rule = true;
        APPEND_REASON("filename contains a Unicode bidi-override character");
    }
    if (has_space_padding_before_hidden_extension(entry->name)) {
        any_high_rule = true;
        APPEND_REASON("long space padding hides the real extension");
    }
    if (entry->is_hidden && last_ext != NULL &&
        in_set(last_ext, k_executable_extensions, USBS_ARRAY_LEN(k_executable_extensions))) {
        any_high_rule = true;
        APPEND_REASON("hidden/system-attributed executable");
    }

#undef APPEND_REASON

    if (any_high_rule) {
        severity = USBS_SEVERITY_HIGH;
    }

    if (reasons_len > 0) {
        usbs_finding_t finding;
        memset(&finding, 0, sizeof(finding));
        finding.severity = severity;
        /* Phase 17.1: the path relative to the volume root, not the bare
         * name. On a stick, where most files sit near the root, the two
         * were close. On a 1.4-million-file system drive a bare
         * "Iterator.zip.js" cannot be found, let alone judged. */
        snprintf(finding.path, sizeof(finding.path), "%s", relative);
        snprintf(finding.message, sizeof(finding.message), "%s", reasons);
        usbs_finding_list_push(&result->findings, &finding);
        if (lowered && severity < USBS_SEVERITY_HIGH) {
            ++result->policy_lowered;
        }
    } else if (suppressed) {
        ++result->policy_suppressed;
    }

    return USBS_OK;
}

const usbs_detector_t usbs_detector_suspicious_filename = {
    .id          = SUSPICIOUS_FILENAME_ID,
    .description = "Flags filenames using known disguise techniques (double extensions, "
                   "Unicode direction overrides, padding, hidden executables)",
    .on_file     = suspicious_filename_on_file,
    /* .run omitted: driven by scanner's single shared walk (ARCHITECTURE.md
     * Phase 5 notes) rather than walking the volume itself. */
};
