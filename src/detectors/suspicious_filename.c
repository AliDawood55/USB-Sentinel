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
 */
#include <stdio.h>
#include <string.h>

#include "usbsentinel/detector.h"

#define SUSPICIOUS_FILENAME_ID "suspicious_filename"

static const char *const k_executable_extensions[] = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "ps1", "lnk", "hta", "jar", "cpl", "msc", "reg",
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

static usbs_status_t suspicious_filename_on_file(usbs_detector_file_ctx_t *ctx,
                                                 const char               *full_path,
                                                 const usbs_dir_entry_t   *entry)
{
    usbs_check_result_t *result;
    char                  reasons[USBS_FINDING_MESSAGE_MAX];
    size_t                reasons_len = 0;
    char                  buf[128];
    const char           *last_ext;

    if (ctx == NULL || full_path == NULL || entry == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    result = ctx->result;
    reasons[0] = '\0';

#define APPEND_REASON(text)                                                    \
    do {                                                                       \
        int n = snprintf(reasons + reasons_len, sizeof(reasons) - reasons_len, \
                         "%s%s", reasons_len > 0 ? "; " : "", (text));         \
        if (n > 0 && (size_t)n < sizeof(reasons) - reasons_len) {              \
            reasons_len += (size_t)n;                                         \
        }                                                                      \
    } while (0)

    if (has_double_extension_disguise(entry->name, buf, sizeof(buf))) {
        APPEND_REASON(buf);
    }
    if (has_bidi_override(entry->name)) {
        APPEND_REASON("filename contains a Unicode bidi-override character");
    }
    if (has_space_padding_before_hidden_extension(entry->name)) {
        APPEND_REASON("long space padding hides the real extension");
    }
    last_ext = nth_extension_from_end(entry->name, 1);
    if (entry->is_hidden && last_ext != NULL &&
        in_set(last_ext, k_executable_extensions, USBS_ARRAY_LEN(k_executable_extensions))) {
        APPEND_REASON("hidden/system-attributed executable");
    }

#undef APPEND_REASON

    if (reasons_len > 0) {
        usbs_finding_t finding;
        memset(&finding, 0, sizeof(finding));
        finding.severity = USBS_SEVERITY_HIGH;
        snprintf(finding.path, sizeof(finding.path), "%s", entry->name);
        snprintf(finding.message, sizeof(finding.message), "%s", reasons);
        usbs_finding_list_push(&result->findings, &finding);
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
