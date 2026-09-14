/*
 * .lnk (Windows shortcut, MS-SHLLINK) inspection.
 *
 * The real-world delivery mechanism behind the USB attacks this project
 * exists to catch (the Stuxnet LNK vulnerability; the classic
 * "resume.pdf.lnk" -> powershell one-liner pattern). This parser treats
 * every byte of every .lnk file as hostile:
 *
 *   - a hard, generous-but-bounded read cap (LNK_MAX_READ); an oversized
 *     "shortcut" is reported as suspicious on that basis alone and is never
 *     read past the cap, let alone fully parsed
 *   - every length/offset field read from the file is validated against the
 *     bytes actually in hand *before* it is used to index or copy anything
 *     - the canonical parser-bug class, and the one this file cannot ship
 *       with a single instance of
 *   - malformed, truncated, or structurally inconsistent input fails
 *     cleanly to a negative/failed result, never a crash
 *   - the extracted target path and arguments are inspected as text only;
 *     nothing here ever opens, follows, or executes what a .lnk points to
 *     (ARCHITECTURE.md section 1: no sample execution)
 *
 * Phase 17.1 (ARCHITECTURE.md section 24.2), internal drives only: in the
 * Start Menu an interpreter target alone is normal ("Developer PowerShell
 * for VS 2022", "Node.js command prompt"), so there only the attack shape
 * (an interpreter target AND a suspicious argument) is reported. In the
 * WinSxS component store nothing is reported. Everywhere else, including
 * Recent Items and both Startup folders, this detector is unchanged, and on
 * a USB device it is unchanged everywhere. Every suppression is counted.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/location.h"
#include "usbsentinel/platform.h"

#define LNK_INSPECT_ID "lnk_inspection"

/* A real shortcut is at most a few KB; this is a deliberately generous cap
 * that still bounds worst-case memory/CPU against a hostile "shortcut". */
#define LNK_MAX_READ (256 * 1024)

#define LNK_HEADER_SIZE 76
#define LNK_TARGET_MAX  520
#define LNK_ARGS_MAX    1024

static const unsigned char k_shell_link_clsid[16] = {
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
};

/* LinkFlags bits used here (MS-SHLLINK 2.1.1). */
#define LNK_FLAG_HAS_LINK_TARGET_ID_LIST 0x00000001u
#define LNK_FLAG_HAS_LINK_INFO           0x00000002u
#define LNK_FLAG_HAS_NAME                0x00000004u
#define LNK_FLAG_HAS_RELATIVE_PATH       0x00000008u
#define LNK_FLAG_HAS_WORKING_DIR         0x00000010u
#define LNK_FLAG_HAS_ARGUMENTS           0x00000020u
#define LNK_FLAG_IS_UNICODE              0x00000080u

/* LinkInfoFlags bit (MS-SHLLINK 2.3). */
#define LNK_INFO_HAS_VOLUME_AND_LOCAL_BASE_PATH 0x00000001u

/* --- bounds-checked primitive readers --- */

/* True iff [offset, offset+count) lies entirely within [0, len). Written to
 * avoid any addition that could itself overflow. */
static usbs_bool in_range(size_t len, size_t offset, size_t count)
{
    if (count > len) {
        return false;
    }
    return offset <= len - count;
}

static usbs_bool read_u16(const unsigned char *buf, size_t len, size_t offset,
                          uint16_t *out)
{
    if (!in_range(len, offset, 2)) {
        return false;
    }
    *out = (uint16_t)(buf[offset] | ((uint16_t)buf[offset + 1] << 8));
    return true;
}

static usbs_bool read_u32(const unsigned char *buf, size_t len, size_t offset,
                          uint32_t *out)
{
    if (!in_range(len, offset, 4)) {
        return false;
    }
    *out = (uint32_t)buf[offset] | ((uint32_t)buf[offset + 1] << 8) |
           ((uint32_t)buf[offset + 2] << 16) | ((uint32_t)buf[offset + 3] << 24);
    return true;
}

/* Reads a NUL-terminated ANSI string starting at `offset`, never scanning at
 * or beyond `bound`. Copies at most out_cap-1 bytes into `out`, always
 * NUL-terminating it. Returns false only if `offset` itself is out of range
 * (an unterminated string within bounds is truncated, not rejected - a
 * missing NUL before `bound` is itself something a hostile file could do,
 * and stopping at `bound` already prevents any over-read). */
static usbs_bool read_cstring_ansi(const unsigned char *buf, size_t bound, size_t offset,
                                   char *out, size_t out_cap)
{
    size_t i = 0;
    size_t o = 0;

    if (offset > bound || out_cap == 0) {
        return false;
    }
    for (i = offset; i < bound; ++i) {
        if (buf[i] == '\0') {
            break;
        }
        if (o + 1 < out_cap) {
            out[o++] = (char)buf[i];
        }
    }
    out[o] = '\0';
    return true;
}

/*
 * Reads one StringData block (MS-SHLLINK 2.4) at *inout_offset: a
 * CountCharacters WORD followed by that many 1- or 2-byte characters. On
 * success, advances *inout_offset past the block. If `out` is non-NULL, a
 * best-effort ASCII-lossy copy is written there (UTF-16LE code units are
 * truncated to their low byte, which is sufficient for matching ASCII
 * keywords such as interpreter names or "-enc"; anything non-ASCII becomes
 * '?', never a partial multibyte read). Bounds-checked throughout; returns
 * false (without advancing) on any malformed/truncated block.
 */
static usbs_bool read_string_data(const unsigned char *buf, size_t len, size_t *inout_offset,
                                  usbs_bool is_unicode, char *out, size_t out_cap)
{
    size_t   offset = *inout_offset;
    uint16_t count   = 0;
    size_t   char_size;
    size_t   byte_len;
    size_t   i;
    size_t   o = 0;

    if (!read_u16(buf, len, offset, &count)) {
        return false;
    }
    char_size = is_unicode ? 2u : 1u;
    byte_len  = (size_t)count * char_size;

    if (!in_range(len, offset + 2, byte_len)) {
        return false;
    }

    if (out != NULL && out_cap > 0) {
        for (i = 0; i < count; ++i) {
            size_t        char_offset = offset + 2 + (i * char_size);
            unsigned char low_byte    = buf[char_offset];

            if (is_unicode) {
                unsigned char high_byte = buf[char_offset + 1];
                if (high_byte != 0 || low_byte >= 0x80) {
                    low_byte = '?';
                }
            } else if (low_byte >= 0x80) {
                low_byte = '?';
            }
            if (o + 1 < out_cap) {
                out[o++] = (char)low_byte;
            }
        }
        out[o] = '\0';
    }

    *inout_offset = offset + 2 + byte_len;
    return true;
}

typedef struct lnk_parsed {
    usbs_bool have_target;
    char      target[LNK_TARGET_MAX];
    usbs_bool have_arguments;
    char      arguments[LNK_ARGS_MAX];
} lnk_parsed_t;

/*
 * Parses `buf` (length `len`) into `out`. Returns false for anything
 * structurally invalid (bad magic, a field whose bounds don't check out) -
 * the caller treats that as "malformed", not as a crash.
 */
static usbs_bool parse_lnk(const unsigned char *buf, size_t len, lnk_parsed_t *out)
{
    uint32_t header_size = 0;
    uint32_t link_flags  = 0;
    size_t   offset;
    usbs_bool is_unicode;

    memset(out, 0, sizeof(*out));

    if (len < LNK_HEADER_SIZE) {
        return false;
    }
    if (!read_u32(buf, len, 0, &header_size) || header_size != LNK_HEADER_SIZE) {
        return false;
    }
    if (memcmp(buf + 4, k_shell_link_clsid, sizeof(k_shell_link_clsid)) != 0) {
        return false;
    }
    if (!read_u32(buf, len, 20, &link_flags)) {
        return false;
    }
    is_unicode = (link_flags & LNK_FLAG_IS_UNICODE) ? true : false;

    offset = LNK_HEADER_SIZE;

    if (link_flags & LNK_FLAG_HAS_LINK_TARGET_ID_LIST) {
        uint16_t id_list_size = 0;
        if (!read_u16(buf, len, offset, &id_list_size)) {
            return false;
        }
        if (!in_range(len, offset + 2, id_list_size)) {
            return false;
        }
        offset += 2 + id_list_size;
    }

    if (link_flags & LNK_FLAG_HAS_LINK_INFO) {
        uint32_t link_info_size        = 0;
        uint32_t link_info_header_size = 0;
        uint32_t link_info_flags       = 0;
        uint32_t local_base_path_off   = 0;

        if (!read_u32(buf, len, offset, &link_info_size)) {
            return false;
        }
        if (!in_range(len, offset, link_info_size) || link_info_size < 4) {
            return false;
        }

        if (!read_u32(buf, len, offset + 4, &link_info_header_size) ||
            !read_u32(buf, len, offset + 8, &link_info_flags)) {
            return false;
        }

        /* LocalBasePathOffset is the 5th DWORD in the structure (after
         * LinkInfoSize, LinkInfoHeaderSize, LinkInfoFlags, VolumeIDOffset).
         * If the flags claim it is present, every validation step for it
         * must succeed, or this file is malformed - not "target simply
         * unavailable". Silently ignoring a field the file itself declared
         * present, just because reading it failed a bounds check, would
         * mask exactly the kind of corruption this parser exists to catch. */
        if (link_info_header_size >= 0x1C &&
            (link_info_flags & LNK_INFO_HAS_VOLUME_AND_LOCAL_BASE_PATH)) {
            size_t path_offset;

            if (!read_u32(buf, len, offset + 16, &local_base_path_off)) {
                return false;
            }
            if (local_base_path_off >= link_info_size) {
                return false; /* offset claims to point outside this LinkInfo */
            }
            path_offset = offset + local_base_path_off;
            if (!read_cstring_ansi(buf, offset + link_info_size, path_offset,
                                   out->target, sizeof(out->target))) {
                return false;
            }
            out->have_target = (out->target[0] != '\0');
        }

        offset += link_info_size;
    }

    /* NAME_STRING, RELATIVE_PATH, WORKING_DIR must be skipped in this fixed
     * order (MS-SHLLINK 2.4) to reach COMMAND_LINE_ARGUMENTS at the right
     * offset - their content is not needed. */
    if (link_flags & LNK_FLAG_HAS_NAME) {
        if (!read_string_data(buf, len, &offset, is_unicode, NULL, 0)) {
            return false;
        }
    }
    if (link_flags & LNK_FLAG_HAS_RELATIVE_PATH) {
        if (!read_string_data(buf, len, &offset, is_unicode, NULL, 0)) {
            return false;
        }
    }
    if (link_flags & LNK_FLAG_HAS_WORKING_DIR) {
        if (!read_string_data(buf, len, &offset, is_unicode, NULL, 0)) {
            return false;
        }
    }
    if (link_flags & LNK_FLAG_HAS_ARGUMENTS) {
        if (!read_string_data(buf, len, &offset, is_unicode,
                              out->arguments, sizeof(out->arguments))) {
            return false;
        }
        out->have_arguments = (out->arguments[0] != '\0');
    }

    return true;
}

/* --- suspicion heuristics over the extracted, already-bounded text --- */

static const char *const k_interpreter_basenames[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
};

static const char *const k_argument_markers[] = {
    "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden",
    "-windowstyle hidden", "iex", "invoke-expression",
    "http://", "https://", "downloadstring", "frombase64string",
};

static usbs_bool str_ci_eq(const char *a, const char *b)
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

static usbs_bool str_ci_contains(const char *haystack, const char *needle)
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

static const char *basename_of(const char *path)
{
    const char *last_sep = NULL;
    const char *p;
    for (p = path; *p != '\0'; ++p) {
        if (*p == '\\' || *p == '/') {
            last_sep = p;
        }
    }
    return (last_sep != NULL) ? last_sep + 1 : path;
}

/* --- per-file callback --- */

static usbs_bool has_lnk_extension(const char *name)
{
    size_t len = strlen(name);
    if (len < 4) {
        return false;
    }
    return (name[len - 4] == '.') &&
           (name[len - 3] == 'l' || name[len - 3] == 'L') &&
           (name[len - 2] == 'n' || name[len - 2] == 'N') &&
           (name[len - 1] == 'k' || name[len - 1] == 'K');
}

/* The internal-drive location policy's view of one would-be finding. */
typedef enum lnk_policy {
    LNK_POLICY_NONE = 0,      /* strict rules: USB, unknown bus, or an untuned location */
    LNK_POLICY_ATTACK_SHAPE,  /* Start Menu: report only interpreter + suspicious argument */
    LNK_POLICY_SUPPRESS_ALL   /* WinSxS: report nothing */
} lnk_policy_t;

static lnk_policy_t lnk_policy_for(const usbs_detect_context_t *detect_ctx, const char *relative)
{
    if (!usbs_location_policy_applies(detect_ctx->device)) {
        return LNK_POLICY_NONE;
    }
    switch (usbs_location_classify(relative)) {
    case USBS_LOCATION_OS_SHORTCUTS:       return LNK_POLICY_ATTACK_SHAPE;
    case USBS_LOCATION_OS_COMPONENT_STORE: return LNK_POLICY_SUPPRESS_ALL;
    default:                               return LNK_POLICY_NONE;
    }
}

static void push_finding(usbs_check_result_t *result, usbs_severity_t severity,
                         const char *relative_path, const char *message)
{
    usbs_finding_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.severity = severity;
    snprintf(finding.path, sizeof(finding.path), "%s", relative_path);
    snprintf(finding.message, sizeof(finding.message), "%s", message);
    usbs_finding_list_push(&result->findings, &finding);
}

static usbs_status_t lnk_on_file(usbs_detector_file_ctx_t *ctx, const char *full_path,
                                 const usbs_dir_entry_t   *entry)
{
    const char    *volume_path;
    const char    *relative;
    unsigned char *buf;
    usbs_file_t   *file;
    usbs_status_t  status;
    size_t         total = 0;
    usbs_hash_ctx_t *hash_ctx = NULL;
    char           sha256_hex[USBS_SHA256_HEX_LEN + 1];
    usbs_bool      have_hash = false;
    lnk_policy_t   policy;

    if (ctx == NULL || full_path == NULL || entry == NULL || ctx->detect_ctx == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    volume_path = ctx->detect_ctx->volume_path;

    if (!has_lnk_extension(entry->name)) {
        return USBS_OK;
    }

    relative = usbs_location_relative(volume_path, full_path);
    policy   = lnk_policy_for(ctx->detect_ctx, relative);

    /* Oversized "shortcut" is itself the finding; never read it, let alone
     * parse it - a real .lnk is at most a few KB. */
    if (entry->size_bytes > LNK_MAX_READ && policy != LNK_POLICY_NONE) {
        /* A tuned OS location: an oversized entry there is not the attack
         * shape. The WinSxS store holds delta-compressed payloads that only
         * end in ".lnk". */
        ++ctx->result->policy_suppressed;
        return USBS_OK;
    }
    if (entry->size_bytes > LNK_MAX_READ) {
        char message[160];
        snprintf(message, sizeof(message),
                "oversized .lnk file (%llu bytes), not parsed",
                (unsigned long long)entry->size_bytes);
        push_finding(ctx->result, USBS_SEVERITY_WARNING, relative, message);
        return USBS_OK;
    }

    buf = (unsigned char *)malloc(LNK_MAX_READ);
    if (buf == NULL) {
        return USBS_ERR_NO_MEMORY;
    }

    status = usbs_platform_file_open_read(full_path, &file);
    if (!usbs_ok(status)) {
        free(buf);
        return USBS_OK; /* per-file error isolation: skip, do not abort the detector */
    }

    if (usbs_ok(usbs_platform_hash_begin(&hash_ctx))) {
        have_hash = true;
    }

    for (;;) {
        size_t read = 0;
        if (total >= LNK_MAX_READ) {
            break;
        }
        status = usbs_platform_file_read(file, buf + total, LNK_MAX_READ - total, &read);
        if (!usbs_ok(status) || read == 0) {
            break;
        }
        if (have_hash) {
            usbs_platform_hash_update(hash_ctx, buf + total, read);
        }
        total += read;
    }
    usbs_platform_file_close(file);

    if (have_hash) {
        unsigned char digest[USBS_SHA256_DIGEST_SIZE];
        if (!usbs_ok(usbs_platform_hash_finish(hash_ctx, digest, sha256_hex))) {
            have_hash = false;
        }
    }

    {
        lnk_parsed_t parsed;
        usbs_bool    parsed_ok = parse_lnk(buf, total, &parsed);

        if (!parsed_ok && policy != LNK_POLICY_NONE) {
            /* Malformed in a tuned OS location: the WinSxS store's r\ and f\
             * delta files are the observed case (section 24.2), and "could
             * not parse" there is not the attack shape either. */
            ++ctx->result->policy_suppressed;
        } else if (!parsed_ok) {
            char message[192];
            snprintf(message, sizeof(message),
                    "malformed or corrupt .lnk file (could not parse)%s%s",
                    have_hash ? ", sha256=" : "", have_hash ? sha256_hex : "");
            push_finding(ctx->result, USBS_SEVERITY_WARNING, relative, message);
        } else {
            const char *target_base    = parsed.have_target ? basename_of(parsed.target) : "";
            usbs_bool   targets_interp = false;
            const char *matched_marker = NULL;
            char        message[LNK_ARGS_MAX + LNK_TARGET_MAX + 128];
            char        marker_part[96];
            size_t      i;

            for (i = 0; i < USBS_ARRAY_LEN(k_interpreter_basenames); ++i) {
                if (parsed.have_target && str_ci_eq(target_base, k_interpreter_basenames[i])) {
                    targets_interp = true;
                    break;
                }
            }

            if (parsed.have_arguments) {
                for (i = 0; i < USBS_ARRAY_LEN(k_argument_markers); ++i) {
                    if (str_ci_contains(parsed.arguments, k_argument_markers[i])) {
                        matched_marker = k_argument_markers[i];
                        break;
                    }
                }
            }

            if (matched_marker != NULL) {
                snprintf(marker_part, sizeof(marker_part),
                        " [suspicious argument: %s]", matched_marker);
            } else {
                marker_part[0] = '\0';
            }

            if ((targets_interp || matched_marker != NULL) &&
                (policy == LNK_POLICY_SUPPRESS_ALL ||
                 (policy == LNK_POLICY_ATTACK_SHAPE && !(targets_interp && matched_marker != NULL)))) {
                /* Tuned out, and counted: an interpreter shortcut with
                 * ordinary arguments in the Start Menu, a URL argument to
                 * a browser there, or anything in WinSxS. */
                ++ctx->result->policy_suppressed;
            } else if (targets_interp || matched_marker != NULL) {
                snprintf(message, sizeof(message),
                        "target=%s%s%s%s%s sha256=%s",
                        parsed.have_target ? parsed.target : "(none)",
                        parsed.have_arguments ? " arguments=" : "",
                        parsed.have_arguments ? parsed.arguments : "",
                        targets_interp ? " [interpreter target]" : "",
                        marker_part,
                        have_hash ? sha256_hex : "(unavailable)");
                push_finding(ctx->result, USBS_SEVERITY_HIGH, relative, message);
            }
        }
    }

    free(buf);
    return USBS_OK;
}

const usbs_detector_t usbs_detector_lnk_inspect = {
    .id          = LNK_INSPECT_ID,
    .description = "Parses .lnk shortcuts (never following or executing their targets) "
                   "and flags ones pointing at an interpreter or carrying suspicious arguments",
    .on_file     = lnk_on_file,
    /* .run omitted: driven by scanner's single shared walk (ARCHITECTURE.md
     * Phase 5 notes) rather than walking the volume itself. */
};
