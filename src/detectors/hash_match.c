/*
 * ============================================================================
 * hash_match_example - NON-PRODUCTION until a real signature file is loaded.
 * ============================================================================
 *
 * Two states, both honest:
 *
 *   1. No external signature file found (the common, out-of-the-box case):
 *      falls back to exactly one hardcoded entry - the SHA-256 of the EICAR
 *      Standard Anti-Virus Test File, an industry-standard, harmless
 *      68-byte string every AV vendor recognizes, used specifically so
 *      detection capability can be demonstrated without real malware
 *      (ARCHITECTURE.md section 1). The report says so explicitly.
 *
 *   2. A signature file was found and loaded (Phase 6): matches against
 *      whatever entries it contains. USB Sentinel does not ship, vet, or
 *      vouch for that file's contents - the report says that explicitly
 *      too. A real detection-signature *source* (where such a file
 *      legitimately comes from, its licensing, and how it would be updated
 *      while staying fully offline) remains a separate, deferred decision
 *      (ARCHITECTURE.md section 8); this only parses a user-supplied file
 *      at a local path. No network access, ever, for this or any reason.
 *
 * Signature file format ("sha256:size:name" per line, '#' comments) is
 * ClamAV-*inspired*, not claimed byte-for-byte compatible with any specific
 * ClamAV format - that would need independent verification against real
 * ClamAV documentation or sample files, which was not done. See
 * signature_list.h. SHA-256 only, never MD5, keeping the project's crypto
 * surface at exactly the one primitive verified in Phase 4.
 *
 * File location: an optional override via the USBS_HASH_MATCH_SIGNATURES
 * environment variable (set by `usb-sentinel scan --signatures <path>`,
 * cli/cmd_scan.c), else the default `%LOCALAPPDATA%\USBSentinel\signatures.txt`.
 * Env-var indirection, rather than cli reaching directly into this
 * detector's internals, keeps cli/scanner ignorant of individual detectors
 * - the same arm's-length pattern storage.c already uses for
 * %LOCALAPPDATA% itself (usbs_getenv(), core/env.c).
 *
 * The independent verification that produced the EICAR hash below also
 * surfaced a real, disclosed consequence: writing genuine EICAR content to
 * disk and reopening it can fail under active real-time antivirus (this
 * machine's Windows Defender intercepted it mid-development, exactly the
 * reaction EICAR exists to trigger). Handled correctly by this detector's
 * existing per-file error isolation (an unopenable file is skipped, not a
 * crash), but it does mean a real EICAR file on a scanned device may go
 * silently unmatched on a machine whose AV gets to it first - a property of
 * the environment, not a defect here. tests/test_hash_match.c never writes
 * real EICAR bytes to disk for exactly this reason, and neither does any
 * Phase 6 signature-list test - all use synthetic, safe fixture content.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "usbsentinel/detector.h"
#include "usbsentinel/env.h"
#include "usbsentinel/log.h"
#include "usbsentinel/path.h"
#include "usbsentinel/platform.h"
#include "signature_list.h"

#define HASH_MATCH_ID "hash_match_example"

#define HASH_MATCH_SIGNATURES_ENV_OVERRIDE "USBS_HASH_MATCH_SIGNATURES"
#define HASH_MATCH_DEFAULT_FILENAME        "signatures.txt"

/* Files larger than this are skipped without being opened at all (checked
 * via entry->size_bytes, no I/O). Generous relative to a 68-byte EICAR
 * string, but still bounded, matching ARCHITECTURE.md's Phase 4 stance on
 * why unconditional hashing was removed from the general traversal. A real
 * loaded signature file could plausibly include larger entries than the
 * demo one, so this is sized for "a real executable", not just EICAR. */
#define HASH_MATCH_MAX_FILE_SIZE (64u * 1024u * 1024u)

/* The streaming read chunk size. Heap-allocated (Phase 12, ARCHITECTURE.md
 * section 18) rather than a stack array: PREfast's /analyze flagged the
 * former unsigned char buf[65536] local as 66468 bytes of stack per call,
 * and this function runs once per file during a walk - lnk_inspect.c
 * already made the equivalent call for its own read buffer. */
#define HASH_MATCH_READ_CHUNK (64u * 1024u)

static const struct { const char *sha256_hex; usbs_u64 size; const char *label; } k_fallback_entry = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    68, /* the EICAR test string is exactly 68 bytes */
    "EICAR Standard Anti-Virus Test File (industry-standard test string, not malware)",
};

/* Lazily loaded once per process (the tool is one-shot: one scan per
 * invocation, so a process-lifetime cache is sufficient and avoids
 * reloading the file per detector call - see run_whole_check_detectors'
 * counterpart usage pattern in scanner.c for the same one-shot assumption
 * elsewhere in this codebase). */
static usbs_signature_list_t g_signatures;
static usbs_bool             g_load_attempted = false;
static usbs_bool             g_loaded_from_file = false;
static char                  g_loaded_path[512];

/*
 * Not declared in any public header - an internal surface `tests/` links
 * against directly (the same pattern already used for `extern const
 * usbs_detector_t ...` elsewhere). Resets the cached load state so a test
 * can point USBS_HASH_MATCH_SIGNATURES at a different file and reload.
 */
void usbs_hash_match_reset_for_testing(void)
{
    usbs_signature_list_free(&g_signatures);
    usbs_signature_list_init(&g_signatures);
    g_load_attempted   = false;
    g_loaded_from_file = false;
    g_loaded_path[0]   = '\0';
}

static usbs_bool resolve_signature_path(char *out, size_t cap)
{
    char data_dir[400];

    if (usbs_ok(usbs_getenv(HASH_MATCH_SIGNATURES_ENV_OVERRIDE, out, cap)) && out[0] != '\0') {
        return true;
    }
    /* Phase 14: the data directory is a platform convention rather than
     * %LOCALAPPDATA% specifically - see usbs_user_data_dir(). */
    if (usbs_ok(usbs_user_data_dir(data_dir, sizeof(data_dir)))) {
        if (usbs_ok(usbs_path_join(out, cap, data_dir, HASH_MATCH_DEFAULT_FILENAME))) {
            return true;
        }
    }
    return false;
}

static void ensure_signatures_loaded(void)
{
    char          path[512];
    usbs_status_t status;

    if (g_load_attempted) {
        return;
    }
    g_load_attempted = true;
    usbs_signature_list_init(&g_signatures);

    if (!resolve_signature_path(path, sizeof(path))) {
        return; /* no resolvable path (e.g. LOCALAPPDATA unset); fallback applies */
    }

    status = usbs_signature_list_load(&g_signatures, path);
    if (status == USBS_ERR_NOT_FOUND) {
        return; /* no file present: the common case, fallback applies, not an error */
    }
    if (!usbs_ok(status)) {
        USBS_LOG_W("could not read signature file %s: %s", path, usbs_status_string(status));
        return;
    }
    if (g_signatures.count == 0) {
        return; /* file existed but had zero valid entries: fallback applies */
    }

    g_loaded_from_file = true;
    snprintf(g_loaded_path, sizeof(g_loaded_path), "%s", path);
}

/*
 * Not declared in any public header - see usbs_hash_match_reset_for_testing().
 * Exposed for tests that need to verify against a known loaded hash without
 * ever writing real EICAR content to disk.
 */
const char *usbs_hash_match_lookup(usbs_u64 size_bytes, const char *hex)
{
    ensure_signatures_loaded();

    if (g_loaded_from_file) {
        return usbs_signature_list_lookup(&g_signatures, size_bytes, hex);
    }

    if (hex != NULL && size_bytes == k_fallback_entry.size &&
        strcmp(hex, k_fallback_entry.sha256_hex) == 0) {
        return k_fallback_entry.label;
    }
    return NULL;
}

static const char *relative_path(const char *full_path, const char *volume_path)
{
    if (volume_path != NULL &&
        strncmp(full_path, volume_path, strlen(volume_path)) == 0) {
        return full_path + strlen(volume_path);
    }
    return full_path;
}

/*
 * The last path component only (Phase 9): g_loaded_path can be an
 * arbitrarily long --signatures path, and the full path previously pushed
 * this disclaimer past USBS_CHECK_MESSAGE_MAX (256 bytes), truncating it
 * identically in JSON, text, and CSV output alike (ARCHITECTURE.md's
 * Phase 7 notes). The filename is what actually matters for a human
 * reading the report - the full path was never load-bearing information
 * here, just incidentally included.
 */
static const char *path_filename(const char *path)
{
    const char *last_sep = NULL;
    const char *p;

    for (p = path; *p != '\0'; ++p) {
        /* Host-path separators, which differ by platform: a backslash is a
         * legal byte in a POSIX filename, so treating it as a separator
         * there would mangle the basename of a file named `a\b.txt`. */
        if (usbs_path_is_separator(*p)) {
            last_sep = p;
        }
    }
    return (last_sep != NULL) ? (last_sep + 1) : path;
}

static void set_disclaimer(usbs_check_result_t *result)
{
    ensure_signatures_loaded();

    if (g_loaded_from_file) {
        snprintf(result->message, sizeof(result->message),
                "Matched against %zu signature(s) loaded from %s - USB Sentinel does not "
                "ship, vet, or vouch for this file's contents; verify its provenance yourself",
                g_signatures.count, path_filename(g_loaded_path));
    } else {
        snprintf(result->message, sizeof(result->message),
                "NON-PRODUCTION EXAMPLE: matched against 1 hardcoded test hash "
                "(EICAR only) - this is NOT a real malware signature database");
    }
}

static usbs_status_t hash_match_on_file(usbs_detector_file_ctx_t *ctx, const char *full_path,
                                        const usbs_dir_entry_t   *entry)
{
    usbs_file_t     *file;
    usbs_status_t    status;
    usbs_hash_ctx_t *hash_ctx = NULL;
    unsigned char    digest[USBS_SHA256_DIGEST_SIZE];
    char             hex[USBS_SHA256_HEX_LEN + 1];
    unsigned char   *buf;
    const char       *label;

    if (ctx == NULL || full_path == NULL || entry == NULL) {
        return USBS_ERR_INVALID_ARG;
    }

    /* This check_result's message doubles as the "prominent disclaimer"
     * (set on every call so it survives regardless of which file happens to
     * trigger it, and shows in both the JSON report and the text renderer -
     * report.c already prints a RAN check's message unconditionally). Also
     * ensures ensure_signatures_loaded() has run before the size check
     * below consults g_loaded_from_file/g_signatures. */
    set_disclaimer(ctx->result);

    if (entry->size_bytes > HASH_MATCH_MAX_FILE_SIZE) {
        return USBS_OK; /* far larger than anything a hash-list entry would plausibly match */
    }

    /*
     * Phase 7: never open a file whose size cannot possibly match anything.
     * Hashing every file regardless of size - checked only against the
     * upper cap above - was an unintended reintroduction of the
     * whole-volume-hashing cost Phase 4 removed from the general traversal
     * (ARCHITECTURE.md's Phase 7 notes). This applies to the single-entry
     * EICAR fallback too, not just a loaded file: it makes no sense to hash
     * a file that already cannot be 68 bytes.
     */
    if (g_loaded_from_file) {
        if (!usbs_signature_list_has_size(&g_signatures, entry->size_bytes)) {
            USBS_LOG_D("hash_match: skipping %s, size %llu matches no loaded signature",
                      full_path, (unsigned long long)entry->size_bytes);
            return USBS_OK;
        }
    } else if (entry->size_bytes != k_fallback_entry.size) {
        return USBS_OK;
    }

    status = usbs_platform_file_open_read(full_path, &file);
    if (!usbs_ok(status)) {
        return USBS_OK; /* per-file error isolation: skip, do not abort the walk */
    }

    if (!usbs_ok(usbs_platform_hash_begin(&hash_ctx))) {
        usbs_platform_file_close(file);
        return USBS_OK;
    }

    buf = (unsigned char *)malloc(HASH_MATCH_READ_CHUNK);
    if (buf == NULL) {
        usbs_platform_hash_abort(hash_ctx);
        usbs_platform_file_close(file);
        return USBS_OK; /* per-file error isolation: skip, do not abort the walk */
    }

    for (;;) {
        size_t read = 0;
        status = usbs_platform_file_read(file, buf, HASH_MATCH_READ_CHUNK, &read);
        if (!usbs_ok(status) || read == 0) {
            break;
        }
        usbs_platform_hash_update(hash_ctx, buf, read);
    }
    free(buf);
    usbs_platform_file_close(file);

    if (!usbs_ok(usbs_platform_hash_finish(hash_ctx, digest, hex))) {
        return USBS_OK;
    }

    label = usbs_hash_match_lookup(entry->size_bytes, hex);
    if (label != NULL) {
        usbs_finding_t finding;
        memset(&finding, 0, sizeof(finding));
        finding.severity = USBS_SEVERITY_HIGH;
        snprintf(finding.path, sizeof(finding.path), "%s",
                relative_path(full_path, ctx->detect_ctx != NULL
                                              ? ctx->detect_ctx->volume_path
                                              : NULL));
        snprintf(finding.message, sizeof(finding.message),
                "matches signature list entry: %s (sha256=%s)%s",
                label, hex,
                g_loaded_from_file ? "" : " - demonstration match, not a real threat-intelligence source");
        usbs_finding_list_push(&ctx->result->findings, &finding);
    }

    return USBS_OK;
}

const usbs_detector_t usbs_detector_hash_match = {
    .id          = HASH_MATCH_ID,
    .description = "Matches file content by SHA-256 against a loaded signature file "
                   "(falling back to one hardcoded EICAR entry if none is found) - "
                   "not a bundled malware signature database",
    .on_file     = hash_match_on_file,
};
