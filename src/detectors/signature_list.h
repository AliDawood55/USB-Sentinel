/*
 * Internal to the detectors module - not part of the public surface in
 * include/usbsentinel. A hash-list signature format loader, ClamAV-inspired
 * but not claimed byte-for-byte compatible with any specific ClamAV format
 * version (ARCHITECTURE.md's Phase 6 notes: that would need independent
 * verification against real ClamAV documentation/samples, which was not
 * done - the same discipline the EICAR hash got before being hardcoded).
 *
 * One entry per line: "sha256:size:name". Blank lines and lines starting
 * with '#' are ignored. SHA-256 only - no MD5, keeping the project's crypto
 * surface at exactly the one verified primitive from Phase 4.
 */
#ifndef USBSENTINEL_DETECTORS_SIGNATURE_LIST_H
#define USBSENTINEL_DETECTORS_SIGNATURE_LIST_H

#include "usbsentinel/error.h"
#include "usbsentinel/types.h"

#define USBS_SIGNATURE_HASH_LEN 64  /* SHA-256 hex, no terminator */
#define USBS_SIGNATURE_NAME_MAX 160

typedef struct usbs_signature {
    char     sha256_hex[USBS_SIGNATURE_HASH_LEN + 1]; /* lowercase, normalized on load */
    usbs_u64 size;
    char     name[USBS_SIGNATURE_NAME_MAX];
} usbs_signature_t;

typedef struct usbs_signature_list {
    usbs_signature_t *entries; /* sorted by size once loaded - see lookup() */
    size_t            count;
    size_t            capacity;
} usbs_signature_list_t;

void usbs_signature_list_init(usbs_signature_list_t *list);
void usbs_signature_list_free(usbs_signature_list_t *list);

/*
 * Loads signatures from `path`. A malformed line is skipped (logged, capped
 * to avoid log spam on a badly-formed file) - it does not fail the load;
 * only file-level problems do. Returns USBS_ERR_NOT_FOUND if `path` does
 * not exist - the caller's cue to fall back to default behavior, not a hard
 * error. The file is read up to a bounded cap (64 MiB); anything beyond
 * that is not read at all (logged), keeping load cost bounded regardless of
 * how large a supplied file is. On success the list is sorted by size,
 * ready for usbs_signature_list_lookup().
 */
usbs_status_t usbs_signature_list_load(usbs_signature_list_t *list, const char *path);

/*
 * Returns the matching entry's name, or NULL if nothing in `list` has both
 * `size_bytes` and `sha256_hex`. Comparison is an exact (case-sensitive)
 * string match: the loader normalizes every stored hash to lowercase, and
 * `sha256_hex` is expected to already be lowercase too - exactly what
 * usbs_platform_hash_finish() produces, the only real caller. O(log n + k),
 * k = entries sharing that exact size, via binary search into the
 * size-sorted array - not a linear scan of the whole list, which matters
 * once a real, large signature file is loaded (ARCHITECTURE.md's Phase 6
 * notes).
 */
const char *usbs_signature_list_lookup(const usbs_signature_list_t *list,
                                       usbs_u64                     size_bytes,
                                       const char                  *sha256_hex);

/*
 * True iff `list` has at least one entry with exactly `size_bytes`. O(log n)
 * via the same size-sorted binary search as lookup(). Meant to be checked
 * *before* opening and hashing a candidate file (Phase 7): hashing every
 * file regardless of whether its size could possibly match anything was a
 * real, unintended reintroduction of the whole-volume-hashing cost Phase 4
 * removed from the general traversal - see ARCHITECTURE.md's Phase 7 notes.
 */
usbs_bool usbs_signature_list_has_size(const usbs_signature_list_t *list, usbs_u64 size_bytes);

#endif /* USBSENTINEL_DETECTORS_SIGNATURE_LIST_H */
