/*
 * USB Sentinel - in-memory scan result model.
 *
 * Shared by scanner (produces), detectors (fills individual checks), and
 * reporting (serializes/renders). Portable C17, no platform headers - this
 * is exactly the structure ARCHITECTURE.md section 7.4 describes as
 * "the in-memory scan-result structure that scanner produced."
 */
#ifndef USBSENTINEL_SCAN_H
#define USBSENTINEL_SCAN_H

#include "usbsentinel/device.h"
#include "usbsentinel/error.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/types.h"

/*
 * A crashed process cannot honestly report its own status, so that state is
 * not modeled here; a crash simply leaves no report behind (storage's
 * atomic-write rule ensures it leaves no *partial* one either).
 */
typedef enum usbs_scan_status {
    USBS_SCAN_COMPLETED = 0,
    USBS_SCAN_ABORTED
} usbs_scan_status_t;

typedef enum usbs_check_status {
    USBS_CHECK_RAN = 0,
    USBS_CHECK_SKIPPED,
    USBS_CHECK_FAILED
} usbs_check_status_t;

const char *usbs_check_status_string(usbs_check_status_t status);
const char *usbs_scan_status_string(usbs_scan_status_t status);

/*
 * Triage signal for a finding. Deliberately a small closed set, named to
 * match the vocabulary log.h already uses (info/warning) plus one level for
 * "acted-upon-worthy" - not a scoring system. Added in Phase 4; additive per
 * the schema-versioning rule in ARCHITECTURE.md section 7.4/9.2, so
 * schema_version stays 1.
 */
typedef enum usbs_severity {
    USBS_SEVERITY_INFO = 0,
    USBS_SEVERITY_WARNING,
    USBS_SEVERITY_HIGH
} usbs_severity_t;

const char *usbs_severity_string(usbs_severity_t severity);

#define USBS_FINDING_MESSAGE_MAX 256
#define USBS_FINDING_PATH_MAX    512

/* Detector-defined content. The envelope around findings (usbs_check_result_t)
 * is fixed; what a detector puts inside one finding is up to the detector -
 * see ARCHITECTURE.md's Phase 3 report-schema note. `severity` is the one
 * exception: it is deliberately part of the fixed envelope (not free-form),
 * because every detector needs the same small vocabulary for a report or a
 * human to triage across findings. */
typedef struct usbs_finding {
    usbs_severity_t severity;
    char message[USBS_FINDING_MESSAGE_MAX];
    char path[USBS_FINDING_PATH_MAX]; /* relative to the volume root; may be empty */
} usbs_finding_t;

typedef struct usbs_finding_list {
    usbs_finding_t *items;
    size_t          count;
    size_t          capacity;
} usbs_finding_list_t;

void          usbs_finding_list_init(usbs_finding_list_t *list);
usbs_status_t usbs_finding_list_push(usbs_finding_list_t *list, const usbs_finding_t *finding);
void          usbs_finding_list_free(usbs_finding_list_t *list);

#define USBS_CHECK_ID_MAX      64
#define USBS_SKIP_REASON_MAX   128
#define USBS_CHECK_MESSAGE_MAX 256

typedef struct usbs_check_result {
    char                 id[USBS_CHECK_ID_MAX];
    usbs_check_status_t  status;
    char                 skip_reason[USBS_SKIP_REASON_MAX]; /* only if SKIPPED */
    char                 message[USBS_CHECK_MESSAGE_MAX];   /* optional detail */
    usbs_finding_list_t  findings;
} usbs_check_result_t;

/* Initializes `result` with `id` and USBS_CHECK_RAN; findings start empty. */
void usbs_check_result_init(usbs_check_result_t *result, const char *id);
void usbs_check_result_free(usbs_check_result_t *result);

/* Convenience setters; each also frees any findings already recorded, since
 * a skipped or failed check has none. */
void usbs_check_result_set_skipped(usbs_check_result_t *result, const char *reason);
void usbs_check_result_set_failed(usbs_check_result_t *result, const char *message);

typedef struct usbs_check_list {
    usbs_check_result_t *items;
    size_t                count;
    size_t                capacity;
} usbs_check_list_t;

void          usbs_check_list_init(usbs_check_list_t *list);
/* Takes ownership of `result`'s findings allocation (shallow copy + reset of
 * the source), matching usbs_device_list_push's pattern. */
usbs_status_t usbs_check_list_push(usbs_check_list_t *list, usbs_check_result_t *result);
void          usbs_check_list_free(usbs_check_list_t *list);

#define USBS_SCAN_ID_MAX   40 /* GUID string plus terminator */
#define USBS_TIMESTAMP_MAX 32 /* ISO-8601 UTC */

typedef struct usbs_scan_result {
    char                 scan_id[USBS_SCAN_ID_MAX];
    char                 started_at[USBS_TIMESTAMP_MAX];
    char                 finished_at[USBS_TIMESTAMP_MAX];
    usbs_scan_status_t   status;

    usbs_device_t        device;
    usbs_capabilities_t  capabilities;

    usbs_check_list_t    checks;
} usbs_scan_result_t;

void usbs_scan_result_init(usbs_scan_result_t *result);
void usbs_scan_result_free(usbs_scan_result_t *result);

#endif /* USBSENTINEL_SCAN_H */
