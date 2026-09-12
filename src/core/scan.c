/*
 * Placed in core (not scanner) so both scanner and detectors can depend on
 * it without creating a cycle: scanner depends on detectors, so anything
 * detectors also needs must sit below both. This is pure data-structure
 * bookkeeping, no I/O, matching core's existing role.
 */
#include "usbsentinel/scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *usbs_check_status_string(usbs_check_status_t status)
{
    switch (status) {
    case USBS_CHECK_RAN:     return "ran";
    case USBS_CHECK_SKIPPED: return "skipped";
    case USBS_CHECK_FAILED:  return "failed";
    }
    return "unknown";
}

const char *usbs_scan_status_string(usbs_scan_status_t status)
{
    switch (status) {
    case USBS_SCAN_COMPLETED: return "completed";
    case USBS_SCAN_ABORTED:   return "aborted";
    }
    return "unknown";
}

const char *usbs_severity_string(usbs_severity_t severity)
{
    switch (severity) {
    case USBS_SEVERITY_INFO:    return "info";
    case USBS_SEVERITY_WARNING: return "warning";
    case USBS_SEVERITY_HIGH:    return "high";
    }
    return "unknown";
}

void usbs_finding_list_init(usbs_finding_list_t *list)
{
    if (list == NULL) {
        return;
    }
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

usbs_status_t usbs_finding_list_push(usbs_finding_list_t *list, const usbs_finding_t *finding)
{
    if (list == NULL || finding == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (list->count == list->capacity) {
        size_t          next = (list->capacity == 0) ? 4 : list->capacity * 2;
        usbs_finding_t *grown;

        if (next > SIZE_MAX / sizeof(usbs_finding_t)) {
            return USBS_ERR_NO_MEMORY;
        }
        grown = (usbs_finding_t *)realloc(list->items, next * sizeof(usbs_finding_t));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        list->items    = grown;
        list->capacity = next;
    }
    list->items[list->count] = *finding;
    ++list->count;
    return USBS_OK;
}

void usbs_finding_list_free(usbs_finding_list_t *list)
{
    if (list == NULL) {
        return;
    }
    free(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

void usbs_check_result_init(usbs_check_result_t *result, const char *id)
{
    if (result == NULL) {
        return;
    }
    memset(result, 0, sizeof(*result));
    if (id != NULL) {
        snprintf(result->id, sizeof(result->id), "%s", id);
    }
    result->status = USBS_CHECK_RAN;
    usbs_finding_list_init(&result->findings);
}

void usbs_check_result_free(usbs_check_result_t *result)
{
    if (result == NULL) {
        return;
    }
    usbs_finding_list_free(&result->findings);
}

void usbs_check_result_set_skipped(usbs_check_result_t *result, const char *reason)
{
    if (result == NULL) {
        return;
    }
    usbs_finding_list_free(&result->findings);
    usbs_finding_list_init(&result->findings);
    result->status = USBS_CHECK_SKIPPED;
    snprintf(result->skip_reason, sizeof(result->skip_reason), "%s",
             reason != NULL ? reason : "");
}

void usbs_check_result_set_failed(usbs_check_result_t *result, const char *message)
{
    if (result == NULL) {
        return;
    }
    usbs_finding_list_free(&result->findings);
    usbs_finding_list_init(&result->findings);
    result->status = USBS_CHECK_FAILED;
    snprintf(result->message, sizeof(result->message), "%s",
             message != NULL ? message : "");
}

void usbs_check_list_init(usbs_check_list_t *list)
{
    if (list == NULL) {
        return;
    }
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

usbs_status_t usbs_check_list_push(usbs_check_list_t *list, usbs_check_result_t *result)
{
    if (list == NULL || result == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    if (list->count == list->capacity) {
        size_t                next = (list->capacity == 0) ? 4 : list->capacity * 2;
        usbs_check_result_t *grown;

        if (next > SIZE_MAX / sizeof(usbs_check_result_t)) {
            return USBS_ERR_NO_MEMORY;
        }
        grown = (usbs_check_result_t *)realloc(list->items, next * sizeof(usbs_check_result_t));
        if (grown == NULL) {
            return USBS_ERR_NO_MEMORY;
        }
        list->items    = grown;
        list->capacity = next;
    }

    /* Take ownership of the findings allocation; reset the source so a
     * subsequent usbs_check_result_free() on it is a no-op, not a double free. */
    list->items[list->count] = *result;
    memset(result, 0, sizeof(*result));
    ++list->count;
    return USBS_OK;
}

void usbs_check_list_free(usbs_check_list_t *list)
{
    size_t i;

    if (list == NULL) {
        return;
    }
    for (i = 0; i < list->count; ++i) {
        usbs_finding_list_free(&list->items[i].findings);
    }
    free(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

void usbs_scan_result_init(usbs_scan_result_t *result)
{
    if (result == NULL) {
        return;
    }
    /* device/capabilities are POD whose own _init() is exactly this same
     * zeroing; calling them here would make core link platform (device.c and
     * device_win32.c live in usbs_platform, which already links usbs_core -
     * core must have zero outgoing library dependencies, ARCHITECTURE.md
     * section 2), so the zeroing is inlined instead of called. */
    memset(result, 0, sizeof(*result));
    usbs_check_list_init(&result->checks);
}

void usbs_scan_result_free(usbs_scan_result_t *result)
{
    if (result == NULL) {
        return;
    }
    usbs_check_list_free(&result->checks);
}
