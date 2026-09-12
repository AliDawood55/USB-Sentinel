/*
 * USB Sentinel - report serialization and rendering.
 *
 * JSON is the primary, machine-readable format; the text renderer is a
 * formatter over the same in-memory usbs_scan_result_t, never a second
 * source of truth (ARCHITECTURE.md section 7.4). Depends only on core: it
 * reads the structure scanner produced and has no knowledge of storage or
 * platform.
 */
#ifndef USBSENTINEL_REPORT_H
#define USBSENTINEL_REPORT_H

#include <stdio.h>

#include "usbsentinel/scan.h"

#define USBS_REPORT_SCHEMA_VERSION 1

/*
 * Serializes `result` to JSON. On success, *out_text is a freshly allocated,
 * NUL-terminated buffer the caller must free(); *out_len excludes the
 * terminator.
 */
usbs_status_t usbs_report_build_json(const usbs_scan_result_t *result,
                                     char                    **out_text,
                                     size_t                    *out_len);

/* Renders `result` as human-readable text to `stream`. */
void usbs_report_render_text(const usbs_scan_result_t *result, FILE *stream);

/*
 * Serializes `result` to CSV (Phase 7): one row per (check, finding) pair,
 * plus one row for any check with zero findings (empty finding columns,
 * populated status) - a check is never simply absent from the file, the
 * same "never simply absent" discipline ARCHITECTURE.md section 7.3 already
 * applies to JSON. Columns: scan_id, device_identity, check_id,
 * check_status, skip_reason, severity, path, message.
 *
 * RFC 4180 field quoting throughout. A field beginning with '=', '+', '-',
 * or '@' - which a spreadsheet application could interpret as a formula -
 * is additionally prefixed with a single quote, a standard, minimal
 * mitigation: this content can originate from an attacker-controlled
 * filename or LNK-derived string, never from anything USB Sentinel itself
 * generated (ARCHITECTURE.md's Phase 7 notes).
 *
 * On success, *out_text is a freshly allocated, NUL-terminated buffer the
 * caller must free(); *out_len excludes the terminator.
 */
usbs_status_t usbs_report_build_csv(const usbs_scan_result_t *result,
                                    char                    **out_text,
                                    size_t                    *out_len);

#endif /* USBSENTINEL_REPORT_H */
