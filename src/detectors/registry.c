#include "usbsentinel/detector.h"

/* Fixed, statically-compiled array. Adding a detector means adding one line
 * here - no dynamic loading, no plugin discovery (ARCHITECTURE.md's Phase 3
 * decision, reaffirmed for Phase 4 and Phase 5). */
extern const usbs_detector_t usbs_detector_autorun;
extern const usbs_detector_t usbs_detector_suspicious_filename;
extern const usbs_detector_t usbs_detector_lnk_inspect;
extern const usbs_detector_t usbs_detector_hash_match;

static const usbs_detector_t *const k_detectors[] = {
    &usbs_detector_autorun,
    &usbs_detector_suspicious_filename,
    &usbs_detector_lnk_inspect,
    &usbs_detector_hash_match,
};

size_t usbs_detector_count(void)
{
    return USBS_ARRAY_LEN(k_detectors);
}

const usbs_detector_t *usbs_detector_at(size_t index)
{
    if (index >= usbs_detector_count()) {
        return NULL;
    }
    return k_detectors[index];
}
