/*
 * Device enumeration and capability probing for a UNIX host with no
 * OS-specific backend of its own - anything that is neither Linux
 * (device_linux.c) nor Apple (device_macos.c). Selected by CMake
 * (ARCHITECTURE.md section 21), the same "one backend per host" pattern
 * section 20.5 established for the platform layer generally.
 *
 * Reports USBS_ERR_UNSUPPORTED honestly rather than returning an empty
 * device list, which would be indistinguishable from "no USB devices
 * attached" and is exactly the kind of confident-but-wrong answer
 * ARCHITECTURE.md section 7.3 exists to prevent. This is also, deliberately,
 * what Apple links until device_macos.c replaces it - keeping macOS building
 * and CI-green throughout Phase 14b's Linux-first sequencing rather than
 * only once every platform's real backend exists.
 */
#include <string.h>

#include "usbsentinel/platform.h"

usbs_device_source_t usbs_platform_device_source(void)
{
    usbs_device_source_t source;

    /* A NULL enumerate is what usbs_device_enumerate() turns into
     * USBS_ERR_UNSUPPORTED - the seam reports that it has no backend rather
     * than pretending to have found nothing. */
    source.enumerate = NULL;
    source.ctx       = NULL;
    return source;
}

void usbs_capabilities_init(usbs_capabilities_t *caps)
{
    if (caps != NULL) {
        memset(caps, 0, sizeof(*caps));
    }
}

usbs_status_t usbs_platform_probe_capabilities(const usbs_device_t *device,
                                               usbs_capabilities_t *out_caps)
{
    /* Argument validation comes first and is platform-independent: a NULL
     * pointer is a caller error on every host, whereas "unsupported"
     * describes the operation. Reporting UNSUPPORTED for a NULL argument
     * would tell the caller the wrong thing about their own bug, and would
     * make the contract in platform.h true only on Windows. */
    if (device == NULL || out_caps == NULL) {
        return USBS_ERR_INVALID_ARG;
    }
    usbs_capabilities_init(out_caps);
    return USBS_ERR_UNSUPPORTED;
}
