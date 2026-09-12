/*
 * USB Sentinel - GUI executable entry point.
 *
 * Deliberately narrow, mirroring app/main.c: opt in to ComCtl32 v6 visual
 * styles (needed for the progress bar/buttons to render as anything but
 * Windows 95-style controls - ARCHITECTURE.md section 14's noted pitfall),
 * then hand off to gui_window_run() and return its exit code. No scanning
 * or window logic lives here.
 */
#include "gui_window.h"

#include "usbsentinel/types.h"

#if defined(_MSC_VER)
#pragma comment(linker, \
    "\"/manifestdependency:type='win32' " \
    "name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' processorArchitecture='*' " \
    "publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

/*
 * SAL annotations mirrored from the SDK's own wWinMain prototype
 * (winbase.h) so /analyze does not flag a mismatch (C28251) between this
 * definition and that declaration - Phase 12, ARCHITECTURE.md section 18.
 */
int WINAPI wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev_instance,
                    _In_ PWSTR cmd_line, _In_ int show_command)
{
    USBS_UNUSED(prev_instance);
    USBS_UNUSED(cmd_line);
    return gui_window_run(instance, show_command);
}
