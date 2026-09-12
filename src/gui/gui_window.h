/*
 * USB Sentinel - main GUI window (Phase 8, ARCHITECTURE.md section 14).
 *
 * Module-internal, like cli.h: not part of the cross-module surface in
 * include/usbsentinel/.
 */
#ifndef USBS_GUI_WINDOW_H
#define USBS_GUI_WINDOW_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * Registers the main window class, creates the one main window, and runs
 * the message loop until it is closed. Returns the WM_QUIT exit code.
 */
int gui_window_run(HINSTANCE instance, int show_command);

#endif /* USBS_GUI_WINDOW_H */
