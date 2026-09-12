/*
 * USB Sentinel - resource identifiers shared between the GUI's C code and
 * its resource script.
 *
 * The single source of truth for these ids: resources/usb_sentinel_gui.rc.in
 * includes this header (by an absolute path CMake substitutes in, so the
 * resource compiler needs no -I of its own) rather than redeclaring the
 * numbers, which is the classic way an .rc and its consumer drift apart.
 *
 * IDI_USBS_APP_ICON is deliberately the lowest-numbered - and currently
 * only - ICON resource in the executable: Windows Explorer uses the
 * numerically lowest icon resource as a program's representative icon, so
 * any icon added later must take a higher id than this one.
 */
#ifndef USBS_GUI_RESOURCE_H
#define USBS_GUI_RESOURCE_H

#define IDI_USBS_APP_ICON 101

#endif /* USBS_GUI_RESOURCE_H */
