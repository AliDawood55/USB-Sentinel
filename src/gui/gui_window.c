/*
 * USB Sentinel - main GUI window.
 *
 * A resizable window: a device dropdown, Refresh/Scan/Cancel buttons, a
 * determinate progress bar, an owner-drawn verdict banner, and a styled
 * results view fed by gui_report_view.c (the pure, testable formatter -
 * NOT a second source of truth; see that file's header) and an "Open
 * Reports Folder" button in place of an embedded JSON/CSV viewer
 * (ARCHITECTURE.md section 14.4: a viewer would need a JSON deserializer,
 * already deferred once in Phase 7's TASKS.md).
 *
 * Phase 11 changed three things about the presentation layer, all recorded
 * in ARCHITECTURE.md section 17:
 *
 *   - The results view is a RichEdit 4.1 control, not an EDIT. A Win32
 *     EDIT has exactly one text colour for its whole content, so colouring
 *     a malicious finding red is not merely awkward there, it is
 *     impossible without writing a custom control. RichEdit is loaded at
 *     runtime from Msftedit.dll; if that fails, the window falls back to a
 *     plain EDIT showing the same text without colour, rather than
 *     presenting an empty results area.
 *
 *   - The progress bar is determinate. Phase 8 used a marquee on the
 *     grounds that "a fake percentage would be dishonest data", which was
 *     right about invented numbers but overlooked that usbs_device_t
 *     already carries capacity_bytes and free_bytes: used bytes is a real
 *     figure the filesystem reports, and bytes_scanned can be measured
 *     against it. Where that denominator is unavailable the bar reverts to
 *     a marquee rather than guessing.
 *
 *   - The window has an application icon, from the .rc resource compiled
 *     into usb-sentinel-gui.exe.
 *
 * Phase 17 (ARCHITECTURE.md section 23.5) adds an opt-in "Show all drives"
 * checkbox. It re-enumerates in USBS_ENUM_ALL_VOLUMES mode, so internal
 * disks and mapped network drives become selectable. Unchecked, which is
 * the default, is exactly the USB-only window of every earlier phase.
 * Auto-scan on hot-plug stays USB-only in either mode (handle_device_change).
 *
 * Threading is unchanged from Phase 8: Scan spawns one _beginthreadex
 * worker that calls gui_worker_run() (gui_worker.h/.c - the testable core).
 * The worker never touches this window's HWND directly; it only
 * PostMessage()s WM_APP_SCAN_PROGRESS/WM_APP_SCAN_DONE with a
 * heap-allocated payload this window's procedure frees after use. Every
 * call into storage/reporting happens on the UI thread, from those message
 * handlers - never from the worker thread (ARCHITECTURE.md section 4's
 * logger is not documented thread-safe either, which is the other reason to
 * keep all of that on one thread). Only one scan runs at a time: Scan is
 * disabled for the duration, so the progress-throttle state in gui_state_t
 * (last_progress_tick/final_progress/have_final_progress) needs no locking.
 */
#include "gui_window.h"
#include "gui_report_view.h"
#include "gui_worker.h"

/* MSFTEDIT_CLASS (RichEdit 4.1) is declared in richedit.h only when
 * _RICHEDIT_VER asks for it; the header's own default is 0x0300, which
 * would leave the class name undefined and silently push this file onto
 * the plain-EDIT fallback path at compile time. */
#define _RICHEDIT_VER 0x0500

#include <commctrl.h>
#include <dbt.h>
#include <process.h>
#include <richedit.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "usbsentinel/device.h"
#include "usbsentinel/platform.h"
#include "usbsentinel/report.h"
#include "usbsentinel/storage.h"
#include "usbsentinel/types.h"

#include "usbs_gui_resource.h"

#define IDC_COMBO_DEVICES   1001
#define IDC_BUTTON_REFRESH  1002
#define IDC_BUTTON_SCAN     1003
#define IDC_BUTTON_CANCEL   1004
#define IDC_BUTTON_OPENDIR  1005
#define IDC_PROGRESS        1006
#define IDC_EDIT_RESULTS    1007
#define IDC_STATIC_STATUS   1008
#define IDC_CHECK_AUTOSCAN  1009
#define IDC_STATIC_BANNER   1010
#define IDC_STATIC_DEVICE   1011
#define IDC_CHECK_ALLDRIVES 1012

#define WM_APP_SCAN_PROGRESS (WM_APP + 1)
#define WM_APP_SCAN_DONE      (WM_APP + 2)

/* How many distinct device identities the auto-scan "already handled"
 * guard tracks at once (Phase 9, section 14.6) - generous for a real
 * session (one or two USB drives at a time); if ever exceeded, the
 * oldest-tracked identities simply stop being guarded rather than growing a
 * dynamic list for a case this unlikely. */
#define GUI_AUTO_SCAN_TRACK_MAX 8

/* Progress bar resolution. Finer than 0..100 so the bar advances visibly
 * on a large volume instead of stepping a whole percent at a time. */
#define GUI_PROGRESS_RANGE 1000

/* Layout metrics, in the same unscaled pixels the rest of this file uses.
 * This window is not per-monitor DPI aware (see ARCHITECTURE.md section
 * 17.6 for why that was left out of this phase); Windows bitmap-scales it
 * on a high-DPI display. */
#define GUI_MARGIN        14
#define GUI_ROW_H         26
#define GUI_GAP            8
#define GUI_BANNER_H      52
#define GUI_MIN_WIDTH    620
#define GUI_MIN_HEIGHT   520

/*
 * GUID_DEVINTERFACE_VOLUME, {53f5630d-b6bf-11d0-94f2-00a0c91efb8b} - a
 * stable, publicly documented Microsoft constant (used to filter
 * RegisterDeviceNotificationW to volume arrivals/removals only). Declared
 * directly rather than pulling in <ntddstor.h> + <initguid.h> (which would
 * need INITGUID defined in exactly one translation unit to avoid an
 * unresolved external) - one well-known GUID value is simpler and needs no
 * new header or link dependency.
 */
static const GUID k_guid_devinterface_volume =
    { 0x53f5630d, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b } };

/* ------------------------------------------------------------------------ *
 * Palette. gui_report_view.c emits semantic styles; the mapping to actual
 * colours lives here so the two can change independently and so the
 * formatter's tests never have to know an RGB value.
 * ------------------------------------------------------------------------ */

#define GUI_COLOR_TITLE   RGB( 17,  24,  39)
#define GUI_COLOR_SECTION RGB( 30,  58, 110)
#define GUI_COLOR_LABEL   RGB( 90,  98, 112)
#define GUI_COLOR_BODY    RGB( 28,  32,  38)
#define GUI_COLOR_MUTED   RGB(114, 122, 136)
#define GUI_COLOR_GOOD    RGB( 14, 118,  62)
#define GUI_COLOR_WARNING RGB(174,  94,   0)
#define GUI_COLOR_THREAT  RGB(190,  24,  38)
#define GUI_COLOR_PAPER   RGB(252, 252, 253)

typedef struct gui_style_spec {
    COLORREF color;
    usbs_bool bold;
    int       point_delta; /* added to the base font size, in points */
} gui_style_spec_t;

/* Indexed by gui_text_style_t; order must match that enum. */
static const gui_style_spec_t k_styles[GUI_STYLE_COUNT] = {
    { GUI_COLOR_TITLE,   true,  2 },  /* GUI_STYLE_TITLE   */
    { GUI_COLOR_SECTION, true,  0 },  /* GUI_STYLE_SECTION */
    { GUI_COLOR_LABEL,   false, 0 },  /* GUI_STYLE_LABEL   */
    { GUI_COLOR_BODY,    false, 0 },  /* GUI_STYLE_BODY    */
    { GUI_COLOR_MUTED,   false, 0 },  /* GUI_STYLE_MUTED   */
    { GUI_COLOR_GOOD,    true,  0 },  /* GUI_STYLE_GOOD    */
    { GUI_COLOR_WARNING, true,  0 },  /* GUI_STYLE_WARNING */
    { GUI_COLOR_THREAT,  true,  0 }   /* GUI_STYLE_THREAT  */
};

typedef struct gui_banner_spec {
    COLORREF background;
    COLORREF foreground;
} gui_banner_spec_t;

static gui_banner_spec_t banner_colors(gui_verdict_t verdict)
{
    gui_banner_spec_t spec;
    switch (verdict) {
    case GUI_VERDICT_THREAT:
        spec.background = RGB(183, 28, 38);
        break;
    case GUI_VERDICT_SUSPICIOUS:
        spec.background = RGB(176, 106, 12);
        break;
    case GUI_VERDICT_INCOMPLETE:
        spec.background = RGB(74, 96, 130);
        break;
    case GUI_VERDICT_CLEAN:
    default:
        spec.background = RGB(22, 122, 70);
        break;
    }
    spec.foreground = RGB(255, 255, 255);
    return spec;
}

typedef struct gui_state {
    usbs_device_list_t devices;    /* scannable devices for enum_mode(); combo box index maps 1:1 */

    /* Phase 17: false (the default) lists USB devices only, exactly as
     * before; true lists every mounted volume. */
    usbs_bool show_all_drives;
    ULONGLONG scan_started_tick; /* for the elapsed time in the live status line */
    usbs_store_t        store;
    usbs_bool            have_store;
    gui_cancel_flag_t    cancel_flag;
    HANDLE                worker_thread; /* NULL when idle */
    usbs_bool             scanning;

    char      last_report_dir[USBS_STORE_PATH_MAX];
    usbs_bool have_last_report_dir;

    /* Phase 9: hot-plug detection state. */
    HDEVNOTIFY dev_notify; /* NULL if RegisterDeviceNotificationW failed */
    usbs_bool  auto_scan_enabled;
    char       auto_scanned_identities[GUI_AUTO_SCAN_TRACK_MAX][USBS_IDENTITY_MAX];
    size_t     auto_scanned_count;

    /* Phase 11: progress and verdict state. */
    usbs_u64  progress_total_bytes; /* 0 => indeterminate, fall back to marquee */
    usbs_bool progress_determinate;
    int       progress_last_pos;    /* monotonic: the bar never runs backwards */
    usbs_scan_progress_t last_progress;
    usbs_bool            have_progress;

    usbs_bool     banner_visible;
    gui_verdict_t banner_verdict;
    wchar_t       banner_headline[64];
    wchar_t       banner_detail[256];

    /* Phase 11 progress-throttle state, moved off file-scope statics in
     * Phase 12 (ARCHITECTURE.md section 18): one gui_state_t per running
     * scan means these belong to the scan, not the process. Only one scan
     * runs at a time (Scan is disabled while scanning) and these fields are
     * written exclusively by the worker thread via gui_on_progress() and
     * read exclusively by the UI thread in handle_scan_done() after
     * WaitForSingleObject() has joined that thread - the join's
     * happens-before relationship is what still makes this safe without a
     * lock, exactly as it was when the state lived in statics. */
    ULONGLONG            last_progress_tick;
    usbs_scan_progress_t final_progress;
    usbs_bool            have_final_progress;

    HFONT font_ui;      /* the real shell UI font (Segoe UI on Win10/11) */
    HFONT font_banner;  /* larger + bold, for the verdict banner */
    HFONT font_detail;  /* the banner's second line */

    usbs_bool results_is_rich; /* false when Msftedit.dll could not be loaded */

    HWND hwnd;
    HWND label_device;
    HWND combo_devices;
    HWND btn_refresh;
    HWND btn_scan;
    HWND btn_cancel;
    HWND btn_opendir;
    HWND chk_autoscan;
    HWND chk_alldrives;
    HWND progress;
    HWND banner;
    HWND edit_results;
    HWND label_status;
} gui_state_t;

typedef struct gui_done_payload {
    usbs_status_t        status;
    usbs_scan_result_t  *result; /* NULL iff status != USBS_OK */
} gui_done_payload_t;

typedef struct worker_launch {
    gui_worker_args_t args;
} worker_launch_t;

/*
 * last_progress_tick/final_progress/have_final_progress live in gui_state_t
 * (moved off file-scope statics in Phase 12 - ARCHITECTURE.md section 18).
 *
 * final_progress is the most recent progress snapshot, recorded on EVERY
 * callback - including the ones the throttle in gui_on_progress() declines
 * to post to the UI.
 *
 * Throttling is about how often the window repaints; it must not decide
 * what the finished report is allowed to say happened. Keeping only the
 * last *posted* snapshot gets this catastrophically wrong on a fast scan:
 * the walk is metadata-only (ARCHITECTURE.md section 10), so a 631-file
 * volume can finish inside the first 100 ms window, leaving the last posted
 * snapshot at "1 file, 12 bytes" while the scan really covered 631 files
 * and 14.8 GB. That was a real defect found by comparing the window
 * against the saved report for the same scan, not by reading the code.
 *
 * Written only by the worker thread; read only by the UI thread in
 * handle_scan_done(), and only after WaitForSingleObject() on that thread
 * has returned - thread exit happens-before a successful join, so the read
 * needs no further synchronization.
 */

/* Kept for the process lifetime once loaded: freeing it would unregister
 * the RichEdit window class out from under a live control. */
static HMODULE s_richedit_module;

/* ------------------------------------------------------------------------ *
 * UTF-8 / UTF-16 helpers - mirrors fs_win32.c's small, file-local
 * conversion helpers rather than sharing one: this is the only other
 * translation unit that needs them, and each stays self-contained
 * (ARCHITECTURE.md's "wait for a real 2nd/3rd consumer" applies to
 * abstractions, not to every few lines of duplication).
 * ------------------------------------------------------------------------ */

static usbs_bool utf8_to_wide(const char *utf8, wchar_t *wide, size_t wide_cap)
{
    int written;
    if (utf8 == NULL || wide == NULL || wide_cap == 0) {
        return false;
    }
    written = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, (int)wide_cap);
    return written > 0;
}

static void set_status_utf8(gui_state_t *state, const char *utf8)
{
    wchar_t wide[256];
    if (utf8_to_wide(utf8, wide, USBS_ARRAY_LEN(wide))) {
        SetWindowTextW(state->label_status, wide);
    }
}

/* Bytes in human units, e.g. "953.2 GiB". Shared by the live status line
 * and (Phase 17) the dropdown labels of non-USB drives. */
static void format_bytes(usbs_u64 bytes, char *buf, size_t cap)
{
    static const char *const units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    double value = (double)bytes;
    size_t unit  = 0;

    while (value >= 1024.0 && unit + 1 < USBS_ARRAY_LEN(units)) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        snprintf(buf, cap, "%llu B", (unsigned long long)bytes);
    } else {
        snprintf(buf, cap, "%.1f %s", value, units[unit]);
    }
}

static usbs_enum_mode_t enum_mode(const gui_state_t *state)
{
    return state->show_all_drives ? USBS_ENUM_ALL_VOLUMES : USBS_ENUM_USB_ONLY;
}

/* ------------------------------------------------------------------------ *
 * Fonts. GetStockObject(DEFAULT_GUI_FONT) returns an ancient bitmap face
 * (MS Sans Serif-era), which is the single biggest reason a hand-built
 * Win32 window looks two decades old. SPI_GETNONCLIENTMETRICS reports the
 * font the shell itself uses - Segoe UI on Windows 10/11.
 * ------------------------------------------------------------------------ */

static void create_fonts(gui_state_t *state)
{
    NONCLIENTMETRICSW metrics;
    LOGFONTW          base;

    memset(&metrics, 0, sizeof(metrics));
    metrics.cbSize = sizeof(metrics);

    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
        base = metrics.lfMessageFont;
    } else {
        /* Never leave the window font-less: name the face directly rather
         * than letting every control fall back to the system font. */
        memset(&base, 0, sizeof(base));
        base.lfHeight  = -12;
        base.lfCharSet = DEFAULT_CHARSET;
        wcscpy_s(base.lfFaceName, USBS_ARRAY_LEN(base.lfFaceName), L"Segoe UI");
    }

    state->font_ui = CreateFontIndirectW(&base);

    /* lfHeight is negative (character height); scaling it up means making
     * it more negative. */
    {
        LOGFONTW banner = base;
        banner.lfHeight = (base.lfHeight < 0) ? (base.lfHeight * 3) / 2 : base.lfHeight;
        banner.lfWeight = FW_SEMIBOLD;
        state->font_banner = CreateFontIndirectW(&banner);
    }
    {
        LOGFONTW detail = base;
        detail.lfWeight = FW_NORMAL;
        state->font_detail = CreateFontIndirectW(&detail);
    }
}

static void destroy_fonts(gui_state_t *state)
{
    if (state->font_ui != NULL)     { DeleteObject(state->font_ui); }
    if (state->font_banner != NULL) { DeleteObject(state->font_banner); }
    if (state->font_detail != NULL) { DeleteObject(state->font_detail); }
    state->font_ui = state->font_banner = state->font_detail = NULL;
}

/* ------------------------------------------------------------------------ *
 * Results view: RichEdit runs.
 *
 * gui_report_view.c emits (style, UTF-8) runs; each one is converted to
 * UTF-16, the insertion point is formatted with the style's CHARFORMAT2W,
 * and the text is appended. Formatting an empty selection sets the format
 * for what is typed/inserted next, which is what makes per-run colouring
 * work without re-selecting ranges afterwards.
 * ------------------------------------------------------------------------ */

typedef struct rich_sink {
    HWND      control;
    usbs_bool rich;      /* false => plain EDIT fallback, text only */
    LONG      base_size; /* base font size in twips, for point_delta */

    /* The fallback path accumulates plain text instead, since an EDIT can
     * only be given its content in one shot. */
    wchar_t  *plain;
    size_t    plain_len;
    size_t    plain_cap;
} rich_sink_t;

static void rich_sink_append_plain(rich_sink_t *sink, const wchar_t *text)
{
    size_t n = wcslen(text);

    if (sink->plain_len + n + 1 > sink->plain_cap) {
        size_t   new_cap = (sink->plain_cap == 0) ? 8192 : sink->plain_cap;
        wchar_t *grown;
        while (new_cap < sink->plain_len + n + 1) {
            new_cap *= 2;
        }
        grown = (wchar_t *)realloc(sink->plain, new_cap * sizeof(wchar_t));
        if (grown == NULL) {
            return; /* best effort: show what fitted */
        }
        sink->plain     = grown;
        sink->plain_cap = new_cap;
    }
    memcpy(sink->plain + sink->plain_len, text, (n + 1) * sizeof(wchar_t));
    sink->plain_len += n;
}

static void rich_emit(void *ctx, gui_text_style_t style, const char *utf8)
{
    rich_sink_t *sink = (rich_sink_t *)ctx;
    int          needed;
    wchar_t      stack_buf[1024];
    wchar_t     *wide = stack_buf;

    if (utf8 == NULL || utf8[0] == '\0') {
        return;
    }
    needed = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (needed <= 0) {
        return;
    }
    if ((size_t)needed > USBS_ARRAY_LEN(stack_buf)) {
        wide = (wchar_t *)malloc((size_t)needed * sizeof(wchar_t));
        if (wide == NULL) {
            return;
        }
    }
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, needed) <= 0) {
        goto done;
    }

    if (!sink->rich) {
        rich_sink_append_plain(sink, wide);
        goto done;
    }

    {
        const gui_style_spec_t *spec = &k_styles[(style < GUI_STYLE_COUNT) ? style : GUI_STYLE_BODY];
        CHARFORMAT2W            cf;

        memset(&cf, 0, sizeof(cf));
        cf.cbSize      = sizeof(cf);
        cf.dwMask      = CFM_COLOR | CFM_BOLD | CFM_SIZE;
        cf.crTextColor = spec->color;
        cf.dwEffects   = spec->bold ? CFE_BOLD : 0;
        /* CHARFORMAT2W sizes are in twips (1/20 pt). */
        cf.yHeight     = sink->base_size + (LONG)spec->point_delta * 20;

        /* Collapse the selection to the very end, format the insertion
         * point, then insert. */
        SendMessageW(sink->control, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
        SendMessageW(sink->control, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
        SendMessageW(sink->control, EM_REPLACESEL, FALSE, (LPARAM)wide);
    }

done:
    if (wide != stack_buf) {
        free(wide);
    }
}

static void results_set_plain_message(gui_state_t *state, const wchar_t *message)
{
    SetWindowTextW(state->edit_results, message);
}

static void results_render(gui_state_t *state, const usbs_scan_result_t *result)
{
    rich_sink_t         sink;
    gui_report_totals_t totals;

    memset(&totals, 0, sizeof(totals));
    memset(&sink, 0, sizeof(sink));
    sink.control   = state->edit_results;
    sink.rich      = state->results_is_rich;
    sink.base_size = 9 * 20; /* 9pt, in twips */

    /* Suppress the per-insert repaint and the autoscroll that comes with
     * it; one repaint at the end instead of one per run. */
    SendMessageW(state->edit_results, WM_SETREDRAW, FALSE, 0);

    if (sink.rich) {
        SETTEXTEX st;
        st.flags    = ST_DEFAULT;
        st.codepage = 1200; /* UTF-16 */
        SendMessageW(state->edit_results, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)L"");
    }

    if (state->have_progress) {
        totals.files = state->last_progress.files_scanned;
        totals.bytes = state->last_progress.bytes_scanned;
    }

    gui_report_render_runs(result,
                           state->have_progress ? &totals : NULL,
                           rich_emit, &sink);

    if (!sink.rich) {
        results_set_plain_message(state,
            (sink.plain != NULL) ? sink.plain
                                 : L"(scan completed - see the saved JSON/CSV report)");
        free(sink.plain);
    }

    SendMessageW(state->edit_results, WM_SETREDRAW, TRUE, 0);

    if (sink.rich) {
        SendMessageW(state->edit_results, EM_EMPTYUNDOBUFFER, 0, 0);
    }

    InvalidateRect(state->edit_results, NULL, TRUE);
    UpdateWindow(state->edit_results);
}

/*
 * Puts the report back at line 1.
 *
 * This must be the LAST thing done to the results view, after the banner
 * has been shown and the layout recomputed - not at the end of
 * results_render(). Showing the verdict banner makes the results control
 * ~60px shorter, and RichEdit adjusts its own scroll position when it is
 * resized, which silently undoes an earlier scroll-to-top and leaves the
 * report opening two lines down with its title and verdict line clipped
 * off the top.
 *
 * Found by reading EM_GETFIRSTVISIBLELINE back from the real control
 * (it returned 2, not 0) rather than by eyeballing a screenshot - at a
 * glance a report scrolled by two lines just looks like a report.
 *
 * WM_VSCROLL/SB_TOP after EM_SCROLLCARET is deliberate belt and braces:
 * the two disagree in some RichEdit versions, and landing anywhere but
 * the first line is a visible defect.
 */
static void results_scroll_to_top(gui_state_t *state)
{
    SendMessageW(state->edit_results, EM_SETSEL, 0, 0);
    SendMessageW(state->edit_results, EM_SCROLLCARET, 0, 0);
    if (state->results_is_rich) {
        SendMessageW(state->edit_results, WM_VSCROLL, SB_TOP, 0);
    }
}

static void results_clear(gui_state_t *state)
{
    if (state->results_is_rich) {
        SETTEXTEX st;
        st.flags    = ST_DEFAULT;
        st.codepage = 1200;
        SendMessageW(state->edit_results, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)L"");
    } else {
        SetWindowTextW(state->edit_results, L"");
    }
}

/* ------------------------------------------------------------------------ *
 * Verdict banner. Owner-drawn rather than a coloured static: a static
 * control's background can be tinted through WM_CTLCOLORSTATIC, but the
 * warning glyph has to be drawn, and drawing it with GDI primitives avoids
 * depending on any particular font shipping any particular symbol.
 * ------------------------------------------------------------------------ */

static void banner_hide(gui_state_t *state)
{
    state->banner_visible = false;
    ShowWindow(state->banner, SW_HIDE);
}

static void banner_show(gui_state_t *state, const gui_report_summary_t *summary)
{
    char detail_utf8[256];

    state->banner_verdict = summary->verdict;
    utf8_to_wide(gui_verdict_headline(summary->verdict),
                 state->banner_headline, USBS_ARRAY_LEN(state->banner_headline));
    utf8_to_wide(gui_verdict_detail(summary, detail_utf8, sizeof(detail_utf8)),
                 state->banner_detail, USBS_ARRAY_LEN(state->banner_detail));

    state->banner_visible = true;
    ShowWindow(state->banner, SW_SHOW);
    InvalidateRect(state->banner, NULL, TRUE);
}

/* A filled disc with a bold "!" for anything that needs attention, a
 * checkmark polyline for a clean result. Both drawn, not typed, so no font
 * has to contain the glyph. */
static void banner_draw_glyph(HDC dc, const RECT *box, gui_verdict_t verdict, COLORREF ink)
{
    int   size   = (box->bottom - box->top);
    int   cx     = box->left + size / 2;
    int   cy     = box->top + size / 2;
    int   radius = size / 2;
    HPEN  pen;
    HPEN  old_pen;

    pen = CreatePen(PS_SOLID, (size / 8 > 0) ? size / 8 : 1, ink);
    old_pen = (HPEN)SelectObject(dc, pen);

    if (verdict == GUI_VERDICT_CLEAN) {
        POINT check[3];
        check[0].x = cx - radius * 55 / 100; check[0].y = cy;
        check[1].x = cx - radius * 15 / 100; check[1].y = cy + radius * 42 / 100;
        check[2].x = cx + radius * 60 / 100; check[2].y = cy - radius * 48 / 100;
        Polyline(dc, check, 3);
    } else {
        /* Exclamation mark: a stem and a dot, both drawn with the pen. */
        POINT stem[2];
        stem[0].x = cx; stem[0].y = cy - radius * 62 / 100;
        stem[1].x = cx; stem[1].y = cy + radius * 14 / 100;
        Polyline(dc, stem, 2);
        {
            POINT dot[2];
            dot[0].x = cx; dot[0].y = cy + radius * 50 / 100;
            dot[1].x = cx; dot[1].y = cy + radius * 52 / 100;
            Polyline(dc, dot, 2);
        }
        /* A ring around it, so it reads as a warning badge rather than a
         * stray punctuation mark. */
        {
            HBRUSH hollow = (HBRUSH)GetStockObject(NULL_BRUSH);
            HBRUSH old_brush = (HBRUSH)SelectObject(dc, hollow);
            Ellipse(dc, cx - radius, cy - radius, cx + radius, cy + radius);
            SelectObject(dc, old_brush);
        }
    }

    SelectObject(dc, old_pen);
    DeleteObject(pen);
}

static void banner_draw(gui_state_t *state, const DRAWITEMSTRUCT *dis)
{
    gui_banner_spec_t spec = banner_colors(state->banner_verdict);
    HBRUSH            back = CreateSolidBrush(spec.background);
    RECT              rect = dis->rcItem;
    RECT              glyph_box;
    RECT              text_box;
    int               glyph_size;
    int               old_mode;
    COLORREF          old_color;
    HFONT             old_font;

    FillRect(dis->hDC, &rect, back);
    DeleteObject(back);

    glyph_size = (rect.bottom - rect.top) - 20;
    if (glyph_size < 12) {
        glyph_size = 12;
    }
    glyph_box.left   = rect.left + 14;
    glyph_box.top    = rect.top + ((rect.bottom - rect.top) - glyph_size) / 2;
    glyph_box.right  = glyph_box.left + glyph_size;
    glyph_box.bottom = glyph_box.top + glyph_size;
    banner_draw_glyph(dis->hDC, &glyph_box, state->banner_verdict, spec.foreground);

    old_mode  = SetBkMode(dis->hDC, TRANSPARENT);
    old_color = SetTextColor(dis->hDC, spec.foreground);

    text_box        = rect;
    text_box.left   = glyph_box.right + 14;
    text_box.right -= 12;
    text_box.top   += 7;

    old_font = (HFONT)SelectObject(dis->hDC, state->font_banner);
    DrawTextW(dis->hDC, state->banner_headline, -1, &text_box,
              DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);

    SelectObject(dis->hDC, state->font_detail);
    text_box.top += 22;
    DrawTextW(dis->hDC, state->banner_detail, -1, &text_box,
              DT_LEFT | DT_TOP | DT_END_ELLIPSIS | DT_NOPREFIX);

    SelectObject(dis->hDC, old_font);
    SetTextColor(dis->hDC, old_color);
    SetBkMode(dis->hDC, old_mode);
}

/* ------------------------------------------------------------------------ *
 * Progress bar.
 *
 * PBM_SETPOS is ignored while PBS_MARQUEE is set, so switching between
 * determinate and indeterminate means editing the window style itself, not
 * just sending a different message. The bar is hidden entirely when no scan
 * is running.
 * ------------------------------------------------------------------------ */

static void progress_set_marquee(gui_state_t *state, usbs_bool on)
{
    LONG_PTR style = GetWindowLongPtrW(state->progress, GWL_STYLE);

    if (on) {
        SetWindowLongPtrW(state->progress, GWL_STYLE, style | PBS_MARQUEE);
        SendMessageW(state->progress, PBM_SETMARQUEE, TRUE, 30);
    } else {
        SendMessageW(state->progress, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(state->progress, GWL_STYLE, style & ~(LONG_PTR)PBS_MARQUEE);
    }
}

static void progress_begin(gui_state_t *state, const usbs_device_t *device)
{
    usbs_u64 used = 0;

    if (device->capacity_bytes > 0 && device->free_bytes <= device->capacity_bytes) {
        used = device->capacity_bytes - device->free_bytes;
    }

    state->progress_total_bytes = used;
    state->progress_determinate = (used > 0);
    state->progress_last_pos    = 0;

    SendMessageW(state->progress, PBM_SETRANGE32, 0, GUI_PROGRESS_RANGE);
    SendMessageW(state->progress, PBM_SETPOS, 0, 0);
    progress_set_marquee(state, !state->progress_determinate);
    if (state->progress_determinate) {
        /* Re-assert zero after the style change so the bar starts visibly
         * empty rather than wherever it happened to be. */
        SendMessageW(state->progress, PBM_SETPOS, 0, 0);
    }
    ShowWindow(state->progress, SW_SHOW);
}

static void progress_update(gui_state_t *state, const usbs_scan_progress_t *progress)
{
    int pos;

    if (!state->progress_determinate || state->progress_total_bytes == 0) {
        return; /* marquee animates itself */
    }

    /* The denominator is the filesystem's own "bytes in use"; the numerator
     * is the sum of file sizes actually walked. They are close but not
     * identical (metadata, slack, files the walk could not open), so the
     * ratio is clamped and forced monotonic - a bar that stalls just short
     * of the end is fine, a bar that jumps backwards looks broken. */
    if (progress->bytes_scanned >= state->progress_total_bytes) {
        pos = GUI_PROGRESS_RANGE;
    } else {
        pos = (int)((progress->bytes_scanned * (usbs_u64)GUI_PROGRESS_RANGE) /
                    state->progress_total_bytes);
    }
    if (pos < state->progress_last_pos) {
        pos = state->progress_last_pos;
    }
    state->progress_last_pos = pos;
    SendMessageW(state->progress, PBM_SETPOS, (WPARAM)pos, 0);
}

static void progress_end(gui_state_t *state)
{
    if (state->progress_determinate) {
        /* Land on exactly full before disappearing, so the last thing the
         * bar did was finish rather than stop somewhere arbitrary. */
        SendMessageW(state->progress, PBM_SETPOS, (WPARAM)GUI_PROGRESS_RANGE, 0);
    }
    progress_set_marquee(state, false);
    ShowWindow(state->progress, SW_HIDE);
    SendMessageW(state->progress, PBM_SETPOS, 0, 0);
    state->progress_determinate = false;
    state->progress_last_pos    = 0;
}

/* ------------------------------------------------------------------------ *
 * Auto-scan "already handled" set (Phase 9). Tracks device identities that
 * have been auto-scanned since they were last seen absent, so: (a) several
 * WM_DEVICECHANGE messages for the same physical insert (one device can
 * expose more than one volume interface) do not trigger more than one
 * auto-scan, and (b) unplugging and re-plugging the same drive later DOES
 * auto-scan it again, once it has been pruned from the set on removal.
 * ------------------------------------------------------------------------ */

static usbs_bool auto_scan_set_contains(const gui_state_t *state, const char *identity)
{
    size_t i;
    for (i = 0; i < state->auto_scanned_count; ++i) {
        if (strcmp(state->auto_scanned_identities[i], identity) == 0) {
            return true;
        }
    }
    return false;
}

static void auto_scan_set_add(gui_state_t *state, const char *identity)
{
    if (auto_scan_set_contains(state, identity)) {
        return;
    }
    if (state->auto_scanned_count < GUI_AUTO_SCAN_TRACK_MAX) {
        snprintf(state->auto_scanned_identities[state->auto_scanned_count],
                USBS_IDENTITY_MAX, "%s", identity);
        ++state->auto_scanned_count;
    }
    /* Tracking capacity exceeded (an unlikely number of distinct devices
     * inserted in one session): simply stop guarding new ones rather than
     * growing a dynamic list for this case. */
}

/* Drops any tracked identity no longer present in state->devices, so a
 * later re-insertion of the same physical device is treated as new. */
static void auto_scan_set_prune_absent(gui_state_t *state)
{
    size_t write = 0;
    size_t read;

    for (read = 0; read < state->auto_scanned_count; ++read) {
        usbs_bool still_present = false;
        size_t    i;

        for (i = 0; i < state->devices.count; ++i) {
            char identity[USBS_IDENTITY_MAX];
            if (usbs_ok(usbs_device_identity(&state->devices.items[i], identity, sizeof(identity))) &&
                strcmp(identity, state->auto_scanned_identities[read]) == 0) {
                still_present = true;
                break;
            }
        }
        if (still_present) {
            if (write != read) {
                snprintf(state->auto_scanned_identities[write], USBS_IDENTITY_MAX,
                        "%s", state->auto_scanned_identities[read]);
            }
            ++write;
        }
    }
    state->auto_scanned_count = write;
}

/* ------------------------------------------------------------------------ *
 * Device enumeration
 * ------------------------------------------------------------------------ */

static void populate_devices(gui_state_t *state)
{
    usbs_device_source_t source;
    usbs_device_list_t   raw;
    usbs_status_t        status;
    size_t                i;
    char                  status_utf8[64];
    char                  previous_identity[USBS_IDENTITY_MAX];
    usbs_bool             have_previous = false;
    int                   restore_index = -1;

    /* Capture the current selection by identity (not index) before
     * rebuilding, so a hot-plug-triggered refresh does not yank the
     * dropdown away from whatever the user had manually selected. */
    {
        int sel = (int)SendMessageW(state->combo_devices, CB_GETCURSEL, 0, 0);
        if (sel != CB_ERR && (size_t)sel < state->devices.count) {
            have_previous = usbs_ok(usbs_device_identity(&state->devices.items[sel],
                                                          previous_identity, sizeof(previous_identity)));
        }
    }

    SendMessageW(state->combo_devices, CB_RESETCONTENT, 0, 0);
    usbs_device_list_free(&state->devices);
    usbs_device_list_init(&state->devices);

    source = usbs_platform_device_source_ex(enum_mode(state));
    status = usbs_device_enumerate(&source, &raw);
    if (!usbs_ok(status)) {
        set_status_utf8(state, "Device enumeration failed.");
        return;
    }

    for (i = 0; i < raw.count; ++i) {
        const usbs_device_t *device = &raw.items[i];
        char    identity[USBS_IDENTITY_MAX];
        char    label_utf8[256];
        wchar_t label_wide[320];

        if (!usbs_device_is_scannable(device, enum_mode(state))) {
            continue;
        }
        identity[0] = '\0';
        usbs_device_identity(device, identity, sizeof(identity));
        if (device->bus_type == USBS_BUS_USB) {
            /* Unchanged from Phase 9: a USB identity is short and is what
             * tells two identical-looking sticks apart. */
            snprintf(label_utf8, sizeof(label_utf8), "%s%s%s  [%s]",
                    device->mount_point_count > 0 ? device->mount_points[0] : "(no letter)",
                    device->label[0] != '\0' ? "  " : "",
                    device->label,
                    identity);
        } else {
            /* A non-USB identity is "volume:\\?\Volume{GUID}\" or a UNC path,
             * which is long and tells a person nothing. Connection and size
             * are how anyone tells C: from D:. The identity is still in the
             * report once a scan runs. */
            char size[32];
            format_bytes(device->capacity_bytes, size, sizeof(size));
            snprintf(label_utf8, sizeof(label_utf8), "%s%s%s  [%s, %s]",
                    device->mount_points[0],
                    device->label[0] != '\0' ? "  " : "",
                    device->label,
                    usbs_bus_type_string(device->bus_type),
                    size);
        }
        if (utf8_to_wide(label_utf8, label_wide, USBS_ARRAY_LEN(label_wide))) {
            SendMessageW(state->combo_devices, CB_ADDSTRING, 0, (LPARAM)label_wide);
        }
        if (have_previous && restore_index < 0 && strcmp(identity, previous_identity) == 0) {
            restore_index = (int)state->devices.count;
        }
        usbs_device_list_push(&state->devices, device);
    }
    usbs_device_list_free(&raw);

    auto_scan_set_prune_absent(state);

    if (state->devices.count > 0) {
        SendMessageW(state->combo_devices, CB_SETCURSEL,
                    (WPARAM)((restore_index >= 0) ? restore_index : 0), 0);
        snprintf(status_utf8, sizeof(status_utf8),
                 state->show_all_drives ? "%zu drive(s) found." : "%zu USB device(s) found.",
                 state->devices.count);
    } else if (state->show_all_drives) {
        snprintf(status_utf8, sizeof(status_utf8), "No readable drive found.");
    } else {
        snprintf(status_utf8, sizeof(status_utf8), "No USB device found. Insert one and click Refresh.");
    }
    set_status_utf8(state, status_utf8);
}

/* ------------------------------------------------------------------------ *
 * Control creation and layout
 * ------------------------------------------------------------------------ */

static HWND create_results_control(HWND hwnd, gui_state_t *state, HINSTANCE instance)
{
    HWND control;

    /* RichEdit 4.1. The class is registered as a side effect of loading
     * Msftedit.dll, so this has to happen before CreateWindowExW. The
     * module is intentionally never freed - see s_richedit_module. */
    if (s_richedit_module == NULL) {
        s_richedit_module = LoadLibraryW(L"Msftedit.dll");
    }

    if (s_richedit_module != NULL) {
        control = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL,
            0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_EDIT_RESULTS, instance, NULL);
        if (control != NULL) {
            state->results_is_rich = true;

            /* A RichEdit defaults to a ~32 KB text limit, silently
             * truncating anything longer. A report from a device with many
             * findings can exceed that. */
            SendMessageW(control, EM_EXLIMITTEXT, 0, (LPARAM)(1 << 22));
            /* ES_READONLY would otherwise pick a background that does not
             * match the paper colour the runs are designed against. */
            SendMessageW(control, EM_SETBKGNDCOLOR, 0, (LPARAM)GUI_COLOR_PAPER);
            SendMessageW(control, EM_SETEVENTMASK, 0, 0);
            return control;
        }
    }

    /* Msftedit.dll missing or the control failed to create: a plain EDIT
     * still shows the whole report, just without colour. An uncoloured
     * report is a degraded experience; a blank results pane would be a
     * broken one. */
    state->results_is_rich = false;
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL,
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_EDIT_RESULTS, instance, NULL);
}

static void create_controls(HWND hwnd, gui_state_t *state, HINSTANCE instance)
{
    create_fonts(state);

    state->label_device = CreateWindowExW(0, L"STATIC", L"Device", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_STATIC_DEVICE, instance, NULL);

    state->combo_devices = CreateWindowExW(0, L"COMBOBOX", NULL,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
        0, 0, 10, 200, hwnd, (HMENU)(UINT_PTR)IDC_COMBO_DEVICES, instance, NULL);

    state->btn_refresh = CreateWindowExW(0, L"BUTTON", L"Refresh",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_BUTTON_REFRESH, instance, NULL);

    state->btn_scan = CreateWindowExW(0, L"BUTTON", L"Scan",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_BUTTON_SCAN, instance, NULL);

    state->btn_cancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_BUTTON_CANCEL, instance, NULL);

    state->btn_opendir = CreateWindowExW(0, L"BUTTON", L"Open Reports Folder",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_BUTTON_OPENDIR, instance, NULL);

    state->chk_autoscan = CreateWindowExW(0, L"BUTTON", L"Auto-scan new devices",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_CHECK_AUTOSCAN, instance, NULL);
    /* Off by default - "no silent action" (ARCHITECTURE.md section 1):
     * scanning is read-only and safe, but auto-triggering it without a
     * click is still a behavior change the user should opt into. */
    SendMessageW(state->chk_autoscan, BM_SETCHECK, BST_UNCHECKED, 0);

    /* "&&" is a literal ampersand; a single "&" would be taken as a
     * mnemonic marker and underline the next letter instead. */
    state->chk_alldrives = CreateWindowExW(0, L"BUTTON", L"Show all drives (Internal && External)",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_CHECK_ALLDRIVES, instance, NULL);
    /* Off by default (Phase 17): USB-only is the safe, fast default this
     * tool has always had. Widening to a 1 TB system drive is a deliberate
     * choice, never a starting state. */
    SendMessageW(state->chk_alldrives, BM_SETCHECK, BST_UNCHECKED, 0);

    /* Created hidden: the bar is only on screen while a scan is running. */
    state->progress = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
        WS_CHILD | PBS_SMOOTH,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_PROGRESS, instance, NULL);
    SendMessageW(state->progress, PBM_SETRANGE32, 0, GUI_PROGRESS_RANGE);

    /* Also hidden until there is a verdict to show. */
    state->banner = CreateWindowExW(0, L"STATIC", NULL,
        WS_CHILD | SS_OWNERDRAW,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_STATIC_BANNER, instance, NULL);

    state->label_status = CreateWindowExW(0, L"STATIC", L"Ready.",
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_ENDELLIPSIS,
        0, 0, 10, 10, hwnd, (HMENU)(UINT_PTR)IDC_STATIC_STATUS, instance, NULL);

    state->edit_results = create_results_control(hwnd, state, instance);

    {
        HWND controls[] = { state->label_device, state->combo_devices, state->btn_refresh,
                            state->btn_scan, state->btn_cancel, state->btn_opendir,
                            state->chk_autoscan, state->chk_alldrives, state->label_status,
                            state->edit_results };
        size_t i;
        for (i = 0; i < USBS_ARRAY_LEN(controls); ++i) {
            SendMessageW(controls[i], WM_SETFONT, (WPARAM)state->font_ui, TRUE);
        }
    }
}

/*
 * One place that positions everything, called from WM_SIZE. The window is
 * resizable (Phase 11): a fixed 580x500 frame made a long report needlessly
 * hard to read, and a single layout function is cheaper than the workaround
 * of making the window taller and hoping.
 */
static void layout_controls(gui_state_t *state, int width, int height)
{
    const int m     = GUI_MARGIN;
    const int right = width - GUI_MARGIN;
    int       y     = GUI_MARGIN;
    int       label_w, refresh_w, combo_w;
    int       results_top, results_bottom;

    if (state->combo_devices == NULL) {
        return; /* WM_SIZE can arrive before the controls exist */
    }

    /* Row 1: device label, dropdown, Refresh. */
    label_w   = 48;
    refresh_w = 88;
    combo_w   = right - m - label_w - GUI_GAP - refresh_w - GUI_GAP;
    if (combo_w < 120) {
        combo_w = 120;
    }
    MoveWindow(state->label_device, m, y, label_w, GUI_ROW_H, TRUE);
    /* A dropdown's height argument sizes the *dropped* list, not the
     * closed control, so it is given a generous value here. */
    MoveWindow(state->combo_devices, m + label_w + GUI_GAP, y, combo_w, 240, TRUE);
    MoveWindow(state->btn_refresh, m + label_w + GUI_GAP + combo_w + GUI_GAP, y,
               refresh_w, GUI_ROW_H, TRUE);
    y += GUI_ROW_H + 4;

    /* Row 2 (Phase 17): the two opt-in checkboxes, under the dropdown they
     * both affect. "Show all drives" is aligned with the dropdown's left
     * edge because it changes what the dropdown lists. Auto-scan moved here
     * from the button row, which at the minimum window width had no room
     * left for a second checkbox. */
    MoveWindow(state->chk_alldrives, m + label_w + GUI_GAP, y, 260, 20, TRUE);
    MoveWindow(state->chk_autoscan, right - 170, y, 170, 20, TRUE);
    y += 20 + GUI_GAP + 2;

    /* Row 3: actions. */
    {
        const int btn_h = 30;
        MoveWindow(state->btn_scan,    m,            y, 104, btn_h, TRUE);
        MoveWindow(state->btn_cancel,  m + 112,      y, 104, btn_h, TRUE);
        MoveWindow(state->btn_opendir, m + 224,      y, 168, btn_h, TRUE);
        y += btn_h + GUI_GAP + 2;
    }

    /* Row 4: the progress bar's slot. It is hidden most of the time, but
     * the slot is reserved either way so nothing below it jumps when a
     * scan starts. */
    MoveWindow(state->progress, m, y, right - m, 16, TRUE);
    y += 16 + GUI_GAP;

    /* Row 5: the verdict banner, when there is one. */
    MoveWindow(state->banner, m, y, right - m, GUI_BANNER_H, TRUE);
    if (state->banner_visible) {
        y += GUI_BANNER_H + GUI_GAP;
    }

    results_top    = y;
    results_bottom = height - GUI_MARGIN - GUI_ROW_H - GUI_GAP;
    if (results_bottom < results_top + 60) {
        results_bottom = results_top + 60;
    }
    MoveWindow(state->edit_results, m, results_top, right - m, results_bottom - results_top, TRUE);
    MoveWindow(state->label_status, m, results_bottom + GUI_GAP, right - m, GUI_ROW_H, TRUE);
}

static void relayout(gui_state_t *state)
{
    RECT client;
    if (GetClientRect(state->hwnd, &client)) {
        layout_controls(state, client.right - client.left, client.bottom - client.top);
    }
}

/* ------------------------------------------------------------------------ *
 * Report saving - the same usbs_report_build_json/csv + usbs_store_write_*
 * calls cmd_scan.c already makes, just on this window's UI thread instead
 * of a console command's single thread of execution.
 * ------------------------------------------------------------------------ */

static void save_reports(gui_state_t *state, const usbs_scan_result_t *result)
{
    char      identity[USBS_IDENTITY_MAX];
    usbs_bool have_identity;
    char     *json_text = NULL;
    size_t    json_len  = 0;
    char     *csv_text  = NULL;
    size_t    csv_len   = 0;
    char      saved_path[USBS_STORE_PATH_MAX];
    usbs_bool saved_any = false;

    if (!state->have_store) {
        return;
    }
    have_identity = usbs_ok(usbs_device_identity(&result->device, identity, sizeof(identity)));
    if (!have_identity) {
        return;
    }

    if (usbs_ok(usbs_report_build_json(result, &json_text, &json_len))) {
        if (usbs_ok(usbs_store_write_report(&state->store, identity, result->scan_id,
                                            result->started_at, json_text, json_len,
                                            saved_path, sizeof(saved_path)))) {
            snprintf(state->last_report_dir, sizeof(state->last_report_dir), "%s", saved_path);
            saved_any = true;
        }
        free(json_text);
    }

    if (usbs_ok(usbs_report_build_csv(result, &csv_text, &csv_len))) {
        usbs_store_write_report_csv(&state->store, identity, result->scan_id,
                                    result->started_at, csv_text, csv_len,
                                    saved_path, sizeof(saved_path));
        free(csv_text);
    }

    if (saved_any) {
        char *last_sep = strrchr(state->last_report_dir, '\\');
        if (last_sep != NULL) {
            *last_sep = '\0';
        }
        state->have_last_report_dir = true;
        EnableWindow(state->btn_opendir, TRUE);
    }
}

/* ------------------------------------------------------------------------ *
 * UI-thread handlers for the worker's messages
 * ------------------------------------------------------------------------ */

static void handle_scan_done(gui_state_t *state, usbs_status_t status, usbs_scan_result_t *result)
{
    gui_report_summary_t summary;
    char                 status_line[160];

    if (state->worker_thread != NULL) {
        /* The worker has already returned by the time this message arrives
         * (it posts WM_APP_SCAN_DONE as its last action) - this just
         * reclaims the thread handle. */
        WaitForSingleObject(state->worker_thread, INFINITE);
        CloseHandle(state->worker_thread);
        state->worker_thread = NULL;

        /* Safe to read state->final_progress only now: the join above
         * orders the worker's last write before this read. Replaces
         * whatever the throttled live updates happened to leave behind,
         * which is not the same number and must not be reported as the
         * total. */
        if (state->have_final_progress) {
            state->last_progress = state->final_progress;
            state->have_progress = true;
        }
    }
    state->scanning = false;
    EnableWindow(state->btn_scan, TRUE);
    EnableWindow(state->btn_refresh, TRUE);
    EnableWindow(state->combo_devices, TRUE);
    EnableWindow(state->chk_alldrives, TRUE);
    EnableWindow(state->btn_cancel, FALSE);
    progress_end(state);

    if (!usbs_ok(status) || result == NULL) {
        banner_hide(state);
        relayout(state);
        set_status_utf8(state, "Scan could not be started.");
        return;
    }

    gui_report_summarize(result, &summary);
    results_render(state, result);
    banner_show(state, &summary);
    relayout(state);
    /* After relayout, never before - see results_scroll_to_top(). */
    results_scroll_to_top(state);

    save_reports(state, result);

    {
        int written = snprintf(status_line, sizeof(status_line),
                               "%s  -  %zu finding(s) across %zu check(s)",
                               summary.completed ? "Scan complete" : "Scan stopped early",
                               summary.finding_count,
                               summary.checks_run + summary.checks_skipped + summary.checks_failed);
        if (written > 0 && (size_t)written < sizeof(status_line)) {
            if (summary.paths_skipped > 0) {
                snprintf(status_line + written, sizeof(status_line) - (size_t)written,
                         ", %llu protected location(s) skipped.",
                         (unsigned long long)summary.paths_skipped);
            } else {
                snprintf(status_line + written, sizeof(status_line) - (size_t)written, ".");
            }
        }
    }
    set_status_utf8(state, status_line);

    usbs_scan_result_free(result);
    free(result);
}

static void handle_progress(gui_state_t *state, const usbs_scan_progress_t *progress)
{
    char      msg[200];
    char      bytes[32];
    char      elapsed[32];
    char      skipped[48];
    ULONGLONG seconds = (GetTickCount64() - state->scan_started_tick) / 1000ULL;

    state->last_progress = *progress;
    state->have_progress = true;

    progress_update(state, progress);

    /* Bytes in human units: the raw count was accurate but unreadable at a
     * glance, which is the whole point of a live status line. */
    format_bytes(progress->bytes_scanned, bytes, sizeof(bytes));

    /* Phase 17: a system drive takes minutes, not the sub-second of a USB
     * stick. Elapsed time is what shows a long scan is alive and moving,
     * even while the byte-based percentage stalls in a directory of many
     * small files. */
    if (seconds >= 3600ULL) {
        snprintf(elapsed, sizeof(elapsed), "%lluh %02llum %02llus",
                 seconds / 3600ULL, (seconds / 60ULL) % 60ULL, seconds % 60ULL);
    } else {
        snprintf(elapsed, sizeof(elapsed), "%llum %02llus", seconds / 60ULL, seconds % 60ULL);
    }

    skipped[0] = '\0';
    if (progress->paths_skipped > 0) {
        snprintf(skipped, sizeof(skipped), ", %llu skipped",
                 (unsigned long long)progress->paths_skipped);
    }

    if (state->progress_determinate) {
        snprintf(msg, sizeof(msg), "Scanning...  %llu file(s), %s%s  (%d%%)  -  %s",
                 (unsigned long long)progress->files_scanned, bytes, skipped,
                 state->progress_last_pos / (GUI_PROGRESS_RANGE / 100), elapsed);
    } else {
        snprintf(msg, sizeof(msg), "Scanning...  %llu file(s), %s%s  -  %s",
                 (unsigned long long)progress->files_scanned, bytes, skipped, elapsed);
    }
    set_status_utf8(state, msg);
}

/* ------------------------------------------------------------------------ *
 * Worker-thread callbacks - the only code in this file that runs off the
 * UI thread. They touch nothing but PostMessage(); everything else happens
 * back on the UI thread in the handlers above.
 * ------------------------------------------------------------------------ */

static void gui_on_progress(void *ctx, const usbs_scan_progress_t *progress)
{
    gui_state_t          *state = (gui_state_t *)ctx;
    ULONGLONG             now   = GetTickCount64();
    usbs_scan_progress_t *copy;

    /* Recorded before the throttle, never after: the throttle may drop a
     * UI update, but it must never drop the record of what was scanned. */
    state->final_progress      = *progress;
    state->have_final_progress = true;

    if (now - state->last_progress_tick < 100ULL) {
        return; /* throttle: at most ~10 UI updates/sec, so a drive with a
                  * huge number of files cannot flood the message queue */
    }
    state->last_progress_tick = now;

    copy = (usbs_scan_progress_t *)malloc(sizeof(*copy));
    if (copy == NULL) {
        return; /* best-effort UI update; dropping one is harmless */
    }
    *copy = *progress;
    if (!PostMessageW(state->hwnd, WM_APP_SCAN_PROGRESS, 0, (LPARAM)copy)) {
        free(copy);
    }
}

static void gui_on_done(void *ctx, usbs_status_t status, usbs_scan_result_t *result)
{
    HWND                 hwnd    = (HWND)ctx;
    gui_done_payload_t  *payload = (gui_done_payload_t *)malloc(sizeof(*payload));

    if (payload == NULL) {
        if (result != NULL) {
            usbs_scan_result_free(result);
            free(result);
        }
        return;
    }
    payload->status = status;
    payload->result = result;
    if (!PostMessageW(hwnd, WM_APP_SCAN_DONE, 0, (LPARAM)payload)) {
        if (result != NULL) {
            usbs_scan_result_free(result);
            free(result);
        }
        free(payload);
    }
}

static unsigned __stdcall worker_thread_proc(void *param)
{
    worker_launch_t *launch = (worker_launch_t *)param;
    gui_worker_run(&launch->args);
    free(launch);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Button handlers
 * ------------------------------------------------------------------------ */

/*
 * Shared by the manual Scan button and Phase 9's auto-scan: the actual
 * "launch a worker for this device" logic, independent of how the device
 * was chosen (the combo box selection, or a just-arrived device that was
 * never selected at all).
 */
static void start_scan_for_device(gui_state_t *state, const usbs_device_t *device)
{
    worker_launch_t  *launch;
    usbs_status_t     store_status;

    if (state->scanning) {
        return;
    }

    if (!state->have_store) {
        store_status = usbs_store_open(&state->store);
        if (!usbs_ok(store_status)) {
            set_status_utf8(state, "Could not open the report store.");
            return;
        }
        state->have_store = true;
    }

    launch = (worker_launch_t *)malloc(sizeof(*launch));
    if (launch == NULL) {
        set_status_utf8(state, "Out of memory.");
        return;
    }
    memset(launch, 0, sizeof(*launch));
    launch->args.device       = *device;
    launch->args.store        = &state->store;
    gui_cancel_flag_init(&state->cancel_flag);
    launch->args.cancel_flag  = &state->cancel_flag;
    launch->args.on_progress  = gui_on_progress;
    launch->args.progress_ctx = (void *)state;
    launch->args.on_done      = gui_on_done;
    launch->args.done_ctx     = (void *)state->hwnd;

    state->last_progress_tick  = 0;
    state->have_final_progress = false;
    memset(&state->final_progress, 0, sizeof(state->final_progress));

    state->worker_thread = (HANDLE)_beginthreadex(NULL, 0, worker_thread_proc, launch, 0, NULL);
    if (state->worker_thread == NULL) {
        free(launch);
        set_status_utf8(state, "Could not start the scan worker thread.");
        return;
    }

    state->scanning          = true;
    state->have_progress     = false;
    state->scan_started_tick = GetTickCount64();
    memset(&state->last_progress, 0, sizeof(state->last_progress));

    EnableWindow(state->btn_scan, FALSE);
    EnableWindow(state->btn_refresh, FALSE);
    EnableWindow(state->combo_devices, FALSE);
    /* Toggling it re-enumerates and rebuilds state->devices, which must
     * not change under a running scan any more than Refresh may. */
    EnableWindow(state->chk_alldrives, FALSE);
    EnableWindow(state->btn_cancel, TRUE);

    /* The previous scan's verdict is no longer true of the scan now
     * running, so it comes down before this one starts rather than
     * lingering over a fresh, still-unknown result. */
    banner_hide(state);
    results_clear(state);
    relayout(state);

    progress_begin(state, device);
    set_status_utf8(state, "Scanning...");
}

static void on_scan_clicked(gui_state_t *state)
{
    int sel;

    if (state->scanning) {
        return;
    }

    sel = (int)SendMessageW(state->combo_devices, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR || (size_t)sel >= state->devices.count) {
        set_status_utf8(state, "Select a device first.");
        return;
    }

    start_scan_for_device(state, &state->devices.items[sel]);
}

static void on_cancel_clicked(gui_state_t *state)
{
    if (!state->scanning) {
        return;
    }
    gui_cancel_flag_set(&state->cancel_flag);
    EnableWindow(state->btn_cancel, FALSE);
    set_status_utf8(state, "Cancelling...");
}

static void on_open_folder_clicked(gui_state_t *state)
{
    wchar_t wide_path[USBS_STORE_PATH_MAX];

    if (!state->have_last_report_dir) {
        set_status_utf8(state, "No report saved yet.");
        return;
    }
    if (!utf8_to_wide(state->last_report_dir, wide_path, USBS_ARRAY_LEN(wide_path))) {
        return;
    }
    ShellExecuteW(state->hwnd, L"open", wide_path, NULL, NULL, SW_SHOWNORMAL);
}

static void on_autoscan_toggled(gui_state_t *state)
{
    state->auto_scan_enabled =
        (SendMessageW(state->chk_autoscan, BM_GETCHECK, 0, 0) == BST_CHECKED);
}

/* Phase 17: re-enumerate in the newly chosen mode. populate_devices()
 * restores the previous selection by identity, so a USB stick selected
 * before the toggle stays selected after it, in both directions. */
static void on_alldrives_toggled(gui_state_t *state)
{
    if (state->scanning) {
        return; /* the checkbox is disabled while scanning; belt and braces */
    }
    state->show_all_drives =
        (SendMessageW(state->chk_alldrives, BM_GETCHECK, 0, 0) == BST_CHECKED);
    populate_devices(state);
}

/*
 * Phase 9: WM_DEVICECHANGE handler. Refreshes the device list (preserving
 * the user's selection, populate_devices() above) and, if auto-scan is
 * on, starts a scan for at most one newly-arrived, not-yet-auto-scanned
 * device - gui_should_auto_scan() (gui_worker.h) makes the actual
 * decision, kept pure and testable; this function only supplies the three
 * booleans it needs and does the bookkeeping around the decision.
 */
static void handle_device_change(gui_state_t *state)
{
    if (state->scanning) {
        /* Do not disturb the dropdown or start a second scan while one is
         * already running; the user can Refresh manually once it
         * finishes, and the next real device-change event will catch up. */
        return;
    }

    populate_devices(state);

    if (!state->auto_scan_enabled) {
        return;
    }

    {
        size_t i;
        for (i = 0; i < state->devices.count; ++i) {
            char identity[USBS_IDENTITY_MAX];
            usbs_bool already;

            if (!usbs_ok(usbs_device_identity(&state->devices.items[i], identity, sizeof(identity)))) {
                continue;
            }
            already = auto_scan_set_contains(state, identity);
            /* Phase 17: gui_should_auto_scan() also refuses anything that
             * is not a USB device. With "Show all drives" on,
             * state->devices holds C:, which has never been auto-scanned
             * either, so the first hot-plug event would otherwise start an
             * unrequested, hours-long scan of the system drive. */
            if (gui_should_auto_scan(&state->devices.items[i], state->auto_scan_enabled,
                                     state->scanning, already)) {
                auto_scan_set_add(state, identity);
                start_scan_for_device(state, &state->devices.items[i]);
                break; /* only one scan can run at a time */
            }
        }
    }
}

/* ------------------------------------------------------------------------ *
 * Window lifecycle
 * ------------------------------------------------------------------------ */

static LRESULT on_create(HWND hwnd, LPARAM lparam)
{
    CREATESTRUCTW *cs    = (CREATESTRUCTW *)lparam;
    gui_state_t    *state = (gui_state_t *)calloc(1, sizeof(*state));

    if (state == NULL) {
        return -1;
    }
    state->hwnd = hwnd;
    usbs_device_list_init(&state->devices);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);

    create_controls(hwnd, state, cs->hInstance);
    relayout(state);
    populate_devices(state);

    if (usbs_ok(usbs_store_open(&state->store))) {
        state->have_store = true;
    } else {
        set_status_utf8(state, "Warning: could not open the report store; scans will not be saved.");
    }
    return 0;
}

static void on_destroy(HWND hwnd, gui_state_t *state)
{
    if (state != NULL) {
        if (state->dev_notify != NULL) {
            UnregisterDeviceNotification(state->dev_notify);
        }
        if (state->worker_thread != NULL) {
            WaitForSingleObject(state->worker_thread, INFINITE);
            CloseHandle(state->worker_thread);
        }
        destroy_fonts(state);
        usbs_device_list_free(&state->devices);
        free(state);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
    }
    PostQuitMessage(0);
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    gui_state_t *state = (gui_state_t *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_CREATE:
        return on_create(hwnd, lparam);

    case WM_SIZE:
        if (state != NULL) {
            layout_controls(state, LOWORD(lparam), HIWORD(lparam));
        }
        return 0;

    case WM_GETMINMAXINFO: {
        /* Below this the layout stops being readable rather than merely
         * cramped, so the frame refuses to go smaller. */
        MINMAXINFO *mmi = (MINMAXINFO *)lparam;
        mmi->ptMinTrackSize.x = GUI_MIN_WIDTH;
        mmi->ptMinTrackSize.y = GUI_MIN_HEIGHT;
        return 0;
    }

    case WM_DRAWITEM:
        if (state != NULL && wparam == IDC_STATIC_BANNER) {
            banner_draw(state, (const DRAWITEMSTRUCT *)lparam);
            return TRUE;
        }
        break;

    case WM_CTLCOLORSTATIC:
        /* The status line sits on the window background, not on a white
         * control background. */
        if (state != NULL && (HWND)lparam == state->label_status) {
            SetBkMode((HDC)wparam, TRANSPARENT);
            SetTextColor((HDC)wparam, GUI_COLOR_LABEL);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        break;

    case WM_COMMAND:
        if (state != NULL) {
            switch (LOWORD(wparam)) {
            case IDC_BUTTON_SCAN:    on_scan_clicked(state);    break;
            case IDC_BUTTON_CANCEL:  on_cancel_clicked(state);  break;
            case IDC_BUTTON_REFRESH: if (!state->scanning) { populate_devices(state); } break;
            case IDC_BUTTON_OPENDIR: on_open_folder_clicked(state); break;
            case IDC_CHECK_AUTOSCAN: on_autoscan_toggled(state); break;
            case IDC_CHECK_ALLDRIVES:
                if (HIWORD(wparam) == BN_CLICKED) { on_alldrives_toggled(state); }
                break;
            default: break;
            }
        }
        return 0;

    case WM_DEVICECHANGE:
        if (state != NULL &&
            (wparam == DBT_DEVICEARRIVAL || wparam == DBT_DEVICEREMOVECOMPLETE)) {
            handle_device_change(state);
        }
        return TRUE;

    case WM_APP_SCAN_PROGRESS:
        if (state != NULL) {
            usbs_scan_progress_t *progress = (usbs_scan_progress_t *)lparam;
            handle_progress(state, progress);
            free(progress);
        }
        return 0;

    case WM_APP_SCAN_DONE:
        if (state != NULL) {
            gui_done_payload_t *payload = (gui_done_payload_t *)lparam;
            handle_scan_done(state, payload->status, payload->result);
            free(payload);
        }
        return 0;

    case WM_CLOSE:
        if (state != NULL && state->scanning) {
            MessageBoxW(hwnd, L"A scan is in progress. Cancel it first.",
                       L"USB Sentinel", MB_OK | MB_ICONWARNING);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        on_destroy(hwnd, state);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

/*
 * icon_large/icon_small are out-parameters so the caller can DestroyIcon()
 * them at process shutdown (Phase 12, ARCHITECTURE.md section 18): these
 * two LoadImageW() calls have no LR_SHARED flag, so each returns a private
 * HICON this process owns, distinct from the wc.hIcon/hIconSm fields they
 * feed (which may instead hold the *shared* system icon from
 * LoadIconW(NULL, IDI_APPLICATION) when loading the resource fails - a
 * shared icon must never be passed to DestroyIcon). Only these two output
 * handles are ever destroyed; the class's own hIcon/hIconSm fields are not
 * read back for that purpose.
 */
static ATOM register_class(HINSTANCE instance, HICON *out_icon_large, HICON *out_icon_small)
{
    WNDCLASSEXW wc;
    HICON       icon_large;
    HICON       icon_small;

    /* The application icon, compiled into this executable's resources
     * (resources/usb_sentinel_gui.rc.in). LoadIconW picks the closest
     * large size; the small one is requested explicitly at the system's
     * small-icon metric so the title bar and Alt+Tab get a crisp 16px
     * image rather than a downscaled 32px one. */
    icon_large = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(IDI_USBS_APP_ICON), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                   LR_DEFAULTCOLOR);
    icon_small = (HICON)LoadImageW(instance, MAKEINTRESOURCEW(IDI_USBS_APP_ICON), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                   LR_DEFAULTCOLOR);
    *out_icon_large = icon_large;
    *out_icon_small = icon_small;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = instance;
    wc.hIcon         = (icon_large != NULL) ? icon_large : LoadIconW(NULL, IDI_APPLICATION);
    wc.hIconSm       = (icon_small != NULL) ? icon_small : wc.hIcon;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"USBSentinelMainWindow";
    return RegisterClassExW(&wc);
}

int gui_window_run(HINSTANCE instance, int show_command)
{
    INITCOMMONCONTROLSEX icc;
    HWND                  hwnd;
    MSG                   msg;
    HICON                 icon_large = NULL;
    HICON                 icon_small = NULL;
    int                   result;

    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    if (register_class(instance, &icon_large, &icon_small) == 0 &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        if (icon_large != NULL) { DestroyIcon(icon_large); }
        if (icon_small != NULL) { DestroyIcon(icon_small); }
        return -1;
    }

    hwnd = CreateWindowExW(0, L"USBSentinelMainWindow", L"USB Sentinel",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 720, 640,
        NULL, NULL, instance, NULL);
    if (hwnd == NULL) {
        if (icon_large != NULL) { DestroyIcon(icon_large); }
        if (icon_small != NULL) { DestroyIcon(icon_small); }
        return -1;
    }

    /*
     * Phase 9 hot-plug detection: filtered to volume interface arrivals/
     * removals (GUID_DEVINTERFACE_VOLUME) rather than every device class,
     * so WM_DEVICECHANGE only fires for things populate_devices() would
     * actually care about. Not fatal if this fails - the window still
     * works, just without live updates; Refresh still works manually. By
     * this point WM_CREATE has already run (CreateWindowExW dispatches it
     * synchronously), so GWLP_USERDATA is already set. */
    {
        DEV_BROADCAST_DEVICEINTERFACE_W filter;
        HDEVNOTIFY                       notify;

        memset(&filter, 0, sizeof(filter));
        filter.dbcc_size       = sizeof(filter);
        filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        filter.dbcc_classguid  = k_guid_devinterface_volume;

        notify = RegisterDeviceNotificationW(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
        if (notify != NULL) {
            gui_state_t *state = (gui_state_t *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
            if (state != NULL) {
                state->dev_notify = notify;
            }
        }
    }

    ShowWindow(hwnd, show_command);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    result = (int)msg.wParam;

    /* The window (and the class's own references to these icons) is gone by
     * the time GetMessageW returns 0 - WM_DESTROY has already run inside
     * DispatchMessageW for the WM_DESTROY/WM_QUIT pair that ends the loop.
     * This process only ever creates one window, so this is also the last
     * possible moment any code could still be using these HICONs; freeing
     * them earlier (e.g. in on_destroy) would either race the still-visible
     * window or need to special-case "window destroyed, message loop not
     * yet drained". Never destroys the LoadIconW(NULL, IDI_APPLICATION)
     * fallback: only these two out-parameters, which are NULL whenever that
     * fallback was the one actually used. */
    if (icon_large != NULL) { DestroyIcon(icon_large); }
    if (icon_small != NULL) { DestroyIcon(icon_small); }

    return result;
}
