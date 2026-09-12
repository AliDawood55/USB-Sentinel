/*
 * Genuinely OS-independent POSIX plumbing: the status_from_win32 stub, and
 * cancellation. Compiled on every UNIX host (Linux, macOS, and anything
 * else), unlike device enumeration and capability probing, which are
 * OS-specific and live in device_linux.c / device_macos.c /
 * device_posix_unsupported.c (ARCHITECTURE.md section 21) - this file
 * used to hold stub versions of those too, before Phase 14b gave Linux a
 * real implementation.
 *
 * Cancellation needs no hardware and is fully implemented here - it is a
 * signal handler, and without it a POSIX scan could not be interrupted at
 * all.
 */
#include <signal.h>
#include <string.h>

#include "usbsentinel/log.h"
#include "usbsentinel/platform.h"

/*
 * Declared in platform.h for the Win32 side and exposed there for its tests.
 * It must still link on POSIX; there is no errno that maps to a Win32 error
 * code, so this is the one honest answer.
 */
usbs_status_t usbs_platform_status_from_win32(unsigned long win32_error)
{
    USBS_UNUSED(win32_error);
    return USBS_ERR_UNSUPPORTED;
}

/* --- cancellation --- */

/*
 * sig_atomic_t, volatile, and nothing else: these are the only objects the C
 * standard permits a signal handler to touch in a well-defined way. The
 * Win32 side can use InterlockedExchange because its handler runs on a
 * separate thread; a POSIX signal handler interrupts the running thread, so
 * the constraint is different and stricter.
 */
static volatile sig_atomic_t g_cancel_requested = 0;

static void handle_cancel_signal(int signo)
{
    USBS_UNUSED(signo);
    g_cancel_requested = 1;
}

usbs_status_t usbs_platform_install_cancel_handler(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_cancel_signal;
    sigemptyset(&action.sa_mask);

    /*
     * Deliberately NOT SA_RESTART. Without it an interrupted read() or
     * readdir() returns EINTR, which is what lets a scan notice the
     * cancellation promptly instead of finishing the current syscall on a
     * slow or wedged device first. fs_posix.c retries EINTR explicitly
     * wherever a partial operation would otherwise be lost, so this costs
     * nothing in correctness.
     *
     * sigaction rather than signal(): signal()'s handler-reset and
     * restart semantics differ between platforms, and this has to behave
     * identically on Linux and macOS.
     */
    if (sigaction(SIGINT, &action, NULL) != 0) {
        USBS_LOG_W("could not install SIGINT handler; scans will not be cancellable");
        return USBS_ERR_INTERNAL;
    }

    /* SIGTERM too: a scan is just as likely to be stopped by a service
     * manager or a `kill` as by Ctrl+C at a terminal, and the correct
     * response - stop cleanly, keep the partial report - is the same. */
    if (sigaction(SIGTERM, &action, NULL) != 0) {
        USBS_LOG_W("could not install SIGTERM handler");
        /* SIGINT is installed and is the common case, so this is a partial
         * success rather than a failure. */
    }

    return USBS_OK;
}

usbs_bool usbs_platform_cancel_requested(void)
{
    return g_cancel_requested != 0;
}
