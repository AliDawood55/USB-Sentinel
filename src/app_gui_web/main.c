/*
 * USB Sentinel - Phase 16: web GUI entry point (usb-sentinel-gui-web).
 *
 * Startup sequence: generate a per-launch CSPRNG token, open the HTTP
 * server on an OS-assigned loopback port, build the launch URL
 * (http://127.0.0.1:<port>/?token=<token>), print it, hand it to
 * xdg-open/open, then run the server's accept loop on this thread
 * until SIGINT/SIGTERM or a long idle period. See ARCHITECTURE.md
 * section 22 for the full security model this file is one half of
 * (src/gui_web/ is the other half).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

#include "gui_web_app.h"
#include "http_server.h"

#include "usbsentinel/env.h"
#include "usbsentinel/error.h"
#include "usbsentinel/storage.h"

#define TOKEN_HEX_LEN 32 /* 16 random bytes, hex-encoded */

/*
 * A long but bounded default: this server has no window and no dock
 * icon, so nothing else reminds a user it is still running after they
 * close the browser tab. An idle server is otherwise harmless (loopback
 * only, token-gated - ARCHITECTURE.md section 22), but exiting after a
 * long period of no requests at all is a safety net against an
 * orphaned listener accumulating across many past sessions, the same
 * concern Jupyter's own idle-culling addresses.
 */
#define IDLE_TIMEOUT_SECONDS (60u * 60u)

static volatile sig_atomic_t g_stop_requested = 0;

static void handle_stop_signal(int sig)
{
    (void)sig;
    g_stop_requested = 1;
}

/*
 * 16 random bytes, hex-encoded into `out` (needs at least
 * TOKEN_HEX_LEN + 1 bytes). getrandom() on Linux (with a /dev/urandom
 * fallback for a kernel too old to have the syscall), arc4random_buf()
 * on macOS/BSD - both first-party OS facilities, not a third-party
 * dependency, the same "prefer the platform's own facility" stance
 * ARCHITECTURE.md applies to SHA-256 (CNG/CommonCrypto) and device
 * enumeration (SetupAPI, not WMI). rand()/srand() - the only
 * randomness this project uses anywhere else (scanner.c's scan_id) -
 * is explicitly documented there as not cryptographically random and
 * is not good enough for a token that gates a local HTTP API.
 */
static usbs_status_t generate_token(char *out, size_t out_cap)
{
    unsigned char raw[16];
    size_t        i;
    static const char hex_digits[] = "0123456789abcdef";
    usbs_bool     have_bytes = false;

    if (out == NULL || out_cap < TOKEN_HEX_LEN + 1) {
        return USBS_ERR_INVALID_ARG;
    }

#if defined(__linux__)
    if (getrandom(raw, sizeof(raw), 0) == (ssize_t)sizeof(raw)) {
        have_bytes = true;
    }
#elif defined(__APPLE__)
    arc4random_buf(raw, sizeof(raw));
    have_bytes = true;
#endif

    if (!have_bytes) {
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom == NULL) {
            return USBS_ERR_IO;
        }
        have_bytes = (fread(raw, 1, sizeof(raw), urandom) == sizeof(raw));
        fclose(urandom);
        if (!have_bytes) {
            return USBS_ERR_IO;
        }
    }

    for (i = 0; i < sizeof(raw); ++i) {
        out[i * 2]     = hex_digits[(raw[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_digits[raw[i] & 0x0F];
    }
    out[sizeof(raw) * 2] = '\0';
    return USBS_OK;
}

/*
 * Forks xdg-open (Linux) / open (macOS) on `url` and does not wait for
 * it - SIGCHLD is set to SIG_IGN in main() before this runs, which the
 * kernel treats as "auto-reap", so the child never becomes a zombie
 * without this file needing its own SIGCHLD handler. The URL is always
 * printed regardless of whether this succeeds (or whether the opener
 * command exists at all) - a graceful, honest fallback rather than a
 * hard failure, matching this project's stance elsewhere of never
 * silently dropping a capability gap (ARCHITECTURE.md section 1).
 */
static void launch_browser(const char *url)
{
    pid_t pid = fork();

    if (pid < 0) {
        return; /* fork failed; the printed URL is still the fallback */
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
        }
#if defined(__APPLE__)
        execlp("open", "open", url, (char *)NULL);
#else
        execlp("xdg-open", "xdg-open", url, (char *)NULL);
#endif
        _exit(127); /* exec failed (e.g. no xdg-open installed) */
    }
}

/*
 * A single-instance lock under a per-user runtime directory
 * ($XDG_RUNTIME_DIR, falling back to /tmp - the same fallback order
 * systemd-adjacent tools use). flock() rather than a PID file: it is
 * released automatically on process exit or crash, so there is no
 * stale-lock cleanup logic to get wrong.
 *
 * On success, this process becomes the running server: the fd stays
 * open (and locked) for the process's whole lifetime and the file is
 * (re)written with this launch's own "<port> <token>" line for a
 * second launch to find. On failure to acquire the lock, this
 * function instead reads that line back and returns the existing
 * server's port/token so main() can just open a browser tab against
 * it and exit, rather than confusing the user with two independent
 * servers. That read is not synchronized with the holder's write (no
 * second lock protects it), so it can in principle race a holder that
 * is between opening the file and finishing that write; the failure
 * mode is a second launch briefly seeing a stale or partial line and
 * printing an unusable URL, not a security issue (the running
 * server's own token/Host checks are unaffected either way) - low
 * enough odds and low enough consequence not to warrant a second lock
 * just for this optional convenience feature.
 */
static usbs_bool acquire_single_instance_lock(unsigned short *out_existing_port,
                                              char *out_existing_token, size_t token_cap)
{
    char        lock_path[512];
    const char *runtime_dir;
    char        env_buf[400];
    int         fd;

    if (usbs_ok(usbs_getenv("XDG_RUNTIME_DIR", env_buf, sizeof(env_buf))) && env_buf[0] != '\0') {
        runtime_dir = env_buf;
    } else {
        runtime_dir = "/tmp";
    }
    snprintf(lock_path, sizeof(lock_path), "%s/usb-sentinel-gui-web.lock", runtime_dir);

    fd = open(lock_path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        return true; /* can't even open the lock file; proceed as if we own it */
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        return true; /* lock acquired; fd deliberately leaked for the process's lifetime */
    }

    /* Another instance holds the lock - read its port/token instead. */
    close(fd);
    if (out_existing_port != NULL && out_existing_token != NULL) {
        FILE *f = fopen(lock_path, "r");
        unsigned port = 0;

        *out_existing_port = 0;
        out_existing_token[0] = '\0';
        if (f != NULL) {
            if (fscanf(f, "%u %399s", &port, env_buf) == 2) {
                *out_existing_port = (unsigned short)port;
                snprintf(out_existing_token, token_cap, "%s", env_buf);
            }
            fclose(f);
        }
    }
    return false;
}

static void write_lock_file_contents(unsigned short port, const char *token)
{
    const char *runtime_dir;
    char        env_buf[400];
    char        lock_path[512];
    FILE       *f;

    if (usbs_ok(usbs_getenv("XDG_RUNTIME_DIR", env_buf, sizeof(env_buf))) && env_buf[0] != '\0') {
        runtime_dir = env_buf;
    } else {
        runtime_dir = "/tmp";
    }
    snprintf(lock_path, sizeof(lock_path), "%s/usb-sentinel-gui-web.lock", runtime_dir);

    f = fopen(lock_path, "w");
    if (f != NULL) {
        fprintf(f, "%u %s\n", (unsigned)port, token);
        fclose(f);
    }
}

int main(void)
{
    char           token[TOKEN_HEX_LEN + 1];
    usbs_store_t   store;
    http_server_t *server;
    unsigned short port;
    gui_web_app_t *app;
    char           url[256];
    unsigned short existing_port;
    char           existing_token[TOKEN_HEX_LEN + 1];

    /* Auto-reap launch_browser()'s child; see its own comment. */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    if (!acquire_single_instance_lock(&existing_port, existing_token, sizeof(existing_token))) {
        if (existing_port != 0 && existing_token[0] != '\0') {
            snprintf(url, sizeof(url), "http://127.0.0.1:%u/?token=%s",
                    (unsigned)existing_port, existing_token);
            printf("USB Sentinel is already running: %s\n", url);
            launch_browser(url);
            return 0;
        }
        fprintf(stderr, "USB Sentinel appears to already be running, "
                        "but its address could not be determined.\n");
        return 1;
    }

    if (!usbs_ok(generate_token(token, sizeof(token)))) {
        fprintf(stderr, "Failed to generate a launch token (no system randomness source).\n");
        return 1;
    }

    if (!usbs_ok(usbs_store_open(&store))) {
        fprintf(stderr, "Failed to open the report store.\n");
        return 1;
    }

    if (!usbs_ok(http_server_start(&server, &port))) {
        fprintf(stderr, "Failed to start the local HTTP server.\n");
        return 1;
    }

    write_lock_file_contents(port, token);

    if (!usbs_ok(gui_web_app_create(&app, token, &store, port))) {
        fprintf(stderr, "Failed to initialize the application.\n");
        http_server_free(server);
        return 1;
    }

    snprintf(url, sizeof(url), "http://127.0.0.1:%u/?token=%s", (unsigned)port, token);
    printf("USB Sentinel is running at %s\n", url);
    printf("Press Ctrl+C to stop.\n");
    /* stdio is fully buffered, not line buffered, whenever stdout is not
     * a terminal (redirected to a file, or captured by a process
     * supervisor/launcher script) - confirmed empirically while testing
     * this file: without this flush, the printed URL above sat in libc's
     * buffer and never reached a redirected log at all until the process
     * later exited. The printed URL is this server's one fallback if
     * launch_browser() below can't find xdg-open/open, so it must be
     * visible immediately, not eventually. */
    fflush(stdout);
    launch_browser(url);

    http_server_run(server, gui_web_app_handle_request, app,
                    IDLE_TIMEOUT_SECONDS, &g_stop_requested);

    gui_web_app_shutdown(app);
    gui_web_app_free(app);
    http_server_free(server);
    return 0;
}
