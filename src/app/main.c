/*
 * USB Sentinel - executable entry point.
 *
 * Responsibilities are deliberately narrow: configure logging, hand control to
 * the cli module, and map the resulting status onto a process exit code.
 */
#include "cli.h"
#include "usbsentinel/error.h"
#include "usbsentinel/log.h"

int main(int argc, char **argv)
{
    usbs_status_t status;

    usbs_log_set_level(USBS_LOG_INFO);

    status = usbs_cli_run(argc, argv);

    /* Exit code 0 on success, 1 on any failure. Callers get detail on stderr. */
    return usbs_ok(status) ? 0 : 1;
}
