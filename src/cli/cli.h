/*
 * USB Sentinel - command dispatch.
 *
 * Internal to the cli module plus its tests; not part of the public surface in
 * include/usbsentinel.
 */
#ifndef USBSENTINEL_CLI_H
#define USBSENTINEL_CLI_H

#include <stdio.h>

#include "usbsentinel/error.h"

/*
 * Runs the command described by argv (argv[0] is the program name, as in main).
 * Returns USBS_OK on success, USBS_ERR_INVALID_ARG for an unknown command.
 */
usbs_status_t usbs_cli_run(int argc, char **argv);

/* Writes the usage text to `stream`. */
void usbs_cli_print_usage(FILE *stream);

/* Implements the `devices` command. argv/argc are as passed to usbs_cli_run. */
usbs_status_t usbs_cli_cmd_devices(int argc, char **argv);

/* Implements the `scan` command. argv/argc are as passed to usbs_cli_run. */
usbs_status_t usbs_cli_cmd_scan(int argc, char **argv);

#endif /* USBSENTINEL_CLI_H */
