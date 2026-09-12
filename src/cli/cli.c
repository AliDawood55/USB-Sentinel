#include <stdio.h>
#include <string.h>

#include "cli.h"
#include "usbsentinel/log.h"
#include "usbsentinel/version.h"

void usbs_cli_print_usage(FILE *stream)
{
    fprintf(stream,
            "%s\n"
            "\n"
            "Usage:\n"
            "  usb-sentinel <command>\n"
            "\n"
            "Commands:\n"
            "  devices    List attached USB storage devices\n"
            "  scan       Scan a USB device and produce a report\n"
            "  version    Print the version and exit\n"
            "  help       Print this message and exit\n"
            "\n"
            "Options for `devices`:\n"
            "  --all      List every volume, not just USB devices\n"
            "\n"
            "Usage for `scan`:\n"
            "  usb-sentinel scan [target] [--signatures <path>]\n"
            "    target       A drive letter (e.g. \"E:\") or part of a device\n"
            "                 identity; with none, the first USB device found\n"
            "                 is scanned. Ctrl+C cancels an in-progress scan.\n"
            "    --signatures <path>\n"
            "                 Load hash-match signatures from <path> instead of\n"
            "                 the default %%LOCALAPPDATA%%\\USBSentinel\\signatures.txt.\n"
            "                 Format: one \"sha256:size:name\" entry per line,\n"
            "                 '#' comments. Never fetched over the network -\n"
            "                 you supply this file yourself.\n"
            "\n"
            "Scanning is read-only by design: USB Sentinel never deletes,\n"
            "quarantines, or modifies files, and never accesses the network.\n",
            usbs_version_banner());
}

usbs_status_t usbs_cli_run(int argc, char **argv)
{
    const char *command;

    if (argc < 2 || argv == NULL) {
        usbs_cli_print_usage(stdout);
        return USBS_OK;
    }

    command = argv[1];

    if (strcmp(command, "devices") == 0) {
        return usbs_cli_cmd_devices(argc, argv);
    }

    if (strcmp(command, "scan") == 0) {
        return usbs_cli_cmd_scan(argc, argv);
    }

    if (strcmp(command, "version") == 0) {
        printf("%s\n", usbs_version_banner());
        return USBS_OK;
    }

    if (strcmp(command, "help") == 0 ||
        strcmp(command, "--help") == 0 ||
        strcmp(command, "-h") == 0) {
        usbs_cli_print_usage(stdout);
        return USBS_OK;
    }

    USBS_LOG_E("unknown command: %s", command);
    usbs_cli_print_usage(stderr);
    return USBS_ERR_INVALID_ARG;
}
