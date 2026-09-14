/*
 * Phase 17.1 (ARCHITECTURE.md section 24): the internal-drive location
 * classifier. Pure string matching, so every rule is pinned here, table
 * driven, with no filesystem and no hardware.
 *
 * The negative rows matter as much as the positive ones. Each tuned kind
 * weakens a heuristic somewhere, so "a path that merely looks similar does
 * NOT get tuned" is the property that keeps the policy from turning into a
 * blind spot. That covers a Startup folder inside the Start Menu, a
 * node_modules tree inside Downloads, and a scratch-like name outside a
 * build tree.
 */
#include <string.h>

#include "test_util.h"
#include "usbsentinel/location.h"

typedef struct row {
    const char           *path;
    usbs_location_kind_t  expected;
} row_t;

static void test_classification_table(void)
{
    static const row_t rows[] = {
        /* Real paths from the Phase 17 C: scan that motivated this. */
        { "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CV_ALI.pdf.lnk",
          USBS_LOCATION_RECENT_ITEMS },
        { "Users\\alida\\AppData\\Roaming\\Microsoft\\Office\\Recent\\Report.docx.LNK",
          USBS_LOCATION_RECENT_ITEMS },
        /* Found by the 17.1 verification rescan: an application's own
         * recent-files folder, the last warning on a clean machine. */
        { "Users\\alida\\AppData\\Roaming\\Autodesk\\AutoCAD 2025\\R25.0\\enu\\Recent\\PDFIMPORT\\CW 3-3.pdf.lnk",
          USBS_LOCATION_RECENT_ITEMS },
        { "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Visual Studio 2022\\Visual Studio Tools\\Developer PowerShell for VS 2022.lnk",
          USBS_LOCATION_OS_SHORTCUTS },
        { "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Windows PowerShell\\Windows PowerShell.lnk",
          USBS_LOCATION_OS_SHORTCUTS },
        { "Windows\\WinSxS\\amd64_microsoft.windows.powershell.common_31bf3856ad364e35_10.0.26100.1_none_2dd2f8b883c5b765\\Windows PowerShell.lnk",
          USBS_LOCATION_OS_COMPONENT_STORE },
        { "Projects\\LiveGuard\\frontend\\node_modules\\es-iterator-helpers\\test\\Iterator.zip.js",
          USBS_LOCATION_DEPENDENCY_TREE },
        { "Projects\\MedOrbit\\mobile\\build\\app\\intermediates\\compressed_assets\\debug\\flutter_map_logo.png.jar",
          USBS_LOCATION_DEPENDENCY_TREE },
        { "Projects\\USB-Sentinel\\build\\x64-debug\\tests\\test_scanner_scratch_0000053d\\invoice.pdf.exe",
          USBS_LOCATION_SELF_TEST_FIXTURES },
        { "Projects\\USB-Sentinel\\build\\ci-vs\\tests\\test_lnk_scratch_00003a26",
          USBS_LOCATION_SELF_TEST_FIXTURES },

        /* Other dependency trees. */
        { "Users\\u\\AppData\\Local\\Programs\\Python\\Python312\\Lib\\site-packages\\x\\a.zip.py",
          USBS_LOCATION_DEPENDENCY_TREE },
        { "Users\\u\\.gradle\\caches\\a.png.jar", USBS_LOCATION_DEPENDENCY_TREE },
        { "Users\\u\\.m2\\repository\\a.zip.jar", USBS_LOCATION_DEPENDENCY_TREE },

        /* User-exposed: full severity. */
        { "Users\\alida\\Downloads\\invoice.pdf.exe", USBS_LOCATION_USER_EXPOSED },
        { "Users\\alida\\Desktop\\resume.pdf.lnk", USBS_LOCATION_USER_EXPOSED },
        { "Users\\alida\\OneDrive\\Desktop\\a.pdf.exe", USBS_LOCATION_USER_EXPOSED },
        { "Users\\alida\\OneDrive - Contoso\\Downloads\\a.pdf.exe", USBS_LOCATION_USER_EXPOSED },
        { "Users\\alida\\AppData\\Local\\Temp\\Temp1_mail.zip\\invoice.pdf.exe", USBS_LOCATION_USER_EXPOSED },

        /* Startup outranks the Start Menu it lives in: persistence location. */
        { "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\updater.lnk",
          USBS_LOCATION_USER_EXPOSED },
        { "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk",
          USBS_LOCATION_USER_EXPOSED },

        /* User-exposed outranks a dependency tree: a node_modules folder in
         * Downloads is an attacker-controllable name, not an npm install. */
        { "Users\\alida\\Downloads\\proj\\node_modules\\x\\invoice.pdf.exe", USBS_LOCATION_USER_EXPOSED },

        /* POSIX separators and case-insensitivity. */
        { "users/ALIDA/appdata/roaming/microsoft/windows/recent/a.pdf.lnk", USBS_LOCATION_RECENT_ITEMS },
        { "home/alice/project/node_modules/pkg/Iterator.zip.js", USBS_LOCATION_DEPENDENCY_TREE },
        { "\\Windows\\WinSxS\\x.lnk", USBS_LOCATION_OS_COMPONENT_STORE }, /* leading separator */

        /* Ordinary, including near-misses. */
        { "", USBS_LOCATION_ORDINARY },
        { "invoice.pdf.exe", USBS_LOCATION_ORDINARY },
        { "Users\\alida\\Documents\\invoice.pdf.exe", USBS_LOCATION_ORDINARY },
        { "Users\\alida\\AppData\\Roaming\\Microsoft\\Windows\\Recently\\a.pdf.lnk", USBS_LOCATION_ORDINARY },
        { "Users\\alida\\AppData\\Local\\App\\Recent\\a.pdf.lnk", USBS_LOCATION_ORDINARY },    /* Local, not Roaming */
        { "Users\\alida\\Documents\\Recent\\a.pdf.lnk", USBS_LOCATION_ORDINARY },              /* not under AppData */
        { "Users\\alida\\AppData\\Roaming\\Recent", USBS_LOCATION_ORDINARY },                  /* a file named Recent */
        { "Data\\Users\\alida\\Downloads\\a.pdf.exe", USBS_LOCATION_ORDINARY }, /* Users not at the root */
        { "Windows\\System32\\a.lnk", USBS_LOCATION_ORDINARY },
        { "Projects\\x\\node_modules_backup\\a.zip.js", USBS_LOCATION_ORDINARY },
        { "Projects\\x\\intermediates\\a.png.jar", USBS_LOCATION_ORDINARY }, /* not under build\ */

        /* Self-test fixture look-alikes that must NOT be excluded. */
        { "Users\\alida\\Downloads\\tests\\test_scanner_scratch_0000053d\\invoice.pdf.exe",
          USBS_LOCATION_USER_EXPOSED },                                   /* no build\ ancestor */
        { "Projects\\x\\tests\\test_scanner_scratch_0000053d\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* no build\ ancestor */
        { "Projects\\x\\build\\tests\\test_scanner_scratch_053d\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* not 8 hex digits */
        { "Projects\\x\\build\\tests\\test_scanner_scratch_0000053g\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* 'g' is not hex */
        { "Projects\\x\\build\\tests\\test__scratch_0000053d\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* empty <name> */
        { "Projects\\x\\build\\other\\test_scanner_scratch_0000053d\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* parent is not tests\ */
        { "Projects\\x\\build\\tests\\evil test_scanner_scratch_0000053d\\a.pdf.exe",
          USBS_LOCATION_ORDINARY },                                       /* prefix must be exact */
    };
    size_t i;

    for (i = 0; i < USBS_ARRAY_LEN(rows); ++i) {
        usbs_location_kind_t got = usbs_location_classify(rows[i].path);
        if (got != rows[i].expected) {
            printf("  classify(\"%s\") = %s, expected %s\n", rows[i].path,
                   usbs_location_kind_string(got), usbs_location_kind_string(rows[i].expected));
        }
        USBS_CHECK(got == rows[i].expected);
    }

    USBS_CHECK(usbs_location_classify(NULL) == USBS_LOCATION_ORDINARY);
}

/* The policy is only ever for a known non-USB bus. USB (including an
 * external USB HDD, whose names an attacker controls) and an unknown bus
 * (a bare `scan <path>`) keep the strict rules. */
static void test_policy_applies_only_to_known_non_usb_buses(void)
{
    usbs_device_t device;

    usbs_device_init(&device);

    device.bus_type = USBS_BUS_USB;     USBS_CHECK(!usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_UNKNOWN; USBS_CHECK(!usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_SATA;    USBS_CHECK(usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_NVME;    USBS_CHECK(usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_SCSI;    USBS_CHECK(usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_SD;      USBS_CHECK(usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_OTHER;   USBS_CHECK(usbs_location_policy_applies(&device));
    device.bus_type = USBS_BUS_NETWORK; USBS_CHECK(usbs_location_policy_applies(&device));

    USBS_CHECK(!usbs_location_policy_applies(NULL));
}

static void test_relative_path(void)
{
    const char *volume = "\\\\?\\Volume{abc}\\";

    USBS_CHECK_STR_EQ(usbs_location_relative(volume, "\\\\?\\Volume{abc}\\Users\\a\\x.lnk"),
                      "Users\\a\\x.lnk");
    USBS_CHECK_STR_EQ(usbs_location_relative(volume, "D:\\other\\x.lnk"), "D:\\other\\x.lnk");
    USBS_CHECK_STR_EQ(usbs_location_relative(NULL, "x.lnk"), "x.lnk");
    USBS_CHECK_STR_EQ(usbs_location_relative(volume, NULL), "");
}

static void test_kind_strings_never_null(void)
{
    int k;
    for (k = USBS_LOCATION_ORDINARY; k <= USBS_LOCATION_SELF_TEST_FIXTURES; ++k) {
        USBS_CHECK(usbs_location_kind_string((usbs_location_kind_t)k) != NULL);
    }
    USBS_CHECK(usbs_location_kind_string((usbs_location_kind_t)999) != NULL);
}

/* A path deeper than the component bound must not crash, and must fall to
 * the strict side (never to a tuned kind it cannot see). */
static void test_pathologically_deep_path(void)
{
    char   path[4096];
    size_t used = 0;
    int    i;

    for (i = 0; i < 200 && used + 3 < sizeof(path); ++i) {
        path[used++] = 'd';
        path[used++] = '\\';
    }
    snprintf(path + used, sizeof(path) - used, "node_modules\\a.zip.js");
    USBS_CHECK(usbs_location_classify(path) == USBS_LOCATION_ORDINARY);
}

int main(void)
{
    test_classification_table();
    test_policy_applies_only_to_known_non_usb_buses();
    test_relative_path();
    test_kind_strings_never_null();
    test_pathologically_deep_path();
    return USBS_TEST_RESULT();
}
