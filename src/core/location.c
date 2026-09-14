/*
 * See usbsentinel/location.h. Pure string matching over a relative path's
 * components: nothing here touches the filesystem, so every rule is
 * unit-testable (tests/test_location.c) on any host.
 */
#include <string.h>

#include "usbsentinel/location.h"

/* A relative path is at most a few thousand bytes (scanner.c's child_path is
 * 2048) at a depth of at most USBS_SCAN_MAX_DEPTH (64) plus the file name.
 * Components past this bound are ignored, and every rule below matches
 * within the first dozen components except the "anywhere" ones, which a
 * pathologically deep path could then miss. That errs toward ORDINARY, i.e.
 * toward the stricter rules, never toward suppression. */
#define LOCATION_MAX_COMPONENTS 96

typedef struct component {
    const char *text;
    size_t      len;
} component_t;

static usbs_bool is_sep(char c)
{
    return c == '\\' || c == '/';
}

static char lower_ascii(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

static usbs_bool comp_is(const component_t *c, const char *literal)
{
    size_t i;
    size_t n = strlen(literal);

    if (c->len != n) {
        return false;
    }
    for (i = 0; i < n; ++i) {
        if (lower_ascii(c->text[i]) != lower_ascii(literal[i])) {
            return false;
        }
    }
    return true;
}

static usbs_bool comp_starts_with(const component_t *c, const char *prefix)
{
    size_t i;
    size_t n = strlen(prefix);

    if (c->len < n) {
        return false;
    }
    for (i = 0; i < n; ++i) {
        if (lower_ascii(c->text[i]) != lower_ascii(prefix[i])) {
            return false;
        }
    }
    return true;
}

static size_t split_components(const char *path, component_t *out, size_t cap)
{
    size_t      count = 0;
    const char *p     = path;

    while (*p != '\0' && count < cap) {
        const char *start;
        while (is_sep(*p)) {
            ++p;
        }
        if (*p == '\0') {
            break;
        }
        start = p;
        while (*p != '\0' && !is_sep(*p)) {
            ++p;
        }
        out[count].text = start;
        out[count].len  = (size_t)(p - start);
        ++count;
    }
    return count;
}

/* True iff comps[at...] equals the NULL-terminated literal sequence `seq`. */
static usbs_bool seq_at(const component_t *comps, size_t count, size_t at,
                        const char *const *seq)
{
    size_t i;
    for (i = 0; seq[i] != NULL; ++i) {
        if (at + i >= count || !comp_is(&comps[at + i], seq[i])) {
            return false;
        }
    }
    return true;
}

/* "test_<name>_scratch_<8 lowercase-or-uppercase hex>": the exact shape
 * every tests/test_*.c make_scratch_root() produces. Kept this narrow on
 * purpose: an exclusion is a blind spot, so it matches only what this
 * project's own suite creates. */
static usbs_bool is_self_test_scratch_name(const component_t *c)
{
    static const char marker[] = "_scratch_";
    const size_t      marker_len = sizeof(marker) - 1;
    size_t            i;

    if (!comp_starts_with(c, "test_") || c->len < 5 + 1 + marker_len + 8) {
        return false;
    }
    /* The 8 hex digits are the tail; the marker sits immediately before. */
    for (i = c->len - 8; i < c->len; ++i) {
        char ch = lower_ascii(c->text[i]);
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    if (strncmp(c->text + c->len - 8 - marker_len, marker, marker_len) != 0) {
        return false;
    }
    /* <name>: at least one [a-z0-9_] between "test_" and the marker. */
    for (i = 5; i < c->len - 8 - marker_len; ++i) {
        char ch = lower_ascii(c->text[i]);
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_')) {
            return false;
        }
    }
    return c->len - 8 - marker_len > 5;
}

static usbs_bool matches_self_test_fixtures(const component_t *comps, size_t count)
{
    size_t    i;
    usbs_bool seen_build = false;

    for (i = 0; i < count; ++i) {
        if (comp_is(&comps[i], "build")) {
            seen_build = true;
        }
        if (seen_build && i >= 1 && comp_is(&comps[i - 1], "tests") &&
            is_self_test_scratch_name(&comps[i])) {
            return true;
        }
    }
    return false;
}

static usbs_bool matches_user_exposed(const component_t *comps, size_t count)
{
    static const char *const startup_all[]  = { "ProgramData", "Microsoft", "Windows",
                                                "Start Menu", "Programs", "Startup", NULL };
    static const char *const startup_user[] = { "AppData", "Roaming", "Microsoft", "Windows",
                                                "Start Menu", "Programs", "Startup", NULL };
    static const char *const temp_user[]    = { "AppData", "Local", "Temp", NULL };

    if (seq_at(comps, count, 0, startup_all)) {
        return true;
    }
    if (count < 3 || !comp_is(&comps[0], "Users")) {
        return false;
    }
    /* Users\<u>\... */
    if (comp_is(&comps[2], "Desktop") || comp_is(&comps[2], "Downloads")) {
        return true;
    }
    /* Users\<u>\OneDrive[ - Org]\Desktop|Downloads (known-folder redirection). */
    if (count >= 4 && comp_starts_with(&comps[2], "OneDrive") &&
        (comp_is(&comps[3], "Desktop") || comp_is(&comps[3], "Downloads"))) {
        return true;
    }
    return seq_at(comps, count, 2, startup_user) || seq_at(comps, count, 2, temp_user);
}

static usbs_bool matches_dependency_tree(const component_t *comps, size_t count)
{
    size_t i;
    for (i = 0; i < count; ++i) {
        if (comp_is(&comps[i], "node_modules") || comp_is(&comps[i], "site-packages") ||
            comp_is(&comps[i], ".gradle") || comp_is(&comps[i], ".m2")) {
            return true;
        }
        /* Gradle puts intermediates at <module>\build\intermediates; Flutter's
         * Android build nests the module inside, build\app\intermediates
         * (the real path of the flutter_map_logo.png.jar finding that
         * prompted this rule, and what test_location.c pins). */
        if (comp_is(&comps[i], "intermediates") &&
            ((i >= 1 && comp_is(&comps[i - 1], "build")) ||
             (i >= 2 && comp_is(&comps[i - 2], "build")))) {
            return true;
        }
    }
    return false;
}

/* Users\<u>\AppData\Roaming\...\Recent\...: Windows' own Recent Items
 * (Microsoft\Windows\Recent), Office's (Microsoft\Office\Recent), and the
 * per-application recent-file folders many applications keep under Roaming,
 * e.g. Autodesk\AutoCAD 2025\R25.0\enu\Recent\PDFIMPORT, which the Phase
 * 17.1 verification scan found as the one remaining warning on a clean
 * machine. Roaming AppData is not a location a user browses to open files,
 * and a shortcut's content is still inspected there by lnk_inspection. */
static usbs_bool matches_recent_items(const component_t *comps, size_t count)
{
    static const char *const roaming[] = { "AppData", "Roaming", NULL };
    size_t i;

    if (count < 5 || !comp_is(&comps[0], "Users") || !seq_at(comps, count, 2, roaming)) {
        return false;
    }
    /* A "Recent" directory below Roaming; the final component is the file
     * itself and cannot be the directory. */
    for (i = 4; i + 1 < count; ++i) {
        if (comp_is(&comps[i], "Recent")) {
            return true;
        }
    }
    return false;
}

static usbs_bool matches_os_shortcuts(const component_t *comps, size_t count)
{
    static const char *const all_users[] = { "ProgramData", "Microsoft", "Windows", "Start Menu", NULL };
    static const char *const per_user[]  = { "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", NULL };

    return seq_at(comps, count, 0, all_users) ||
           (count >= 2 && comp_is(&comps[0], "Users") && seq_at(comps, count, 2, per_user));
}

usbs_bool usbs_location_policy_applies(const usbs_device_t *device)
{
    if (device == NULL) {
        return false;
    }
    return device->bus_type != USBS_BUS_USB && device->bus_type != USBS_BUS_UNKNOWN;
}

usbs_location_kind_t usbs_location_classify(const char *relative_path)
{
    static const char *const winsxs[] = { "Windows", "WinSxS", NULL };
    component_t comps[LOCATION_MAX_COMPONENTS];
    size_t      count;

    if (relative_path == NULL) {
        return USBS_LOCATION_ORDINARY;
    }
    count = split_components(relative_path, comps, USBS_ARRAY_LEN(comps));

    if (matches_self_test_fixtures(comps, count)) {
        return USBS_LOCATION_SELF_TEST_FIXTURES;
    }
    if (matches_user_exposed(comps, count)) {
        return USBS_LOCATION_USER_EXPOSED;
    }
    if (matches_dependency_tree(comps, count)) {
        return USBS_LOCATION_DEPENDENCY_TREE;
    }
    if (matches_recent_items(comps, count)) {
        return USBS_LOCATION_RECENT_ITEMS;
    }
    if (seq_at(comps, count, 0, winsxs)) {
        return USBS_LOCATION_OS_COMPONENT_STORE;
    }
    if (matches_os_shortcuts(comps, count)) {
        return USBS_LOCATION_OS_SHORTCUTS;
    }
    return USBS_LOCATION_ORDINARY;
}

const char *usbs_location_kind_string(usbs_location_kind_t kind)
{
    switch (kind) {
    case USBS_LOCATION_ORDINARY:           return "ordinary location";
    case USBS_LOCATION_USER_EXPOSED:       return "user-facing location";
    case USBS_LOCATION_OS_SHORTCUTS:       return "Start Menu";
    case USBS_LOCATION_OS_COMPONENT_STORE: return "Windows component store";
    case USBS_LOCATION_RECENT_ITEMS:       return "Windows Recent Items";
    case USBS_LOCATION_DEPENDENCY_TREE:    return "package dependency tree";
    case USBS_LOCATION_SELF_TEST_FIXTURES: return "USB Sentinel test fixtures";
    }
    return "ordinary location";
}

const char *usbs_location_relative(const char *volume_path, const char *full_path)
{
    size_t prefix;

    if (full_path == NULL) {
        return "";
    }
    if (volume_path == NULL) {
        return full_path;
    }
    prefix = strlen(volume_path);
    if (prefix > 0 && strncmp(full_path, volume_path, prefix) == 0) {
        return full_path + prefix;
    }
    return full_path;
}
