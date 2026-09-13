/*
 * Deterministic tests for src/gui_web/http_server.c's pure request
 * parsing (http_request_parse(), http_request_header(),
 * http_request_content_length(), http_query_get()) - no sockets, no
 * real server, matching this project's usual split between "pure
 * logic, tested directly" and "real I/O, exercised end to end
 * separately" (the same shape test_device_linux.c uses for
 * device_linux.c's sysfs/mountinfo parsing vs. its real-hardware CI
 * job). The actual socket-facing half of http_server.c is exercised by
 * a real curl round trip instead - see the release workflow/CI notes -
 * since a fixture cannot meaningfully stand in for a real accept()/
 * recv() loop the way it can for sysfs.
 *
 * Also covers gui_web_app.c's device_has_valid_mount_point() - a small
 * pure function, but the one guarding a real v1.2.1 bug report
 * (ARCHITECTURE.md section 22.9), so it earns direct deterministic
 * coverage rather than relying solely on the real-device curl tests.
 */
#include <string.h>

#include "test_util.h"

#include "http_server.h"
#include "usbsentinel/device.h"

extern usbs_bool device_has_valid_mount_point(const usbs_device_t *device);

static void test_simple_get_no_headers(void)
{
    const char     *raw = "GET /api/devices HTTP/1.1\r\n\r\n";
    http_request_t  request;
    size_t          head_len = 0;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK_STR_EQ(request.method, "GET");
    USBS_CHECK_STR_EQ(request.path, "/api/devices");
    USBS_CHECK_STR_EQ(request.query, "");
    USBS_CHECK(request.header_count == 0);
    USBS_CHECK(head_len == strlen(raw));
}

/*
 * The real bug this test is modeled on: the header-parsing loop's
 * search range originally stopped one byte short of the LAST header's
 * own terminating '\r' (the same byte the "\r\n\r\n" head-end scan had
 * already matched against), silently dropping it. A real end-to-end
 * curl request - which always sends Host as one header among several,
 * never last by coincidence in this exact case - caught it; this test
 * pins it down deterministically. Multiple headers, in a specific
 * order, are essential to this test actually exercising that path.
 */
static void test_multiple_headers_last_one_not_dropped(void)
{
    const char *raw =
        "GET /api/progress?token=abc HTTP/1.1\r\n"
        "Host: 127.0.0.1:9999\r\n"
        "Accept: application/json\r\n"
        "X-USBSentinel-Token: deadbeef\r\n"
        "\r\n";
    http_request_t request;
    size_t         head_len = 0;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK_STR_EQ(request.method, "GET");
    USBS_CHECK_STR_EQ(request.path, "/api/progress");
    USBS_CHECK_STR_EQ(request.query, "token=abc");
    USBS_REQUIRE(request.header_count == 3);
    USBS_CHECK_STR_EQ(http_request_header(&request, "Host"), "127.0.0.1:9999");
    USBS_CHECK_STR_EQ(http_request_header(&request, "Accept"), "application/json");
    /* The one that was silently dropped before the fix - the last
     * header in the block, immediately preceding the blank line. */
    USBS_CHECK_STR_EQ(http_request_header(&request, "X-USBSentinel-Token"), "deadbeef");
    USBS_CHECK(head_len == strlen(raw));
}

static void test_header_lookup_is_case_insensitive(void)
{
    const char     *raw = "GET / HTTP/1.1\r\nhost: example\r\n\r\n";
    http_request_t  request;
    size_t          head_len = 0;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK_STR_EQ(http_request_header(&request, "Host"), "example");
    USBS_CHECK_STR_EQ(http_request_header(&request, "HOST"), "example");
    USBS_CHECK(http_request_header(&request, "Nonexistent") == NULL);
}

static void test_header_value_leading_space_trimmed(void)
{
    const char     *raw = "GET / HTTP/1.1\r\nX-Thing:    value with spaces\r\n\r\n";
    http_request_t  request;
    size_t          head_len = 0;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK_STR_EQ(http_request_header(&request, "X-Thing"), "value with spaces");
}

static void test_post_with_body_head_len_excludes_body(void)
{
    const char     *raw =
        "POST /api/scan HTTP/1.1\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";
    http_request_t  request;
    size_t          head_len = 0;
    size_t          content_length = 0;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK_STR_EQ(request.method, "POST");
    USBS_CHECK(usbs_ok(http_request_content_length(&request, &content_length)));
    USBS_CHECK(content_length == 5);
    USBS_CHECK(head_len == strlen(raw) - 5);
    USBS_CHECK(strncmp(raw + head_len, "hello", 5) == 0);
}

static void test_no_content_length_means_zero_not_error(void)
{
    const char     *raw = "GET / HTTP/1.1\r\n\r\n";
    http_request_t  request;
    size_t          head_len = 0;
    size_t          content_length = 999;

    USBS_REQUIRE(usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
    USBS_CHECK(usbs_ok(http_request_content_length(&request, &content_length)));
    USBS_CHECK(content_length == 0);
}

static void test_missing_blank_line_is_rejected(void)
{
    const char     *raw = "GET / HTTP/1.1\r\nHost: x\r\n"; /* no terminating blank line */
    http_request_t  request;
    size_t          head_len = 0;

    USBS_CHECK(!usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
}

static void test_malformed_request_line_is_rejected(void)
{
    const char     *raw = "GET\r\n\r\n"; /* fewer than 3 tokens */
    http_request_t  request;
    size_t          head_len = 0;

    USBS_CHECK(!usbs_ok(http_request_parse(raw, strlen(raw), &request, &head_len)));
}

static void test_query_get(void)
{
    char out[64];

    USBS_CHECK(http_query_get("device=abc123&token=deadbeef", "device", out, sizeof(out)));
    USBS_CHECK_STR_EQ(out, "abc123");

    USBS_CHECK(http_query_get("device=abc123&token=deadbeef", "token", out, sizeof(out)));
    USBS_CHECK_STR_EQ(out, "deadbeef");

    USBS_CHECK(!http_query_get("device=abc123", "missing", out, sizeof(out)));

    /* A key that is a prefix of another key must not false-match. */
    USBS_CHECK(!http_query_get("devicex=abc123", "device", out, sizeof(out)));

    USBS_CHECK(!http_query_get("", "device", out, sizeof(out)));
}

/*
 * The real bug report this guards against (v1.2.1): a device with no
 * resolved mount point must never reach a worker thread. Covers the
 * three ways a device can fail to qualify, plus the one shape that
 * must pass - a real, fully-populated mounted device.
 */
static void test_device_has_valid_mount_point(void)
{
    usbs_device_t device;

    usbs_device_init(&device);
    USBS_CHECK(!device_has_valid_mount_point(&device)); /* zeroed: no mount at all */

    usbs_device_init(&device);
    device.mount_point_count = 1;
    snprintf(device.mount_points[0], sizeof(device.mount_points[0]), "/media/user/USB");
    /* volume_path deliberately left empty - mount_points[] alone (a
     * display-only field) must not be enough. */
    USBS_CHECK(!device_has_valid_mount_point(&device));

    usbs_device_init(&device);
    device.mount_point_count = 1;
    snprintf(device.mount_points[0], sizeof(device.mount_points[0]), "/");
    snprintf(device.volume_path, sizeof(device.volume_path), "/");
    USBS_CHECK(!device_has_valid_mount_point(&device)); /* the explicit "/" guard */

    usbs_device_init(&device);
    device.mount_point_count = 1;
    snprintf(device.mount_points[0], sizeof(device.mount_points[0]), "/media/user/USB");
    snprintf(device.volume_path, sizeof(device.volume_path), "/media/user/USB/");
    USBS_CHECK(device_has_valid_mount_point(&device)); /* the real, valid shape */
}

int main(void)
{
    test_simple_get_no_headers();
    test_multiple_headers_last_one_not_dropped();
    test_header_lookup_is_case_insensitive();
    test_header_value_leading_space_trimmed();
    test_post_with_body_head_len_excludes_body();
    test_no_content_length_means_zero_not_error();
    test_missing_blank_line_is_rejected();
    test_malformed_request_line_is_rejected();
    test_query_get();
    test_device_has_valid_mount_point();

    return USBS_TEST_RESULT();
}
