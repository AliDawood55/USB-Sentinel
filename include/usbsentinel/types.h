/*
 * USB Sentinel - core scalar types.
 *
 * This header must stay free of platform headers. Nothing here may include
 * <windows.h>; see ARCHITECTURE.md for the layering rule.
 */
#ifndef USBSENTINEL_TYPES_H
#define USBSENTINEL_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef bool     usbs_bool;
typedef uint8_t  usbs_u8;
typedef uint16_t usbs_u16;
typedef uint32_t usbs_u32;
typedef uint64_t usbs_u64;
typedef int64_t  usbs_i64;

/* Silences /W4 C4100 on intentionally unused parameters. */
#define USBS_UNUSED(x) ((void)(x))

#define USBS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#endif /* USBSENTINEL_TYPES_H */
