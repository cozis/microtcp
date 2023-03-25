#ifndef MICROTCP_DEFS_H
#define MICROTCP_DEFS_H
#include <stdint.h>
#include <assert.h> // static_assert

typedef struct {
    uint8_t data[6];
} mac_address_t;

typedef uint32_t ip_address_t;

static_assert(sizeof(mac_address_t) == 6);
static_assert(sizeof(ip_address_t) == 4);

#define MAC_ZERO      (mac_address_t) {.data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
#define MAC_BROADCAST (mac_address_t) {.data = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

#endif /* MICROTCP_DEFS_H */