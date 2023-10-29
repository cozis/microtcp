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

typedef struct {
    void  *ptr;
    size_t len;
} slice_t;

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define ABS(X) ((X) < 0 ? -(X) : (X))
#define COUNT(X) ((int) (sizeof(X) / sizeof((X)[0])))
#define SLICE(X) ((slice_t) {.ptr=&(X), .len=sizeof(X)})

#define UNPACK_IP(IP)    \
    ((IP) >> 0  & 0xff), \
    ((IP) >> 8  & 0xff), \
    ((IP) >> 16 & 0xff), \
    ((IP) >> 24 & 0xff)

#endif /* MICROTCP_DEFS_H */