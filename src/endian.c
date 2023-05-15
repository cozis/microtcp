#include <stdbool.h>
#include "endian.h"

static bool cpu_is_little_endian(void)
{
    uint16_t x = 1;
    return *((uint8_t*) &x);
}

static uint16_t invert_byte_order_u16(uint32_t n)
{
    return (n >> 8) 
         | (n << 8);
}

static uint32_t invert_byte_order_u32(uint32_t n)
{
    return ((n >> 24) & 0x000000FF)
         | ((n >>  8) & 0x0000FF00)
         | ((n <<  8) & 0x00FF0000)
         | ((n << 24) & 0xFF000000);
}

uint16_t net_to_cpu_u16(uint16_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u16(n);
    return n;
}

uint32_t net_to_cpu_u32(uint32_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u32(n);
    return n;
}

uint16_t cpu_to_net_u16(uint16_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u16(n);
    return n;
}

uint32_t cpu_to_net_u32(uint32_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u32(n);
    return n;
}

