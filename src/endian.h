#include <stdint.h>
#include <stdbool.h>

bool cpu_is_little_endian(void);
uint16_t net_to_cpu_u16(uint16_t n);
uint32_t net_to_cpu_u32(uint32_t n);
uint16_t cpu_to_net_u16(uint16_t n);
uint32_t cpu_to_net_u32(uint32_t n);
