#include <stddef.h>
#include "defs.h"

typedef struct {
    void  *output_ptr;
    size_t output_len;
    void *send_data;
    void (*send)(void *send_data, ip_address_t ip, size_t len);
} icmp_state_t;

void icmp_init(icmp_state_t *state, void *send_data, void (*send)(void*, ip_address_t, size_t));
void icmp_free(icmp_state_t *state);
void icmp_process_packet(icmp_state_t *state, ip_address_t ip, const void *src, size_t len);
void icmp_change_output_buffer(icmp_state_t *state, void *ptr, size_t len);
