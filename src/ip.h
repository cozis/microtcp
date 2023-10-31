#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "defs.h"
#include "icmp.h"

#define IP_PLUGGED_PROTOCOLS_MAX 4

typedef struct {
    uint8_t header_length_or_version1: 4; // Header length when little endian
    uint8_t header_length_or_version2: 4; // Header length when big endian
    uint8_t  type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t  time_to_live;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    char     payload[];
} __attribute__((packed)) ip_packet_t;
static_assert(sizeof(ip_packet_t) == 20);

typedef enum {
    IP_PROTOCOL_ICMP = 1,
    IP_PROTOCOL_TCP  = 6,
    IP_PROTOCOL_UDP  = 17,
} ip_protocol_t;

typedef struct {
    uint8_t protocol;
    void *data;
    void (*process_packet)(void*, ip_address_t, const void*, size_t);
} ip_plugged_protocol_t;

typedef struct {
    ip_address_t ip;
    
    uint32_t next_id;

    void  *output_ptr;
    size_t output_max;

    icmp_state_t icmp_state;

    void *send_data;
    void (*send)(void*, ip_address_t, size_t);

    size_t plugged_protocols_count;
    ip_plugged_protocol_t plugged_protocols[IP_PLUGGED_PROTOCOLS_MAX];
} ip_state_t;

void ip_ms_passed(ip_state_t *state, size_t ms);
void ip_change_output_buffer(ip_state_t *state, void *ptr, size_t max);
void ip_init(ip_state_t *state, ip_address_t ip, void *send_data, void (*send)(void*, ip_address_t, size_t));
void ip_free(ip_state_t *state);
int  ip_send(ip_state_t *state, ip_protocol_t protocol, ip_address_t dst, bool no_fragm, const void *src, size_t len);
int  ip_send_2(ip_state_t *state, ip_protocol_t protocol, ip_address_t dst, bool no_fragm, const slice_t *slices, size_t num_slices);
void ip_process_packet(ip_state_t *state, const void *packet, size_t len);
bool ip_plug_protocol(ip_state_t *ip_state, uint8_t protocol, void *data, void (*process_packet)(void *data, ip_address_t sender, const void *packet, size_t len));
