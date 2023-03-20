#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include "defs.h"

#define ARP_MAX_PENDING_REQUESTS 32
#define ARP_TRANSLATION_TABLE_SIZE 128

typedef enum {
    ARP_RESOLUTION_OK,
    ARP_RESOLUTION_FAILED,
    ARP_RESOLUTION_TIMEOUT,
} arp_resolution_status_t;

typedef struct arp_translation_table_entry_t arp_translation_table_entry_t;
struct arp_translation_table_entry_t {
    arp_translation_table_entry_t *prev;
    arp_translation_table_entry_t *next;
    mac_address_t mac;
    ip_address_t  ip;
    uint64_t timeout;
};

typedef struct {
    uint64_t time;
    arp_translation_table_entry_t *used_list_head;
    arp_translation_table_entry_t *used_list_tail;
    arp_translation_table_entry_t *free_list;
    arp_translation_table_entry_t entries[ARP_TRANSLATION_TABLE_SIZE];
} arp_translation_table_t;

typedef struct arp_pending_request_t arp_pending_request_t;
struct arp_pending_request_t {
    arp_pending_request_t *prev;
    arp_pending_request_t *next;
    ip_address_t ip;
    uint64_t timeout;
    void *callback_data;
    void (*callback)(void*, arp_resolution_status_t status, mac_address_t);
};

typedef struct __attribute__((__packed__)) {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t operation_type;
    mac_address_t sender_hardware_address;
    ip_address_t  sender_protocol_address;
    mac_address_t target_hardware_address;
    ip_address_t  target_protocol_address;
} arp_packet_t;

static_assert(offsetof(arp_packet_t, hardware_type)  == 0);
static_assert(offsetof(arp_packet_t, protocol_type)  == 2);
static_assert(offsetof(arp_packet_t, hardware_len)   == 4);
static_assert(offsetof(arp_packet_t, protocol_len)   == 5);
static_assert(offsetof(arp_packet_t, operation_type) == 6);
static_assert(offsetof(arp_packet_t, sender_hardware_address) == 8);
static_assert(offsetof(arp_packet_t, sender_protocol_address) == 14);
static_assert(offsetof(arp_packet_t, target_hardware_address) == 18);
static_assert(offsetof(arp_packet_t, target_protocol_address) == 24);
static_assert(sizeof(arp_packet_t) == 28);

typedef struct {

    uint64_t time;
    uint64_t cache_timeout;
    uint64_t request_timeout;

    arp_packet_t *output;

    void *send_data;
    void (*send)(void *send_data, mac_address_t dest_mac);

    ip_address_t  self_ip;
    mac_address_t self_mac;
    arp_translation_table_t table;

    arp_pending_request_t *pending_request_free_list;
    arp_pending_request_t *pending_request_used_list;
    arp_pending_request_t *pending_request_used_tail;
    arp_pending_request_t pending_request_pool[ARP_MAX_PENDING_REQUESTS];
} arp_state_t;

typedef enum {
    ARP_PROCESS_RESULT_HWARENOTSUPP,
    ARP_PROCESS_RESULT_PROTONOTSUPP,
    ARP_PROCESS_RESULT_INVALID,
    ARP_PROCESS_RESULT_OK,
} arp_process_result_t;

void arp_init(arp_state_t *state, ip_address_t ip, mac_address_t mac, void *send_data, void (*send)(void*, mac_address_t));
void arp_free(arp_state_t *state);
arp_process_result_t arp_process_packet(arp_state_t *state, const void *packet, size_t len);
void arp_resolve_mac(arp_state_t *state, ip_address_t ip, void *userp, void (*callback)(void*, arp_resolution_status_t, mac_address_t));
void arp_seconds_passed(arp_state_t *state, size_t seconds);
void arp_change_output_buffer(arp_state_t *state, void *ptr, size_t max);