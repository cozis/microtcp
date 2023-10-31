#include <string.h>
#include "endian.h"
#include "icmp.h"

#ifdef ICMP_DEBUG
#include <stdio.h>
#define ICMP_DEBUG_LOG(fmt, ...) fprintf(stderr, "ICMP :: " fmt "\n", ## __VA_ARGS__)
#else
#define ICMP_DEBUG_LOG(...)
#endif

typedef enum {
    ICMP_TYPE_ECHO_REPLY = 0,
    ICMP_TYPE_ECHO_REQUEST  = 8,
} icmp_type_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id_no;
    uint16_t seq_no;
    uint8_t data[];
} icmp_message_echo_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t data[];
} icmp_message_generic_t;

void icmp_change_output_buffer(icmp_state_t *state, void *ptr, size_t len)
{
    state->output_ptr = ptr;
    state->output_len = len;
}

void icmp_init(icmp_state_t *state, void *send_data, void (*send)(void*, ip_address_t, size_t))
{
    state->output_ptr = NULL;
    state->output_len = 0;
    state->send_data = send_data;
    state->send = send;
}

void icmp_free(icmp_state_t *state)
{
    (void) state;
}

static uint16_t calculate_checksum_icmp(const void *src, size_t len)
{
    assert((len & 1) == 0);

    const uint16_t *src2 = src;

    uint32_t sum = 0xffff;
    for (size_t i = 0; i < len/2; i++) {
        sum += net_to_cpu_u16(src2[i]);
        if (sum > 0xffff)
            sum -= 0xffff;
    }

    return cpu_to_net_u16(~sum);
}

void icmp_process_packet(icmp_state_t *state, ip_address_t ip, const void *src, size_t len)
{
    if (len < sizeof(icmp_message_generic_t))
        return;

    const icmp_message_generic_t *packet = src;
    
    switch (packet->type) {
        case ICMP_TYPE_ECHO_REQUEST:
        {
            if (len < sizeof(icmp_message_echo_t))
                return;
            
            const icmp_message_echo_t *echo_request = (icmp_message_echo_t*) packet;
                        
            if (calculate_checksum_icmp(echo_request, len)) {
                ICMP_DEBUG_LOG("Dropping ICMP message with invalid checksum");
                return;
            }
            
            if (state->output_ptr == NULL || state->output_len < len) {
                ICMP_DEBUG_LOG("Ignoring ECHO REQUEST because the output buffer "
                               "is too small for an ECHO REPLY (have %d, need %d)", 
                               (int) state->output_len, (int) len);
                return;
            }

            icmp_message_echo_t *echo_reply = state->output_ptr;

            echo_reply->type = ICMP_TYPE_ECHO_REPLY;
            echo_reply->code = 0;
            echo_reply->checksum = 0;
            echo_reply->id_no  = echo_request->id_no;
            echo_reply->seq_no = echo_request->seq_no;
            memcpy(echo_reply->data, echo_request->data, len - sizeof(icmp_message_echo_t));

            echo_reply->checksum = calculate_checksum_icmp(echo_reply, len);
            
            ICMP_DEBUG_LOG("Replying to echo request");
            state->send(state->send_data, ip, len);
        }
        break;

        default:
        // Unsupported ICMP message
        break;
    }
}