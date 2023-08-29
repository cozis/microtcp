#include <string.h>

#ifndef MICROTCP_AMALGAMATION
#include "endian.h"
#include "ip.h"
#endif

#ifdef IP_DEBUG
#include <stdio.h>
#define IP_DEBUG_LOG(fmt, ...) do { fprintf(stderr, "IP :: " fmt "\n", ## __VA_ARGS__); } while (0);
#else
#define IP_DEBUG_LOG(...) do { } while (0);
#endif


static uint16_t calculate_checksum_ip(const void *src, size_t len)
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

static ip_plugged_protocol_t *
find_protocol_with_id(ip_state_t *ip_state, uint8_t protocol)
{
    for (size_t i = 0; i < ip_state->plugged_protocols_count; i++)
        if (protocol == ip_state->plugged_protocols[i].protocol)
            return ip_state->plugged_protocols + i;
    return NULL;
}

bool ip_plug_protocol(ip_state_t *ip_state, uint8_t protocol, 
                      void *data, void (*process_packet)(void *data, ip_address_t sender, const void *packet, size_t len))
{
    if (protocol == IP_PROTOCOL_ICMP)
        return false; // Can't override default ICMP module

    ip_plugged_protocol_t *p = find_protocol_with_id(ip_state, protocol);

    if (!p) {
        if (ip_state->plugged_protocols_count == IP_PLUGGED_PROTOCOLS_MAX)
            return false;
        p = ip_state->plugged_protocols + ip_state->plugged_protocols_count++;
    }

    p->protocol = protocol;
    p->data = data;
    p->process_packet = process_packet;

    return true;
}

static bool is_packet_one_of_more_fragments(const ip_packet_t *packet)
{
    size_t offset = net_to_cpu_u16(packet->fragment_offset) & 0x1FFF;
    bool more_fragments = net_to_cpu_u16(packet->fragment_offset) & 0x2000;
    return more_fragments || offset;
}

static void send_icmp_packet(void *data, ip_address_t ip, size_t len)
{
    ip_state_t *ip_state = data;

    // The data was written in the output buffer
    ip_packet_t *packet = ip_state->output_ptr; // This changes every iteration

    int version = 4;
    int header_length = 5;
    if (cpu_is_little_endian()) {
        packet->header_length_or_version1 = header_length;
        packet->header_length_or_version2 = version;
    } else {
        packet->header_length_or_version1 = version;
        packet->header_length_or_version2 = header_length;
    }
    packet->type_of_service = 0; // ???
    packet->total_length = cpu_to_net_u16(sizeof(ip_packet_t) + len);
    packet->id = ip_state->next_id++;
    packet->fragment_offset = 0; // ???
    packet->time_to_live = 32; // ???
    packet->protocol = IP_PROTOCOL_ICMP;
    packet->checksum = 0; // Temporary value
    packet->src_ip = ip_state->ip;
    packet->dst_ip = ip;

    packet->checksum = calculate_checksum_ip((uint16_t*) packet, 4 * header_length);

    ip_state->send(ip_state->send_data, ip, sizeof(ip_packet_t) + len);
}

void ip_init(ip_state_t *state, 
             ip_address_t ip, 
             void *send_data,
             void (*send)(void*, ip_address_t, size_t))
{
    state->ip = ip;
    state->next_id = 0;
    state->send_data = send_data;
    state->send = send;
    state->output_ptr = NULL;
    state->output_max = 0;
    state->plugged_protocols_count = 0;
    icmp_init(&state->icmp_state, state, send_icmp_packet);
}

void ip_free(ip_state_t *ip_state)
{
    icmp_free(&ip_state->icmp_state);
}

void ip_change_output_buffer(ip_state_t *state, void *ptr, size_t max)
{
    state->output_ptr = ptr;
    state->output_max = max;
    icmp_change_output_buffer(&state->icmp_state, (ip_packet_t*) ptr + 1, max - sizeof(ip_packet_t));
}

void ip_ms_passed(ip_state_t *state, size_t ms)
{
    (void) state;
    (void) ms;
}

int ip_send(ip_state_t *state, ip_protocol_t protocol, 
            ip_address_t dst, bool no_fragm, 
            const void *src, size_t len)
{
    const slice_t slices[] = {{src, len}};
    return ip_send_2(state, protocol, dst, no_fragm, slices, COUNT(slices));
}

int ip_send_2(ip_state_t *state, ip_protocol_t protocol, ip_address_t dst, 
              bool no_fragm, const slice_t *slices, size_t num_slices)
{
    size_t total_len = 0;
    for (size_t i = 0; i < num_slices; i++)
        total_len += slices[i].len;

    size_t managed_payload = 0;

    while (managed_payload < total_len && (managed_payload == 0 || !no_fragm)) {

        if (state->output_ptr == NULL) {
            // Lower layers of the network stack didn't specify an output
            // buffer region. This may be because no memory is available.

            // If at least one byte was sent, return gracefully. 
            // If no byte was sent return an error to the caller.
            if (managed_payload > 0)
                break;
            else
                return -1;
        }

        if (state->output_max <= sizeof(ip_packet_t))
            // Output buffer provided by the lower layers of the stack
            // isn't big enough for an IP packet containing a single byte.
            return -1;

        size_t current_payload_limit = state->output_max - sizeof(ip_packet_t);
        size_t remaining_payload = total_len - managed_payload;
        size_t considered_payload = MIN(current_payload_limit, remaining_payload);

        ip_packet_t *packet = state->output_ptr; // This changes every iteration
        
        int version = 4;
        int header_length = 5;
        if (cpu_is_little_endian()) {
            packet->header_length_or_version1 = header_length;
            packet->header_length_or_version2 = version;
        } else {
            packet->header_length_or_version1 = version;
            packet->header_length_or_version2 = header_length;
        }
        packet->type_of_service = 0; // ???
        packet->total_length = cpu_to_net_u16(sizeof(ip_packet_t) + considered_payload);
        packet->id = state->next_id++;
        packet->fragment_offset = 0; // ???
        packet->time_to_live = 32; // ???
        packet->protocol = protocol;
        packet->checksum = 0; // Temporary value
        packet->src_ip = state->ip;
        packet->dst_ip = dst;

        size_t copied_bytes = 0;
        size_t copied_slices = 0;
        while (copied_bytes < considered_payload) {
            size_t copying = MIN(slices[copied_slices].len, considered_payload - copied_bytes);
            memcpy(packet->payload + copied_bytes, slices[copied_slices].ptr, copying);
            copied_bytes += copying;
            copied_slices++;
        }

        packet->checksum = calculate_checksum_ip((uint16_t*) packet, 4 * header_length);

        // Sending updates the [state->output_ptr] and [state->output_len]
        state->send(state->send_data, dst, sizeof(ip_packet_t) + considered_payload);

        managed_payload += considered_payload;
    }

    return managed_payload;
}

void ip_process_packet(ip_state_t *ip_state, const void *packet, size_t len)
{
    if (len < sizeof(ip_packet_t))
        return;

    const ip_packet_t *packet2 = packet;

    int version;
    int header_length;

    if (cpu_is_little_endian()) {
        header_length = packet2->header_length_or_version1;
        version       = packet2->header_length_or_version2;
    } else {
        version       = packet2->header_length_or_version1;
        header_length = packet2->header_length_or_version2;
    }

    if (version != 4 || header_length < 5) {
        IP_DEBUG_LOG("Only supported IPv4 (received %d) with no options", version);
        return;
    }

    size_t option_count = header_length - sizeof(ip_packet_t)/4;
    if (option_count > 0) {
        // TODO: Handle IP options
        return;
    }
    
    if (is_packet_one_of_more_fragments(packet2)) {
        IP_DEBUG_LOG("Not supporting IP fragmentation");
        return;
    }

    if (calculate_checksum_ip((uint16_t*) packet2, 4 * header_length)) {
        IP_DEBUG_LOG("Dropping IP packet with invalid checksum");
        return;
    }
/*
    IP_DEBUG_LOG("Received packet for %d.%d.%d.%d (I'm %d.%d.%d.%d)", 
        ((uint8_t*) &packet2->dst_ip)[0],
        ((uint8_t*) &packet2->dst_ip)[1],
        ((uint8_t*) &packet2->dst_ip)[2],
        ((uint8_t*) &packet2->dst_ip)[3],
        ((uint8_t*) &ip_state->ip)[0],
        ((uint8_t*) &ip_state->ip)[1],
        ((uint8_t*) &ip_state->ip)[2],
        ((uint8_t*) &ip_state->ip)[3]);
*/
    if (packet2->dst_ip != ip_state->ip) {
//        IP_DEBUG_LOG("Packet not for me");
        return;
    }

    ip_plugged_protocol_t *handler = find_protocol_with_id(ip_state, packet2->protocol);

    const void *packet3_ptr = packet2+1;
    size_t      packet3_len = net_to_cpu_u16(packet2->total_length) - sizeof(ip_packet_t);

    if (handler)
        handler->process_packet(handler->data, packet2->src_ip, packet3_ptr, packet3_len);
    else if (packet2->protocol == IP_PROTOCOL_ICMP)
        icmp_process_packet(&ip_state->icmp_state, packet2->src_ip, packet3_ptr, packet3_len);
    else
        IP_DEBUG_LOG("Unsupported protocol %d", packet2->protocol);
}
