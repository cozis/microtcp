#include <stdio.h>
#include <string.h>
#include "test_arp_util.h"

void arp_testcase_init(arp_testcase_t *tcase, 
                       const char mac[static 6], 
                       const char ip[static 4])
{
    memcpy(&tcase->self_ip, ip, 4);
    memcpy(&tcase->self_mac, mac, 6);
    tcase->failed = false;
    tcase->count = 0;
}

void arp_testcase_free(arp_testcase_t *tcase)
{
    (void) tcase;
}

void arp_testcase_send(arp_testcase_t *tcase, const char data[static sizeof(arp_packet_t)])
{
    if (tcase->failed)
        return;

    if (tcase->count == ARP_TESTCASE_MAX_PACKETS) {
        tcase->failed = true;
        return;
    }

    arp_testcase_packet_t *packet = tcase->packets + tcase->count;
    packet->sender = ARP_TESTCASE_SENDER_PEER;
    packet->data = data;

    tcase->count++;
}

void arp_testcase_recv(arp_testcase_t *tcase, const char data[static sizeof(arp_packet_t)])
{
    if (tcase->failed)
        return;

    if (tcase->count == ARP_TESTCASE_MAX_PACKETS) {
        tcase->failed = true;
        return;
    }

    arp_testcase_packet_t *packet = tcase->packets + tcase->count;
    packet->sender = ARP_TESTCASE_SENDER_HOST;
    packet->data = data;

    tcase->count++;
}

typedef struct {
    char *msg;
    size_t msgmax;
    const arp_packet_t *output;
    const arp_testcase_t *tcase;
    size_t cursor;
    bool output_as_expected;
    bool aborted_while_checking_sent_packets;
} testcase_contex_t;

static void send_packet(void *data, mac_address_t dest)
{
    (void) dest; // Is this ok?

    testcase_contex_t *context = data;

    context->aborted_while_checking_sent_packets = false;

    if (context->cursor == context->tcase->count) {
        snprintf(context->msg, context->msgmax, "ARP module sent an unexpected packet");
        context->output_as_expected = false;
        return;
    }

    const arp_testcase_packet_t *packet = context->tcase->packets + context->cursor;

    if (packet->sender != ARP_TESTCASE_SENDER_HOST) {
        snprintf(context->msg, context->msgmax, "ARP module sent an unexpected packet");
        context->output_as_expected = false;
        return;
    }
    context->cursor++;

    if (!memcmp(context->output, packet->data, sizeof(arp_packet_t)))
        context->output_as_expected = true;
    else {
        snprintf(context->msg, context->msgmax, "ARP module sent a different packet than expected");
        context->output_as_expected = false;
    }
}

arp_testcase_result_t arp_testcase_run(arp_testcase_t tcase, char *msg, size_t msgmax)
{
    if (tcase.failed)
        return ARP_TESTCASE_ABORTED;

    arp_packet_t output;

    testcase_contex_t context = {
        .output = &output,
        .tcase = &tcase,
        .cursor = 0,
        .msg = msg,
        .msgmax = msgmax,
    };

    if (msgmax > 0)
        msg[0] = '\0';

    arp_state_t state;
    arp_init(&state, tcase.self_ip, tcase.self_mac, &context, send_packet);
    arp_change_output_buffer(&state, &output, sizeof(output));

    while (context.cursor < tcase.count) {
        
        arp_testcase_packet_t *packet = tcase.packets + context.cursor++;

        if (packet->sender != ARP_TESTCASE_SENDER_PEER) {
            snprintf(msg, msgmax, "ARP module didn't send packet");
            return ARP_TESTCASE_FAILED;
        }
        
        // Initialize these
        context.output_as_expected = true;
        context.aborted_while_checking_sent_packets = false;

        arp_process_result_t status = arp_process_packet(&state, packet->data, sizeof(arp_packet_t));
        
        (void) status; // Not useful yet

        // Before this point the arp_process_packet will have
        // sent some packets that were validated in the send_packet
        // callback. If the testcase didn't fail, the next
        // packet in the list will be sent by the peer.
        if (context.aborted_while_checking_sent_packets)
            return ARP_TESTCASE_ABORTED;
        if (!context.output_as_expected)
            return ARP_TESTCASE_FAILED;
    }

    arp_free(&state);
    return ARP_TESTCASE_PASSED;
}