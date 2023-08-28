#include <stdio.h>
#include <string.h>
#include "../src/utils.c"
#include "../src/endian.c"
#include "../src/arp.c"

/*
    BLACK BOX TEST CASES
        
        A) Peer requests host's MAC given its IP and host 
           replies.
        
        B) Peer requests host's non MAC level 2 address
           given its IP and host doesn't reply because it 
           only supports MAC.
        
        C) Peer requests host's MAC address given its non
           IP level 3 address and host doesn't reply
           because it only supports IP.
        
        D) Peer requests host's MAC given its IP, but the
           MAC address length field isn't 6, therefore
           host doesn't reply.
        
        E) Peer requests host's MAC given its IP, but the
           IP address length field isn't 4, therefore host
           doesn't reply.
        
        F) Peer sends a request/reply that doesn't refer
           to host and is from a sender with IP never seen
           by the host (no entry in the translation table).
           It's expected that no entry is added to the
           translation table.

        G) Peer sends a request/reply that doesn't refer
           to host but is from a sender with IP already
           in the ARP translation table, therefore is
           expected that host updates the entry.

        H) Program queries the ARP module for a MAC that
           isn't cached, therefore an ARP request is
           expected to be generated and, when replied to,
           the ARP module is expected to resolve the
           program's query.

        I) Program queries the ARP module for a MAC that's
           cached, therefore the ARP module is expected to
           resolve it without sending packets.
*/

typedef enum {
    TEST_PASSED,
    TEST_FAILED,
    TEST_ABORTED,
} test_result_t;

#define OUTPUT_QUEUE_SIZE 8

typedef struct {
    arp_state_t *state;
    arp_packet_t queue[OUTPUT_QUEUE_SIZE];
    int          count;
    int          oflow;
} output_queue_t;

static void send_arp_packet_callback(void *data, mac_address_t mac)
{
    output_queue_t *oq = (output_queue_t*) data;
    if (oq->count == OUTPUT_QUEUE_SIZE)
        oq->oflow++;
    else {
        oq->count++;
        if (oq->count == OUTPUT_QUEUE_SIZE)
            arp_change_output_buffer(oq->state, NULL, 0);
        else
            arp_change_output_buffer(oq->state, oq->queue+oq->count, sizeof(arp_packet_t));
    }
}

test_result_t test_arp_bb_A(char *msg, size_t msgmax)
{
    // Addresses of the packets that will be sent towards
    // the ARP module
    const char  net_ip_str[] = "10.0.0.5";
    const char net_mac_str[] = "00:34:56:34:f5:4f";

    // Addresses of the ARP module
    const char  ip_str[] = "10.0.0.4";
    const char mac_str[] = "56:34:f5:4d:4f:44";
        
    // Parse the addresses to binary form
    ip_address_t  ip,  net_ip;
    mac_address_t mac, net_mac;
    if (!parse_mac(mac_str, sizeof(mac_str)-1, &mac) ||
        !parse_ip(ip_str, &ip) ||
        !parse_mac(net_mac_str, sizeof(net_mac_str)-1, &net_mac) ||
        !parse_ip(net_ip_str, &net_ip)) {
        snprintf(msg, msgmax, "Couldn't parse IP and MAC strings");
        return TEST_ABORTED;
    }

    // Set up the module with the output queue
    arp_state_t state;
    output_queue_t oq = {.state=&state, .count=0, .oflow=0}; // Buffer where replies and requests will be stored
                                                             // by the ARP module
    arp_init(&state, ip, mac, &oq, send_arp_packet_callback);
    arp_change_output_buffer(&state, oq.queue, sizeof(arp_packet_t));

    // Build the request
    arp_packet_t request = {
        .hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET),
        .protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP),
        .hardware_len  = 6,
        .protocol_len  = 4,
        .operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST),
        .sender_hardware_address = net_mac,
        .sender_protocol_address = net_ip,
        .target_hardware_address = MAC_ZERO,
        .target_protocol_address = ip,
    };

    // Send the request
    arp_process_result_t res;
    res = arp_process_packet(&state, &request, sizeof(arp_packet_t));
    switch (res) {
        case ARP_PROCESS_RESULT_HWARENOTSUPP:
        case ARP_PROCESS_RESULT_PROTONOTSUPP:
        case ARP_PROCESS_RESULT_INVALID:
        snprintf(msg, msgmax, "ARP module couldn't process request");
        return TEST_FAILED;

        case ARP_PROCESS_RESULT_OK:
        break;
    }

    // Make sure that the module replies one time and one time only
    if (oq.count == 0) {
        // The ARP module sent no reply given
        // our request.
        snprintf(msg, msgmax, "ARP module didn't reply");
        return TEST_FAILED;
    }
    if (oq.count > 1) {
        // Sent too many replies
        snprintf(msg, msgmax, "ARP module replied too many times");
        return TEST_FAILED;
    }

    // Check that the reply has the right content
    arp_packet_t *reply = oq.queue;
    if (net_to_cpu_u16(reply->hardware_type)  != ARP_HARDWARE_ETHERNET ||
        net_to_cpu_u16(reply->protocol_type)  != ARP_PROTOCOL_IP ||
        net_to_cpu_u16(reply->operation_type) != ARP_OPERATION_REPLY ||
        memcmp(&reply->sender_hardware_address, &mac, sizeof(mac_address_t)) ||
        memcmp(&reply->sender_protocol_address, &ip, sizeof(ip_address_t))  ||
        memcmp(&reply->target_hardware_address, &net_mac, sizeof(mac_address_t)) ||
        memcmp(&reply->target_protocol_address, &net_ip, sizeof(ip_address_t))) {
        // Unexpected reply
        snprintf(msg, msgmax, "ARP module sent an unexpected reply");
        return TEST_FAILED;
    }

    return TEST_PASSED;
}

test_result_t test_arp_bb_B(char *msg, size_t msgmax)
{
    // Addresses of the packets that will be sent towards
    // the ARP module
    const char  net_ip_str[] = "10.0.0.5";
    const char net_mac_str[] = "00:34:56:34:f5:4f";

    // Addresses of the ARP module
    const char  ip_str[] = "10.0.0.4";
    const char mac_str[] = "56:34:f5:4d:4f:44";
        
    // Parse the addresses to binary form
    ip_address_t  ip,  net_ip;
    mac_address_t mac, net_mac;
    if (!parse_mac(mac_str, sizeof(mac_str)-1, &mac) ||
        !parse_ip(ip_str, &ip) ||
        !parse_mac(net_mac_str, sizeof(net_mac_str)-1, &net_mac) ||
        !parse_ip(net_ip_str, &net_ip)) {
        snprintf(msg, msgmax, "Couldn't parse IP and MAC strings");
        return TEST_ABORTED;
    }

    // Set up the module with the output queue
    arp_state_t state;
    output_queue_t oq = {.state=&state, .count=0, .oflow=0}; // Buffer where replies and requests will be stored
                                                             // by the ARP module
    arp_init(&state, ip, mac, &oq, send_arp_packet_callback);
    arp_change_output_buffer(&state, oq.queue, sizeof(arp_packet_t));

    // Build the request
    arp_packet_t request = {
        .hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET)+1, // Some value other than ETHERNET
        .protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP),
        .hardware_len  = 6,
        .protocol_len  = 4,
        .operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST),
        .sender_hardware_address = net_mac,
        .sender_protocol_address = net_ip,
        .target_hardware_address = MAC_ZERO,
        .target_protocol_address = ip,
    };

    // Send the request
    arp_process_result_t res;
    res = arp_process_packet(&state, &request, sizeof(arp_packet_t));
    switch (res) {
        case ARP_PROCESS_RESULT_HWARENOTSUPP:
        break;

        case ARP_PROCESS_RESULT_PROTONOTSUPP:
        case ARP_PROCESS_RESULT_INVALID:
        snprintf(msg, msgmax, "ARP module couldn't process request");
        return TEST_FAILED;

        case ARP_PROCESS_RESULT_OK:
        snprintf(msg, msgmax, "ARP module processed a request for an hardware type it didn't support");
        return TEST_FAILED;
    }

    if (oq.count > 0) {
        // Sent replies
        snprintf(msg, msgmax, "ARP module replied even though it failed to process the request");
        return TEST_FAILED;
    }

    return TEST_PASSED;
}

test_result_t test_arp_bb_C(char *msg, size_t msgmax)
{
    // Addresses of the packets that will be sent towards
    // the ARP module
    const char  net_ip_str[] = "10.0.0.5";
    const char net_mac_str[] = "00:34:56:34:f5:4f";

    // Addresses of the ARP module
    const char  ip_str[] = "10.0.0.4";
    const char mac_str[] = "56:34:f5:4d:4f:44";
        
    // Parse the addresses to binary form
    ip_address_t  ip,  net_ip;
    mac_address_t mac, net_mac;
    if (!parse_mac(mac_str, sizeof(mac_str)-1, &mac) ||
        !parse_ip(ip_str, &ip) ||
        !parse_mac(net_mac_str, sizeof(net_mac_str)-1, &net_mac) ||
        !parse_ip(net_ip_str, &net_ip)) {
        snprintf(msg, msgmax, "Couldn't parse IP and MAC strings");
        return TEST_ABORTED;
    }

    // Set up the module with the output queue
    arp_state_t state;
    output_queue_t oq = {.state=&state, .count=0, .oflow=0}; // Buffer where replies and requests will be stored
                                                             // by the ARP module
    arp_init(&state, ip, mac, &oq, send_arp_packet_callback);
    arp_change_output_buffer(&state, oq.queue, sizeof(arp_packet_t));

    // Build the request
    arp_packet_t request = {
        .hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET),
        .protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP)+1, // Some value other than IP
        .hardware_len  = 6,
        .protocol_len  = 4,
        .operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST),
        .sender_hardware_address = net_mac,
        .sender_protocol_address = net_ip,
        .target_hardware_address = MAC_ZERO,
        .target_protocol_address = ip,
    };

    // Send the request
    arp_process_result_t res;
    res = arp_process_packet(&state, &request, sizeof(arp_packet_t));
    switch (res) {
        
        case ARP_PROCESS_RESULT_PROTONOTSUPP:
        break;

        case ARP_PROCESS_RESULT_HWARENOTSUPP:
        case ARP_PROCESS_RESULT_INVALID:
        snprintf(msg, msgmax, "ARP module couldn't process request");
        return TEST_FAILED;

        case ARP_PROCESS_RESULT_OK:
        snprintf(msg, msgmax, "ARP module processed a request for a protocol type it didn't support");
        return TEST_FAILED;
    }

    if (oq.count > 0) {
        // Sent replies
        snprintf(msg, msgmax, "ARP module replied even though it failed to process the request");
        return TEST_FAILED;
    }

    return TEST_PASSED;
}


test_result_t test_arp_bb_D(char *msg, size_t msgmax)
{
    // Addresses of the packets that will be sent towards
    // the ARP module
    const char  net_ip_str[] = "10.0.0.5";
    const char net_mac_str[] = "00:34:56:34:f5:4f";

    // Addresses of the ARP module
    const char  ip_str[] = "10.0.0.4";
    const char mac_str[] = "56:34:f5:4d:4f:44";
        
    // Parse the addresses to binary form
    ip_address_t  ip,  net_ip;
    mac_address_t mac, net_mac;
    if (!parse_mac(mac_str, sizeof(mac_str)-1, &mac) ||
        !parse_ip(ip_str, &ip) ||
        !parse_mac(net_mac_str, sizeof(net_mac_str)-1, &net_mac) ||
        !parse_ip(net_ip_str, &net_ip)) {
        snprintf(msg, msgmax, "Couldn't parse IP and MAC strings");
        return TEST_ABORTED;
    }

    // Set up the module with the output queue
    arp_state_t state;
    output_queue_t oq = {.state=&state, .count=0, .oflow=0}; // Buffer where replies and requests will be stored
                                                             // by the ARP module
    arp_init(&state, ip, mac, &oq, send_arp_packet_callback);
    arp_change_output_buffer(&state, oq.queue, sizeof(arp_packet_t));

    // Build the request
    arp_packet_t request = {
        .hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET),
        .protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP),
        .hardware_len  = 6+1, // Something other than the correct length
        .protocol_len  = 4,
        .operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST),
        .sender_hardware_address = net_mac,
        .sender_protocol_address = net_ip,
        .target_hardware_address = MAC_ZERO,
        .target_protocol_address = ip,
    };

    // Send the request
    arp_process_result_t res;
    res = arp_process_packet(&state, &request, sizeof(arp_packet_t));
    switch (res) {

        case ARP_PROCESS_RESULT_INVALID:
        break;

        case ARP_PROCESS_RESULT_HWARENOTSUPP:
        case ARP_PROCESS_RESULT_PROTONOTSUPP:
        snprintf(msg, msgmax, "ARP module couldn't process request");
        return TEST_FAILED;

        case ARP_PROCESS_RESULT_OK:
        snprintf(msg, msgmax, "ARP module processed a request for an invalid hardware address length");
        return TEST_FAILED;
    }

    if (oq.count > 0) {
        // Sent replies
        snprintf(msg, msgmax, "ARP module replied even though it failed to process the request");
        return TEST_FAILED;
    }

    return TEST_PASSED;
}


test_result_t test_arp_bb_E(char *msg, size_t msgmax)
{
    // Addresses of the packets that will be sent towards
    // the ARP module
    const char  net_ip_str[] = "10.0.0.5";
    const char net_mac_str[] = "00:34:56:34:f5:4f";

    // Addresses of the ARP module
    const char  ip_str[] = "10.0.0.4";
    const char mac_str[] = "56:34:f5:4d:4f:44";
        
    // Parse the addresses to binary form
    ip_address_t  ip,  net_ip;
    mac_address_t mac, net_mac;
    if (!parse_mac(mac_str, sizeof(mac_str)-1, &mac) ||
        !parse_ip(ip_str, &ip) ||
        !parse_mac(net_mac_str, sizeof(net_mac_str)-1, &net_mac) ||
        !parse_ip(net_ip_str, &net_ip)) {
        snprintf(msg, msgmax, "Couldn't parse IP and MAC strings");
        return TEST_ABORTED;
    }

    // Set up the module with the output queue
    arp_state_t state;
    output_queue_t oq = {.state=&state, .count=0, .oflow=0}; // Buffer where replies and requests will be stored
                                                             // by the ARP module
    arp_init(&state, ip, mac, &oq, send_arp_packet_callback);
    arp_change_output_buffer(&state, oq.queue, sizeof(arp_packet_t));

    // Build the request
    arp_packet_t request = {
        .hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET),
        .protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP),
        .hardware_len  = 6,
        .protocol_len  = 4+1, // Something other than the correct length
        .operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST),
        .sender_hardware_address = net_mac,
        .sender_protocol_address = net_ip,
        .target_hardware_address = MAC_ZERO,
        .target_protocol_address = ip,
    };

    // Send the request
    arp_process_result_t res;
    res = arp_process_packet(&state, &request, sizeof(arp_packet_t));
    switch (res) {

        case ARP_PROCESS_RESULT_INVALID:
        break;

        case ARP_PROCESS_RESULT_HWARENOTSUPP:
        case ARP_PROCESS_RESULT_PROTONOTSUPP:
        snprintf(msg, msgmax, "ARP module couldn't process request");
        return TEST_FAILED;

        case ARP_PROCESS_RESULT_OK:
        snprintf(msg, msgmax, "ARP module processed a request for an invalid protocol address length");
        return TEST_FAILED;
    }

    if (oq.count > 0) {
        // Sent replies
        snprintf(msg, msgmax, "ARP module replied even though it failed to process the request");
        return TEST_FAILED;
    }

    return TEST_PASSED;
}

int main(void)
{
    void *tests[] = {
        test_arp_bb_A,
        test_arp_bb_B,
        test_arp_bb_C,
        test_arp_bb_D,
        test_arp_bb_E,
    };

    char msg[256];
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
        test_result_t (*test_fn)(char*, size_t) = tests[i];
        switch (test_fn(msg, sizeof(msg))) {
            case TEST_PASSED: fprintf(stdout, "PASSED\n"); break;
            case TEST_FAILED: fprintf(stdout, "FAILED: %s\n", msg); break;
            case TEST_ABORTED: fprintf(stdout, "ABORTED: %s\n", msg); break;
        }
    }
    return 0;
}