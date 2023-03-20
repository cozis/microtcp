#include <stdbool.h>
#include "../src/arp.h"

#define ARP_TESTCASE_MAX_PACKETS 1024

typedef enum {
    ARP_TESTCASE_SENDER_HOST,
    ARP_TESTCASE_SENDER_PEER,
} arp_testcase_packet_sender_t;

typedef struct {
    arp_testcase_packet_sender_t sender;
    const char *data;
} arp_testcase_packet_t;

typedef struct {
    bool failed;

    ip_address_t  self_ip;
    mac_address_t self_mac;

    size_t count;
    arp_testcase_packet_t packets[ARP_TESTCASE_MAX_PACKETS];
} arp_testcase_t;

typedef enum {
    ARP_TESTCASE_PASSED,
    ARP_TESTCASE_FAILED,
    ARP_TESTCASE_ABORTED,
} arp_testcase_result_t;

void arp_testcase_init(arp_testcase_t *tcase, const char mac[static 6], const char ip[static 4]);
void arp_testcase_free(arp_testcase_t *tcase);
void arp_testcase_send(arp_testcase_t *tcase, const char data[static sizeof(arp_packet_t)]);
void arp_testcase_recv(arp_testcase_t *tcase, const char data[static sizeof(arp_packet_t)]);
arp_testcase_result_t arp_testcase_run(arp_testcase_t tcase, char *msg, size_t msgmax);
