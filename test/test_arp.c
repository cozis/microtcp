#include <stdio.h>
#include <string.h>
#include "test_arp_util.h"

/*
    WHITE BOX TEST CASES
        
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

static arp_testcase_result_t test_000(char *msg, size_t msgmax)
{
    char host_ip[4] = {0xc0, 0xa8, 0x01, 0x05};
    char host_mac[6] = {0xcc, 0x6b, 0x1e, 0x13, 0xa8, 0x93};

    arp_testcase_t testcase;
    arp_testcase_init(&testcase, host_mac, host_ip);
    
    arp_testcase_send(&testcase, (char[]) {
        0x00, 0x01, // hardware_type=ethernet
        0x08, 0x00, // protocol_type=ip
        0x06, // hardware_len=6
        0x04, // protocol_len=4
        0x00, 0x01, // operation_type=request
        0xbc, 0x15, 0xac, 0x29, 0xe5, 0x61, // sender MAC
        0xc0, 0xa8, 0x01, 0x01, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (empty)
        0xc0, 0xa8, 0x01, 0x05, // target IP
    });
    
    arp_testcase_recv(&testcase, (char[]) {
        0x00, 0x01, // hardware_type=ethernet
        0x08, 0x00, // protocol_type=ip
        0x06, // hardware_len=6
        0x04, // protocol_len=4
        0x00, 0x02, // operation_type=reply
        0xcc, 0x6b, 0x1e, 0x13, 0xa8, 0x93, // sender MAC
        0xc0, 0xa8, 0x01, 0x05, // sender IP
        0xbc, 0x15, 0xac, 0x29, 0xe5, 0x61, // target MAC
        0xc0, 0xa8, 0x01, 0x01, // target IP
    });
    
    arp_testcase_result_t result = 
        arp_testcase_run(testcase, msg, msgmax);

    arp_testcase_free(&testcase);
    return result;
}


static arp_testcase_result_t test_001(char *msg, size_t msgmax)
{
    /* This testcase simulates the host receiving
     * an ARP request not associated to it, therefore
     * the ARP module is expected to not reply.
     */

    char host_ip[4] = {0xc0, 0xa8, 0x01, 0x05};
    char host_mac[6] = {0xcc, 0x6b, 0x1e, 0x13, 0xa8, 0x93};

    arp_testcase_t testcase;
    arp_testcase_init(&testcase, host_mac, host_ip);
    
    arp_testcase_send(&testcase, (char[]) {
        0x00, 0x01, // hardware_type=ethernet
        0x08, 0x00, // protocol_type=ip
        0x06, // hardware_len=6
        0x04, // protocol_len=4
        0x00, 0x01, // operation_type=request
        0xbc, 0x15, 0xac, 0x29, 0xe5, 0x61, // sender MAC
        0xc0, 0xa8, 0x01, 0x01, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (empty)
        0xc0, 0xa8, 0x01, 0x10, // target IP (different to the host's)
    });

    arp_testcase_result_t result = 
        arp_testcase_run(testcase, msg, msgmax);

    arp_testcase_free(&testcase);
    return result;
}

typedef arp_testcase_result_t (*arp_testcase_routine_t)(char*, size_t);

int main(void)
{
    static const arp_testcase_routine_t routines[] = {
        test_000,
        test_001,
        NULL,
    };

    size_t passed = 0;
    size_t failed = 0;
    size_t aborted = 0;

    for (size_t i = 0; routines[i]; i++) {

        char message[1024];
        arp_testcase_result_t result = routines[i](message, sizeof(message));

        switch (result) {
            case ARP_TESTCASE_PASSED: 
            fprintf(stdout, "Test %ld ... PASSED\n", i);
            passed++;
            break;
            
            case ARP_TESTCASE_FAILED: 
            fprintf(stdout, "Test %ld ... FAILED: %s\n", i, message); 
            failed++;
            break;
            
            case ARP_TESTCASE_ABORTED: 
            fprintf(stdout, "Test %ld ... ABORTED: %s\n", i, message); 
            aborted++;
            break;
        }
    }

    fprintf(stdout, "SUMMARY: %ld passed, %ld failed and %ld aborted\n",
            passed, failed, aborted);
    return 0;
}