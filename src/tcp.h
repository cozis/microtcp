#include <stddef.h>
#include <stdint.h>
#include <endian.h>
#include "defs.h"

#define TCP_MAX_LISTENERS 32
#define TCP_MAX_SOCKETS 1024
#define TCP_INPUT_BUFFER_SIZE 1024
#define TCP_OUTPUT_BUFFER_SIZE 1024

typedef struct tcp_state_t tcp_state_t; // Predeclare for cyclic references

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PUSH 0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_no;
    uint32_t ack_no;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t unused: 4;
    uint8_t offset: 4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t offset: 4;
    uint8_t unused: 4;
#endif
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    char payload[];
} tcp_segment_t;

typedef struct tcp_connection_t tcp_connection_t;
typedef struct tcp_listener_t tcp_listener_t;

struct tcp_listener_t {
    tcp_state_t *state;
    tcp_listener_t *prev;
    tcp_listener_t *next;
    uint16_t port;
    tcp_connection_t *connections;
    tcp_connection_t *connections_waiting_for_ack;
    tcp_connection_t *connections_waiting_for_accept_head;
    tcp_connection_t *connections_waiting_for_accept_tail;
    void (*callback)(void*);
    void *data;
};

struct tcp_connection_t {
    tcp_listener_t   *listener; // Listener that accepted this connection
    tcp_connection_t *next;
    tcp_connection_t *prev;
    ip_address_t peer_ip;
    uint16_t     peer_port;
    uint32_t seq_no;
    uint32_t ack_no;
    size_t  in_used;
    size_t out_used;
    tcp_segment_t out_header;                         // There must be no padding between
    char          out_buffer[TCP_OUTPUT_BUFFER_SIZE]; // these two
    char           in_buffer[TCP_INPUT_BUFFER_SIZE];
};
static_assert(offsetof(tcp_connection_t, out_buffer) == offsetof(tcp_connection_t, out_header) + sizeof(tcp_segment_t));

typedef struct {
    void *data;
    int (*send)(void *data, ip_address_t ip, const void *src, size_t len);
} tcp_callbacks_t;

struct tcp_state_t {
    tcp_callbacks_t callbacks;
    tcp_connection_t *used_connection_list;
    tcp_connection_t *free_connection_list;
    tcp_connection_t connection_pool[TCP_MAX_SOCKETS];
    tcp_listener_t *used_listener_list;
    tcp_listener_t *free_listener_list;
    tcp_listener_t listener_pool[TCP_MAX_LISTENERS];
};

void              tcp_init(tcp_state_t *tcp_state, tcp_callbacks_t callbacks);
void              tcp_free(tcp_state_t *tcp_state);
void              tcp_seconds_passed(tcp_state_t *state, size_t seconds);
void              tcp_process_segment(tcp_state_t *state, ip_address_t sender, tcp_segment_t *segment, size_t len);
tcp_listener_t   *tcp_listener_create(tcp_state_t *state, uint16_t port, void *data, void (*callback)(void*));
void              tcp_listener_destroy(tcp_listener_t *listener);
tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener);
void              tcp_connection_destroy(tcp_connection_t *connection);
size_t            tcp_connection_recv(tcp_connection_t *connection, void *dst, size_t len);
size_t            tcp_connection_send(tcp_connection_t *connection, const void *src, size_t len);
