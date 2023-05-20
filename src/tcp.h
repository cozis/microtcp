#include <stddef.h>
#include <stdint.h>

#ifndef MICROTCP_AMALGAMATION
#include "defs.h"
#endif

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
    uint8_t offset1: 4; // When CPU is big endian
    uint8_t offset2: 4; // When CPU is little endian
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    char payload[];
} tcp_segment_t;
static_assert(sizeof(tcp_segment_t) == 20);

typedef struct tcp_connection_t tcp_connection_t;
typedef struct tcp_listener_t tcp_listener_t;

struct tcp_listener_t {
    tcp_state_t *state;
    tcp_listener_t *prev;
    tcp_listener_t *next;
    uint16_t port;
    tcp_connection_t *accepted_list;
    tcp_connection_t *non_established_list;
    tcp_connection_t *non_accepted_queue_head;
    tcp_connection_t *non_accepted_queue_tail;
    void (*callback_ready_to_accept)(void*);
    void  *callback_data;
};

typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RCVD,
    TCP_STATE_ESTAB,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
} tcp_connstate_t;

struct tcp_connection_t {
    tcp_listener_t   *listener; // Listener that accepted this connection
    tcp_connection_t *next;
    tcp_connection_t *prev;

    void  *callback_data;
    void (*callback_ready_to_recv)(void*);
    void (*callback_ready_to_send)(void*);
    
    tcp_connstate_t state;

    ip_address_t peer_ip; // Network byte order
    uint16_t     peer_port; // CPU byte order

    uint32_t rcv_unread; // It's the sequence number of the first
                         // byte stored in the input buffer, such
                         // that [rcv_next - rcv_unread] is the
                         // number of bytes that the parent application
                         // can read from the socket.

    uint32_t rcv_nxt; // RCV.NXT from RFC 793
                      // It's the sequence number of the next
                      // byte waiting to be received.

    uint32_t rcv_wnd; // RCV.WND from RFC 793
                      // It's the size of the portion of input
                      // buffer that's currently free.
    
    uint32_t snd_wnd; // SND.WND from RFC 793
                      // It's the number of bytes stored in
                      // the [out_buffer] output buffer, both
                      // sent but not acknowledged and not sent.

    uint32_t snd_nxt; // SND.NXT from RFC 793
                      // It's the sequence number of the first
                      // not yet sent byte in the output buffer.
                      // By subtracting [snd_una] from this value,
                      // you get the amount of bytes sent out but
                      // not yet acknowledged. 

    uint32_t snd_una; // SND.UNA from RFC 793
                      // It's the sequence number of the last
                      // byte sent and acknowledged by the peer.

    char out_buffer[TCP_OUTPUT_BUFFER_SIZE];
    char  in_buffer[TCP_INPUT_BUFFER_SIZE];
};

typedef struct {
    void *data;
    int (*send)(void *data, ip_address_t ip, const slice_list_t *slices, size_t num_slices);
} tcp_callbacks_t;

struct tcp_state_t {
    ip_address_t ip;
    tcp_callbacks_t callbacks;
    tcp_connection_t *free_connection_list;
    tcp_connection_t connection_pool[TCP_MAX_SOCKETS];
    tcp_listener_t *used_listener_list;
    tcp_listener_t *free_listener_list;
    tcp_listener_t listener_pool[TCP_MAX_LISTENERS];
};

void              tcp_init(tcp_state_t *tcp_state, ip_address_t ip, tcp_callbacks_t callbacks);
void              tcp_free(tcp_state_t *tcp_state);
void              tcp_seconds_passed(tcp_state_t *state, size_t seconds);
void              tcp_process_segment(tcp_state_t *state, ip_address_t sender, tcp_segment_t *segment, size_t len);
tcp_listener_t   *tcp_listener_create(tcp_state_t *state, uint16_t port, void *data, void (*callback)(void*));
void              tcp_listener_destroy(tcp_listener_t *listener);
tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener, void *callback_data, void (*callback_ready_to_recv)(void*), void (*callback_ready_to_send)(void*));
void              tcp_connection_destroy(tcp_connection_t *connection);
void              tcp_connection_finish(tcp_connection_t *connection);
size_t            tcp_connection_recv(tcp_connection_t *connection, void *dst, size_t len);
size_t            tcp_connection_send(tcp_connection_t *connection, const void *src, size_t len);
