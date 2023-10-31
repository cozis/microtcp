#include <stddef.h>
#include <stdint.h>
#include "defs.h"
#include "tcp_timer.h"

#define TCP_TIMEOUT_TIME_WAIT 1000
//240000

#define TCP_MAX_TIMEOUTS 1024
#define TCP_MAX_LISTENERS 32
#define TCP_MAX_SOCKETS 1024
#define TCP_IBUFFER_SIZE 1024
#define TCP_OBUFFER_SIZE 1024

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
    uint8_t  offset1: 4; // When CPU is big endian
    uint8_t  offset2: 4; // When CPU is little endian
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    char     payload[];
} __attribute__((packed)) tcp_segment_t;
static_assert(sizeof(tcp_segment_t) == 20);

typedef struct tcp_connection_t tcp_connection_t;
typedef struct tcp_listener_t   tcp_listener_t;

// After receiving a reset or close event, no 
// methods shall be called on the connection
// object, not even to close it.
typedef enum {
    TCP_CONNEVENT_CLOSE,
    TCP_CONNEVENT_RESET,
    TCP_CONNEVENT_RECV,
    TCP_CONNEVENT_SEND,
} tcp_connevent_t;

typedef enum {
    TCP_LISTENEVENT_ACCEPT,
} tcp_listenevent_t;

typedef void (*tcp_conneventcb_t)(void *data, tcp_connevent_t);
typedef void (*tcp_listeneventcb_t)(void *data, tcp_listenevent_t);

struct tcp_listener_t {
    tcp_state_t *state;
    tcp_listener_t *prev;
    tcp_listener_t *next;
    bool closed; // When a listener is closed while one or more connections that is
                 // previously accepted are open, the structure isn't deallocated
                 // but just marked lazily as "closed". A listener in the "closed-but-not-deallocated"
                 // state will not accept new connections but will serve the ones
                 // its still holding.
                 // In this state the listener can be reopened by setting the "closed"
                 // flag to true (and keeping the old connections intact).

    // Port the listener is listening onto
    uint16_t port;

    // Number of connection
    int count;

    // List of established and accepted connections
    tcp_connection_t *accepted;

    // List of connections which aren't in an established
    // state yet.
    tcp_connection_t *noestab;

    // Queue of connections ready to be accepted
    // (established but not accepted)
    tcp_connection_t *qhead;
    tcp_connection_t *qtail;
    
    tcp_listeneventcb_t cb_event;
    void *cb_data;
};

typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RCVD,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSING,
} tcp_connstate_t;

struct tcp_connection_t {
    
    tcp_listener_t   *listener; // Listener that accepted this connection
    tcp_connection_t *next;
    tcp_connection_t *prev;

    tcp_conneventcb_t cb_event;
    void             *cb_data;
    
    tcp_connstate_t state;

    ip_address_t peer_ip; // Network byte order
    uint16_t     peer_port; // CPU byte order

    // From RFC 6298, Section 2
    //   To compute the current RTO, a TCP sender maintains two state
    //   variables, SRTT (smoothed round-trip time) and RTTVAR (round-trip
    //   time variation).  In addition, we assume a clock granularity of G
    //   seconds.
    float srtt;
    float rttvar;

    tcp_timer_t *retr_timer;
    tcp_timer_t *wait_timer;

    // Send Sequence Space
    //
    //               1         2          3          4      
    //          ----------|----------|----------|---------- 
    //                 SND.UNA    SND.NXT    SND.UNA        
    //                                      +SND.WND        
    //
    //    1 - old sequence numbers which have been acknowledged  
    //    2 - sequence numbers of unacknowledged data            
    //    3 - sequence numbers allowed for new data transmission 
    //    4 - future sequence numbers which are not yet allowed  
    //
    // Receive Sequence Space
    //
    //                   1          2          3      
    //               ----------|----------|---------- 
    //                      RCV.NXT    RCV.NXT        
    //                                +RCV.WND        
    //
    // (From RFC 793 section 3.2, // https://www.ietf.org/rfc/rfc793.txt)
    
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

    uint32_t snd_wl1; // SND.WL1 from RFC 9293
                      // segment sequence number used for last 
                      // window update.
    
    uint32_t snd_wl2; // SND.WL2 from RFC 9293
                      // segment acknowledgment number used for 
                      // last window update.

    uint32_t last_acked; // Last sequence number of the peer that was ACKed

    // If true, the next segment which will empty the
    // output buffer will contain a FIN.
    bool send_fin_when_fully_flushed;
    bool waiting_ack_for_syn;
    bool waiting_ack_for_fin;
    size_t oused;
    char idata[TCP_IBUFFER_SIZE];
    char odata[TCP_OBUFFER_SIZE];
};

typedef struct {
    void *data;
    int (*send)(void *data, ip_address_t ip, const slice_t *slices, size_t num_slices);
} tcp_callbacks_t;

struct tcp_state_t {

    ip_address_t ip;
    tcp_callbacks_t callbacks;

    tcp_timerset_t timers;

    tcp_connection_t *free_connection_list;

    tcp_listener_t *used_listener_list;
    tcp_listener_t *free_listener_list;

    tcp_listener_t     listener_pool[TCP_MAX_LISTENERS];
    tcp_connection_t connection_pool[TCP_MAX_SOCKETS];
};

void              tcp_init(tcp_state_t *tcp_state, ip_address_t ip, tcp_callbacks_t callbacks);
void              tcp_free(tcp_state_t *tcp_state);
void              tcp_ms_passed(tcp_state_t *state, size_t ms);
void              tcp_process_segment(tcp_state_t *state, ip_address_t sender, tcp_segment_t *segment, size_t len);
tcp_listener_t   *tcp_listener_create(tcp_state_t *state, uint16_t port, bool reuse, void *cb_data, tcp_listeneventcb_t func);
void              tcp_listener_destroy(tcp_listener_t *listener);
tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener, void *cb_data, tcp_conneventcb_t func);
void              tcp_connection_destroy(tcp_connection_t *connection);
size_t            tcp_connection_recv(tcp_connection_t *connection, void *dst, size_t len);
size_t            tcp_connection_send(tcp_connection_t *connection, const void *src, size_t len);
