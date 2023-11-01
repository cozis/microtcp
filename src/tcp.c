#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include "endian.h"
#include "tcp.h"

#ifdef TCP_DEBUG
#   include <stdio.h>
#   define TCP_DEBUG_LOG(fmt, ...) fprintf(stderr, "TCP :: " fmt "\n", ## __VA_ARGS__)
#else
#   define TCP_DEBUG_LOG(...) {}
#endif

#define SLICE_EMPTY ((slice_t) {.ptr=NULL, .len=0})

#define SEGMENT_OFFSET(seg) (cpu_is_little_endian() ? (seg)->offset2 : (seg)->offset1)

void tcp_init(tcp_state_t *tcp_state, ip_address_t ip, tcp_callbacks_t callbacks)
{
    tcp_state->ip = ip;
    tcp_state->callbacks = callbacks;

    for (size_t i = 0; i < TCP_MAX_SOCKETS-1; i++)
        tcp_state->connection_pool[i].next = tcp_state->connection_pool + i+1;
    tcp_state->connection_pool[TCP_MAX_SOCKETS-1].next = NULL;
    tcp_state->free_connection_list = tcp_state->connection_pool;

    for (size_t i = 0; i < TCP_MAX_LISTENERS-1; i++)
        tcp_state->listener_pool[i].next = tcp_state->listener_pool + i+1;
    tcp_state->listener_pool[TCP_MAX_LISTENERS-1].next = NULL;
    tcp_state->free_listener_list = tcp_state->listener_pool;
    tcp_state->used_listener_list = NULL;

    tcp_timerset_init(&tcp_state->timers);
}

void tcp_free(tcp_state_t *state)
{
    // It's not clear to me how to free 
    // all of this stuff up at the moment :/
    tcp_timerset_free(&state->timers);
}

void tcp_ms_passed(tcp_state_t *state, size_t ms)
{
    tcp_timerset_step(&state->timers, ms);
}

static tcp_connection_t*
get_conn_struct(tcp_state_t *tcp)
{
    tcp_connection_t *c = tcp->free_connection_list;
    if (c) {
        tcp->free_connection_list = c->next;
        c->prev = NULL;
        c->next = NULL;
    }
    return c;
}

static void 
append_new_conn_to_listener(tcp_connection_t *c, 
                            tcp_listener_t *listener)
{
    if (listener->noestab)
        listener->noestab->prev = c;
    c->next = listener->noestab;
    listener->noestab = c;
    c->listener = listener;
    listener->count++;
}

static tcp_connection_t*
connection_create(tcp_listener_t *listener, ip_address_t ip, uint16_t port, uint32_t seq, uint32_t ack)
{
    tcp_state_t *state = listener->state;

    // Pop a connection structure from the free list
    tcp_connection_t *c = get_conn_struct(state);
    if (c == NULL)
        // ERROR: Reached connection limit
        return NULL;

    c->listener = NULL;
    c->cb_data = NULL;
    c->cb_event = NULL;
    c->state = TCP_STATE_CLOSED;
    c->peer_port = port;
    c->peer_ip   = ip;
    c->retr_timer = NULL;
    c->wait_timer = NULL;
    c->rcv_unread = ack;
    c->rcv_nxt = ack;
    c->rcv_wnd = TCP_IBUFFER_SIZE;
    c->snd_una = seq;
    c->snd_wnd = 0;
    c->snd_nxt = seq;
    c->snd_wl1 = seq;
    c->snd_wl2 = ack;
    c->oused = 0;
    c->waiting_ack_for_syn = false;
    c->waiting_ack_for_fin = false;
    c->send_fin_when_fully_flushed = false;

    append_new_conn_to_listener(c, listener);
    return c;
}

static tcp_listener_t*
find_listener(tcp_state_t *state, uint16_t port)
{
    tcp_listener_t *cursor = state->used_listener_list;
    while (cursor) {
        if (cursor->port == port)
            return cursor;
        cursor = cursor->next;
    }
    return NULL;
}

static uint32_t choose_sequence_no(void)
{
    return 0;
}

static void retransmit(tcp_connection_t *c);

static void retr_timeout_callback(void *data)
{
    tcp_connection_t *c = data;
    tcp_listener_t   *l = c->listener;
    tcp_state_t *tcp = l->state;

    retransmit(c);

    // Start a new retransmission timer
    size_t ms = 1000;
    c->retr_timer = tcp_timer_create(&tcp->timers, ms, "retr", retr_timeout_callback, c);
    if (c->retr_timer == NULL)
        TCP_DEBUG_LOG("Couldn't set retransmission timer");
}

static void really_close_connection(tcp_connection_t *c);

static void wait_timeout_callback(void *data)
{
    tcp_connection_t *c = data;
    really_close_connection(c);
}

typedef struct {
    ip_address_t self;
    ip_address_t peer;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq, ack;
    uint8_t  flags;
    uint16_t window;
    slice_t  payload;
} transmit_config_t;

typedef struct {
    ip_address_t src_addr;
    ip_address_t dst_addr;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t tcp_length;
} tcp_pseudoheader_t; // Ensure packed?

static uint16_t 
calc_checksum(const slice_t *slices, size_t num_slices)
{
    uint32_t sum = 0xffff;

    for (size_t slice_idx = 0; slice_idx < num_slices; slice_idx++) {
        
        const uint16_t *ptr = slices[slice_idx].ptr;
        const size_t    len = slices[slice_idx].len;

        for (size_t i = 0; i < len/2; i++) {
            sum += net_to_cpu_u16(ptr[i]);
            if (sum > 0xffff)
                sum -= 0xffff;
        }
        
        if (len & 1) {
            alignas(uint16_t) uint8_t temp[2];
            
            temp[0] = ((uint8_t*) slices[slice_idx].ptr)[len-1];
            temp[1] = 0;

            uint16_t temp2 = *(uint16_t*) temp;
            sum += net_to_cpu_u16(temp2);
            if (sum > 0xffff)
                sum -= 0xffff;
        }
    }

    return cpu_to_net_u16(~sum);
}

static tcp_pseudoheader_t
compile_pseudo_header(transmit_config_t config)
{
    tcp_pseudoheader_t pseudo;
    pseudo.src_addr = config.self;
    pseudo.dst_addr = config.peer;
    pseudo.reserved = 0;
    pseudo.protocol = 6; // TCP
    pseudo.tcp_length = cpu_to_net_u16(sizeof(tcp_segment_t) + config.payload.len);   
    return pseudo;
}

static tcp_segment_t
compile_segment(transmit_config_t config)
{
    tcp_segment_t header;

    int offset = 5; // No options
    header.src_port = cpu_to_net_u16(config.src_port);
    header.dst_port = cpu_to_net_u16(config.dst_port);
    header.flags    = config.flags;
    header.seq_no   = cpu_to_net_u32(config.seq);
    header.ack_no   = cpu_to_net_u32(config.ack);
    header.offset1  = cpu_is_little_endian() ? 0 : offset;
    header.offset2  = cpu_is_little_endian() ? offset : 0;
    header.window   = cpu_to_net_u16(config.window); // Why is a 32 bit integer being backed into a 16 bit?
    header.checksum = 0; // Will be calculated later
    header.urgent_pointer = 0;

    tcp_pseudoheader_t pseudo = compile_pseudo_header(config);
    slice_t list[] = { SLICE(pseudo), SLICE(header), config.payload };
    header.checksum = calc_checksum(list, COUNT(list));

    return header;
}

static int 
transmit_bytes(tcp_state_t *tcp, ip_address_t ip, 
           tcp_segment_t header, slice_t payload)
{
    slice_t slices[] = { SLICE(header), payload };
    return tcp->callbacks.send(tcp->callbacks.data, ip, slices, COUNT(slices));
}

static int transmit_basic(tcp_state_t *tcp, transmit_config_t config)
{
    tcp_segment_t header = compile_segment(config);
    return transmit_bytes(tcp, config.peer, header, config.payload);
}

static void transmit_reply_rst(tcp_state_t *tcp, ip_address_t receiver, 
                               tcp_segment_t received, uint32_t seq, uint32_t ack)
{
    uint8_t flags = TCP_FLAG_RST;
    if (ack > 0) flags |= TCP_FLAG_ACK;

    transmit_config_t config = {
        .self = tcp->ip,
        .peer = receiver,
        .src_port = received.dst_port,
        .dst_port = received.src_port,
        .seq = seq, 
        .ack = ack,
        .flags = flags,
        .window = 0,
        .payload = SLICE_EMPTY,
    };
    transmit_basic(tcp, config);
}

static void transmit_rst(tcp_connection_t *c, bool ack)
{
    tcp_listener_t *listener = c->listener;
    tcp_state_t    *tcp = listener->state;

    uint8_t flags = TCP_FLAG_RST;

    if (ack)
        flags |= TCP_FLAG_ACK;

    transmit_config_t config = {
        .self = tcp->ip,
        .peer = c->peer_ip,
        .src_port = listener->port,
        .dst_port = c->peer_port,
        .seq = c->snd_nxt, 
        .ack = ack ? c->rcv_nxt : 0,
        .flags = flags,
        .window = c->rcv_wnd,
        .payload = SLICE_EMPTY,
    };
    transmit_basic(tcp, config);
}

#ifdef TCP_DEBUG
#define TCP_DEBUG_LOCATION(F, L) , const char *F, int L
#else
#define TCP_DEBUG_LOCATION(F, L)
#endif

static const char *flags_to_str(uint8_t flags)
{
    switch (flags) {

        case TCP_FLAG_ACK: return "ACK";
        case TCP_FLAG_FIN: return "FIN";
        case TCP_FLAG_SYN: return "SYN";
        case TCP_FLAG_RST: return "RST";
        case TCP_FLAG_URG: return "URG";

        case TCP_FLAG_FIN | TCP_FLAG_ACK: return "FIN|ACK";
        case TCP_FLAG_SYN | TCP_FLAG_ACK: return "SYN|ACK";
        case TCP_FLAG_RST | TCP_FLAG_ACK: return "RST|ACK";
        
        default: return "?";
    }

}

static void transmit_(tcp_connection_t *c, uint8_t flags, bool no_payload 
                      TCP_DEBUG_LOCATION(file, line)) 
{
    TCP_DEBUG_LOG("transmit(flags=%s, no_payload=%s) at %s:%d", flags_to_str(flags), no_payload ? "true" : "false", file, line);

    tcp_listener_t *listener = c->listener;
    tcp_state_t    *tcp = listener->state;

    bool ack = flags & TCP_FLAG_ACK;

    size_t waiting_to_be_sent = c->oused - (c->snd_nxt - c->snd_una);

    // Choose a slice of the transmission queue
    slice_t payload;
    {
        size_t num;
        if (no_payload)
            num = 0;
        else {
            size_t mss = 500;
            num = MIN(mss, waiting_to_be_sent);
        }
        payload.ptr = c->odata + c->snd_nxt - c->snd_una;
        payload.len = num;
    }

    bool sending_everything = (waiting_to_be_sent == payload.len);
    if (sending_everything && c->send_fin_when_fully_flushed) {
        
        // In a previous transmission the caller requested
        // a FIN to be sent when the transmission queue was
        // emptied. This transmission will send all of the
        // pending data.
        flags |= TCP_FLAG_FIN;
        c->send_fin_when_fully_flushed = false;
        c->waiting_ack_for_fin = true;

    } else if (flags & TCP_FLAG_FIN) {

        // The caller requested a FIN to be sent,
        // but if there is some data in the transmission
        // queue, the FIN should actually be sent
        // after everything else is sent.
        if (sending_everything)
            c->waiting_ack_for_fin = true;
        else {
            c->send_fin_when_fully_flushed = true;
            flags &= ~TCP_FLAG_FIN; // FIN will be sent in one of the next transmissions
        }
    }

    // Peer don't accept FINs if not accompanied by ACKs
    if (flags & TCP_FLAG_FIN) flags |= TCP_FLAG_ACK;

    transmit_config_t config = {
        .self = tcp->ip,
        .peer = c->peer_ip,
        .src_port = listener->port,
        .dst_port = c->peer_port,
        .seq = c->snd_nxt, 
        .ack = ack ? c->rcv_nxt : 0,
        .flags = flags,
        .window = c->rcv_wnd,
        .payload = payload,
    };
    transmit_basic(tcp, config);

    c->snd_nxt += payload.len;

    if (flags & TCP_FLAG_FIN) {
        c->snd_nxt++;
        if (c->state == TCP_STATE_CLOSE_WAIT)
            // This state change was queued in the
            // [tcp_connection_destroy] function.
            c->state = TCP_STATE_LAST_ACK;
    }

    if (flags & TCP_FLAG_SYN) {
        c->snd_nxt++;
        c->waiting_ack_for_syn = true;
    }

    // Restart the retransmission timer if necessary
    if (c->snd_una < c->snd_nxt) {

        if (c->retr_timer)
            tcp_timer_disable(c->retr_timer);

        size_t ms = 1000; // Should be adaptative
        c->retr_timer = tcp_timer_create(&tcp->timers, ms, "retr", retr_timeout_callback, c);
        if (c->retr_timer == NULL)
            TCP_DEBUG_LOG("Couldn't set retransmission timer");
    }
}

#ifdef TCP_DEBUG
#define transmit(c, flags, no_payload) transmit_((c), (flags), (no_payload), __FILE__, __LINE__)
#else
#define transmit transmit_
#endif

static void retransmit(tcp_connection_t *c)
{
    TCP_DEBUG_LOG("Retransmitting");
    tcp_listener_t *listener = c->listener;
    tcp_state_t    *tcp = listener->state;

    size_t retr_queue_bytes = c->snd_nxt - c->snd_una;
    
    //assert(retr_queue_bytes > 0); // If there were no bytes to ACK, 
                                    // there would be no active timer.

    size_t retr_queue_ghost = 0;
    if (c->waiting_ack_for_syn) retr_queue_ghost++;
    if (c->waiting_ack_for_fin) retr_queue_ghost++;

    assert(retr_queue_bytes >= retr_queue_ghost);
    

    size_t retr_queue_actual = retr_queue_bytes - retr_queue_ghost;
    assert(retr_queue_actual <= c->oused);

    size_t mss = 500; // TODO: Make this configurable
    size_t num = MIN(mss, retr_queue_actual);

    slice_t payload = {.ptr=c->odata, .len=num};

    uint8_t flags = TCP_FLAG_ACK;

    // If we're sending the last portion of
    // the retransmission queue and a FIN was
    // sent but not ACKed, send it again.
    if (num == retr_queue_actual && c->waiting_ack_for_fin)
        flags |= TCP_FLAG_FIN;

    transmit_config_t config = {
        .self = tcp->ip,
        .peer = c->peer_ip,
        .src_port = listener->port,
        .dst_port = c->peer_port,
        .seq = c->snd_una, 
        .ack = c->rcv_nxt,
        .flags = flags,
        .window = c->rcv_wnd,
        .payload = payload,
    };
    transmit_basic(tcp, config);
}

static void forget_acked(tcp_connection_t *c, uint32_t ack)
{
    if (ack <= c->snd_una)
        return; // Duplicate ACK

    size_t acked_num = ack - c->snd_una;
    
    size_t ghost = 0; // Number of acked ghost (to be calculated)
    bool acked_fin = c->waiting_ack_for_fin && ack == c->snd_nxt;
    bool acked_syn = c->waiting_ack_for_syn && acked_num > 0;
    if (acked_fin) { ghost++; c->waiting_ack_for_fin = false; }
    if (acked_syn) { ghost++; c->waiting_ack_for_syn = false; }
    assert(acked_num >= ghost);

    size_t acked_num_no_ghost = acked_num - ghost;
    assert(acked_num_no_ghost <= c->oused);

    memmove(c->odata, 
        c->odata + acked_num_no_ghost, 
        c->oused - acked_num_no_ghost);

    c->snd_una = ack;
    c->oused -= acked_num_no_ghost;
/*
    if (acked_syn && acked_fin) {
        TCP_DEBUG_LOG("Peer acked %ld bytes (including SYN and FIN)", acked_num);
    } else if (acked_syn) {
        TCP_DEBUG_LOG("Peer acked %ld bytes (including SYN)", acked_num);
    } else if (acked_fin) {
        TCP_DEBUG_LOG("Peer acked %ld bytes (including FIN)", acked_num);
    } else {
        TCP_DEBUG_LOG("Peer acked %ld bytes", acked_num);
    }
*/
}

static slice_t
get_input_data(tcp_connection_t *c)
{
    slice_t s;
    s.ptr = c->idata;
    s.len = TCP_IBUFFER_SIZE - c->rcv_wnd;
    return s;
}

static size_t
move_from_idata(tcp_connection_t *c, slice_t dst)
{
    slice_t buf = get_input_data(c);
    size_t unread = (c->rcv_nxt - c->rcv_unread);
    size_t moving = MIN(dst.len, unread);
    
    if (moving > 0) {
        memcpy(dst.ptr, buf.ptr, moving);
        memmove(buf.ptr, (char*) buf.ptr + moving, buf.len - moving);
        c->rcv_wnd    += moving;
        c->rcv_unread += moving;
    }

    return moving;
}

static size_t
move_data_into_input_buffer(tcp_connection_t *c, slice_t src)
{
    slice_t buf = get_input_data(c);
    size_t moving = MIN(src.len, c->rcv_wnd);

    if (moving > 0) {
        memcpy((char*) buf.ptr + buf.len, src.ptr, moving);
        c->rcv_wnd -= moving;
        c->rcv_nxt += moving;
    }

    return moving;
}

static tcp_connection_t*
look_for_connection_in_list(tcp_connection_t *list, ip_address_t ip, uint16_t port)
{
    tcp_connection_t *c = list;
    while (c) {
        if (c->peer_ip == ip && c->peer_port == port)
            break;
        c = c->next;
    }
    return c;
}

static tcp_connection_t*
find_connection(tcp_listener_t *listener, ip_address_t ip, uint16_t port)
{
    tcp_connection_t *c = look_for_connection_in_list(listener->accepted, ip, port);
    if (c == NULL) c = look_for_connection_in_list(listener->qhead, ip, port);
    if (c == NULL) c = look_for_connection_in_list(listener->noestab, ip, port);
    return c;
}

static void 
move_from_non_established_list_to_non_accepted_queue(tcp_connection_t *c)
{
    tcp_listener_t *listener = c->listener;

    // Unlink the structure from the non established list
    {
        if (c->prev)
            c->prev->next = c->next;
        else
            listener->noestab = c->next;

        if (c->next)
            c->next->prev = c->prev;
    }

    // Push it into the non accepted queue
    c->prev = NULL;
    c->next = listener->qhead;
    if (listener->qhead)
        listener->qhead->prev = c;
    else
        listener->qtail = c;
    listener->qhead = c;
}

static void
really_close_listener(tcp_listener_t *listener)
{
    tcp_state_t *state = listener->state;

    assert(listener->count == 0);

    // Pop listener from used list
    {
        // Update the reference to the listener of
        // the one that precedes it in the list
        if (listener->prev)
            listener->prev->next = listener->next;
        else
            state->used_listener_list = listener->next;

        // Update the reference to the listener of
        // the one that follows it in the list
        if (listener->next != NULL)
            listener->next->prev = listener->prev;
    }

    // Push the listener in the free list
    listener->next = state->free_listener_list;
    state->free_listener_list = listener;
}

static void 
really_close_connection(tcp_connection_t *connection)
{
    TCP_DEBUG_LOG("Connection closed");

    tcp_listener_t *listener = connection->listener;
    tcp_state_t *state = listener->state;

    // Pop connection from the list it's in
    tcp_connection_t *next = connection->next;
    if (connection->prev)
        connection->prev->next = next;
    else if (listener->accepted == connection)
        listener->accepted = next;
    else if (listener->noestab == connection)
        listener->noestab = next;
    else if (listener->qhead == connection)
        listener->qhead = next;        
    tcp_connection_t *prev = connection->prev;
    if (next)
        connection->next->prev = prev;
    else if (listener->qtail == connection)
        listener->qtail = prev;

    // Push it into the free connection list
    connection->prev = NULL;
    connection->next = state->free_connection_list;
    state->free_connection_list = connection;

    // TODO: Disable all timers

    assert(listener->count > 0);
    listener->count--;

    // If the listener is waiting to be closed
    // and this was the last connection it was
    // holding, then free the listener
    if (listener->closed == true && listener->count == 0)
        really_close_listener(listener);
}

static slice_t 
segment_payload(tcp_segment_t *segment, size_t len)
{
    assert(len >= sizeof(tcp_segment_t));

    // Length (in bytes) of the TCP header,
    // comprehensive of options.
    int off = SEGMENT_OFFSET(segment) * sizeof(uint32_t);

    // The number of bytes of the options is
    // the size of the whole header minus the
    // size of the header without options.
    size_t options_len = off - sizeof(tcp_segment_t); 
    (void) options_len;

    // The segment->payload doesn't refer to the
    // first byte of the payload but to the first
    // byte of the options!! Use this variable to
    // get the payload.
    uint8_t *seg = (uint8_t*) segment;
    slice_t payload = {
        .len = len - off,
        .ptr = seg + off,
    };

    return payload;
}

static bool set(tcp_segment_t *segment, uint8_t flags)
{
    return (segment->flags & flags) != 0;
}

static void unset(tcp_segment_t *segment, uint8_t flags)
{
    segment->flags &= ~flags;
}

static void state_closed(tcp_state_t *tcp, ip_address_t sender, 
                         tcp_segment_t *seg, size_t len)
{
    slice_t payload = segment_payload(seg, len);

    // From RFC 9239, Section 3.10.7.1.
    //
    //   If the state is CLOSED (i.e., TCB does not exist), then
    //
    //     all data in the incoming segment is discarded. An incoming 
    //     segment containing a RST is discarded. An incoming segment 
    //     not containing a RST causes a RST to be sent in response. 
    //     The acknowledgment and sequence field values are selected 
    //     to make the reset sequence acceptable to the TCP endpoint 
    //     that sent the offending segment.
    //
    //     If the ACK bit is off, sequence number zero is used,
    //
    //       <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    //
    //     If the ACK bit is on,
    //
    //       <SEQ=SEG.ACK><CTL=RST>
    //
    //     Return.

    if (!set(seg, TCP_FLAG_RST))
        // Didn't receive a reset so we need to send one.
        transmit_reply_rst(tcp, sender, *seg, 
            set(seg, TCP_FLAG_ACK) ? seg->ack_no : 0, 
            set(seg, TCP_FLAG_ACK) ? 0 : seg->seq_no + payload.len);
}

static tcp_connection_t*
state_listen(tcp_listener_t *listener, ip_address_t sender, 
             tcp_segment_t *seg)
{
    tcp_state_t *tcp = listener->state;
    uint16_t sport = net_to_cpu_u16(seg->src_port);

    // From RFC 9239, Section 3.10.7.2.
    //
    //   If the state is LISTEN, then
    //
    //     First, check for a RST:
    //
    //       An incoming RST segment could not be valid since it 
    //       could not have been sent in response to anything sent 
    //       by this incarnation of the connection. An incoming RST 
    //       should be ignored. Return.
    //
    //     Second, check for an ACK:
    //
    //       Any acknowledgment is bad if it arrives on a connection 
    //       still in the LISTEN state. An acceptable reset segment 
    //       should be formed for any arriving ACK-bearing segment. 
    //       The RST should be formatted as follows:
    //
    //         <SEQ=SEG.ACK><CTL=RST>
    //
    //       Return.
    //
    //     Third, check for a SYN:
    //
    //       If the SYN bit is set, check the security. If the 
    //       security/compartment on the incoming segment does not 
    //       exactly match the security/compartment in the TCB, then 
    //       send a reset and return.
    //
    //         <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
    //
    //       Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ, and 
    //       any other control or text should be queued for processing 
    //       later. ISS should be selected and a SYN segment sent 
    //       of the form:
    //
    //         <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
    //
    //       SND.NXT is set to ISS+1 and SND.UNA to ISS. The connection 
    //       state should be changed to SYN-RECEIVED. Note that any 
    //       other incoming control or data (combined with SYN) will 
    //       be processed in the SYN-RECEIVED state, but processing of 
    //       SYN and ACK should not be repeated. If the listen was not 
    //       fully specified (i.e., the remote socket was not fully 
    //       specified), then the unspecified fields should be filled 
    //       in now.
    //
    //     Fourth, other data or control:
    //
    //       This should not be reached. Drop the segment and return. 
    //       Any other control or data-bearing segment (not containing SYN) 
    //       must have an ACK and thus would have been discarded by the ACK 
    //       processing in the second step, unless it was first discarded by 
    //       RST checking in the first step.

    if (set(seg, TCP_FLAG_RST))
        return NULL;

    if (set(seg, TCP_FLAG_ACK)) {
        transmit_reply_rst(tcp, sender, *seg, 0, seg->ack_no);
        return NULL;
    }

    if (set(seg, TCP_FLAG_SYN)) {
        // TODO: Check for "security/compartment" and "seg precedence value"

        uint32_t seq = choose_sequence_no();
        uint32_t ack = net_to_cpu_u32(seg->seq_no)+1;
            
        tcp_connection_t *c = connection_create(listener, sender, sport, seq, ack);
        if (c == NULL) {
            TCP_DEBUG_LOG("Connection limit reached");
            // Should we let the peer know what happened?
            return NULL;
        }

        transmit(c, TCP_FLAG_SYN | TCP_FLAG_ACK, true);
        c->state = TCP_STATE_SYN_RCVD;
        
        // Complete the processing in the SYN-RCVD state, but
        // don't repeat the SYN and ACK should not be repeated
        unset(seg, TCP_FLAG_SYN | TCP_FLAG_ACK);
        seg->seq_no = cpu_to_net_u32(ack);
        return c; // Continue with the SYN-RCVD state
    }

    // Else, drop the segment.
    return NULL;
}

static bool seq_in_window(tcp_connection_t *c, uint32_t seq)
{
    return c->rcv_nxt <= seq && seq < c->rcv_nxt + c->rcv_wnd;
}

static bool valid_seq(tcp_connection_t *c, uint32_t seq, size_t payload_len)
{

    // From RFC 9293, Section 3.10.7.4.
    //
    //   There are four cases for the acceptability test for an incoming
    //   segment:
    // 
    //   Segment Receive  Test
    //   Length  Window
    //   ------- -------  -------------------------------------------
    //
    //     0       0     SEG.SEQ = RCV.NXT
    //
    //     0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //
    //    >0       0     not acceptable
    //
    //    >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    //                or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        
    uint32_t head = seq;
    uint32_t tail = seq + (payload_len > 0 ? payload_len-1 : 0);

    if (!seq_in_window(c, head) || !seq_in_window(c, tail))
        return false;

    if (c->rcv_wnd == 0) {
        
        if (payload_len > 0)
            // Segment can't be accepted because it has 
            // payload and the input buffer is full.
            return false;

        if (seq == c->rcv_nxt)
            // Sequence number is in range of the receive window
            // (we did the check before) but when the receive window
            // is 0, it needs to be exactly the expected one.
            return false;
    }

    return true;
}

static void transition_to_time_wait(tcp_connection_t *c)
{
    tcp_listener_t *l = c->listener;
    tcp_state_t *tcp = l->state;

    c->state = TCP_STATE_TIME_WAIT;

    if (c->retr_timer) {
        tcp_timer_disable(c->retr_timer);
        c->retr_timer = NULL;
    }

    size_t ms = 60;
    c->wait_timer = tcp_timer_create(&tcp->timers, ms, "wait", wait_timeout_callback, c);
    if (c->wait_timer == NULL) {
        // Couldn't set the TIME-WAIT timer
        TCP_DEBUG_LOG("Couldn't set the TIME-WAIT timer");
        wait_timeout_callback(c);
    }
}

#define DISCARD { return; }

void tcp_process_segment(tcp_state_t *tcp, ip_address_t sender,
                         tcp_segment_t *segment, size_t len)
{
    uint16_t  dport = net_to_cpu_u16(segment->dst_port);
    uint16_t  sport = net_to_cpu_u16(segment->src_port);
    slice_t payload = segment_payload(segment, len);

    tcp_connstate_t connstate;

    tcp_listener_t *listener = find_listener(tcp, dport);
    tcp_connection_t *c = listener ? find_connection(listener, sender, sport) : NULL;

    // If the listener does not exist, then the socket referenced by
    // the segment is in the CLOSED state. If the listener exists but
    // it's marked as closed (as in "listener->closed = true"), then
    // already established connections are ok but new ones are not so
    // the listener should be regarded as in the CLOSED state.

    if (listener == NULL)
        connstate = TCP_STATE_CLOSED; // Not listening on destination port
    else {
        if (c == NULL) {
            if (listener->closed)
                connstate = TCP_STATE_CLOSED; // Listener object exists but it's not listening
            else
                connstate = TCP_STATE_LISTEN;
        } else
            connstate = c->state;
    }

    uint32_t seq;
    uint32_t ack;
    switch (connstate) {
        
        case TCP_STATE_CLOSED: 
        state_closed(tcp, sender, segment, len); 
        return;        

        case TCP_STATE_SYN_SENT:
        // This is the state where we sent SYN to initiate 
        // the connection with a peer acting as server.
        // At the moment "microtcp_connect" isn't implemented
        // so this state can never be reached.
        assert(0); // UNREACHABLE
        DISCARD;
        
        case TCP_STATE_LISTEN: 
        c = state_listen(listener, sender, segment); 
        if (c == NULL || c->state != TCP_STATE_SYN_RCVD)
            break;

        TCP_DEBUG_LOG("Connection established");
        /* fallthrough */

        case TCP_STATE_SYN_RCVD:    /* fallthrough */
        case TCP_STATE_ESTABLISHED: /* fallthrough */
        case TCP_STATE_FIN_WAIT_1:  /* fallthrough */
        case TCP_STATE_FIN_WAIT_2:  /* fallthrough */
        case TCP_STATE_CLOSE_WAIT:  /* fallthrough */
        case TCP_STATE_CLOSING:     /* fallthrough */
        case TCP_STATE_LAST_ACK:    /* fallthrough */
        case TCP_STATE_TIME_WAIT:

        seq = net_to_cpu_u32(segment->seq_no);

        if (!valid_seq(c, seq, payload.len)) {
            // From RFC 9293, Section 3.10.7.4.
            //
            //   If an incoming segment is not acceptable, an acknowledgment 
            //   should be sent in reply (unless the RST bit is set, if so 
            //   drop the segment and return): 
            //
            //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> 
            //
            //   After sending the acknowledgment, drop the unacceptable 
            //   segment and return.
            if (!set(segment, TCP_FLAG_RST))
                transmit(c, TCP_FLAG_ACK, true);
            DISCARD;
        }

        // TODO: Trim any segments without the exact sequence number
        {
            if (c->rcv_nxt < seq) {
                // Segment refers to the future. Send an ACK with the expected
                // sequence number to let the peer know where we're at.
                transmit(c, TCP_FLAG_ACK, true);
                DISCARD;
            }

            if (c->rcv_nxt > seq) {
                
                size_t delta = c->rcv_nxt - seq;
                
                memmove(payload.ptr, payload.ptr + delta, delta);
                
                payload.len -= delta;
                seq += delta;

            }

            assert(seq == c->rcv_nxt);
        }

        if (set(segment, TCP_FLAG_RST)) {
            switch (c->state) {

                case TCP_STATE_SYN_RCVD:
                // From RFC 9293, Section 3.10.7.4.
                //
                //   If this connection was initiated with a passive OPEN 
                //   (i.e., came from the LISTEN state), then return this 
                //   connection to LISTEN state and return. The user need 
                //   not be informed. If this connection was initiated with 
                //   an active OPEN (i.e., came from SYN-SENT state), then 
                //   the connection was refused; signal the user "connection 
                //   refused". In either case, the retransmission queue 
                //   should  be flushed. And in the active OPEN case, enter 
                //   the CLOSED state and delete the TCB, and return.

                // Since we don't implement "connect" yet, we can
                // assume the connection came from the LISTEN state.
                //
                // Since the connection was never ESTABLISHED, there
                // is no need to inform the user.
                really_close_connection(c);
                DISCARD;
                
                case TCP_STATE_ESTABLISHED: /* fallthrough */
                case TCP_STATE_FIN_WAIT_1:  /* fallthrough */
                case TCP_STATE_FIN_WAIT_2:  /* fallthrough */
                case TCP_STATE_CLOSE_WAIT:
                // From RFC 9293, Section 3.10.7.4
                //   If the RST bit is set, then any outstanding RECEIVEs and SEND 
                //   should receive "reset" responses. All segment queues should be 
                //   flushed. Users should also receive an unsolicited general 
                //   "connection reset" signal. Enter the CLOSED state, delete the 
                //   TCB, and return.
                if (c->cb_event) c->cb_event(c->cb_data, TCP_CONNEVENT_RESET);
                really_close_connection(c);
                DISCARD;

                case TCP_STATE_CLOSING:  /* fallthrough */
                case TCP_STATE_LAST_ACK: /* fallthrough */
                case TCP_STATE_TIME_WAIT:
                // From RFC 9293, Section 3.10.7.4.
                //   If the RST bit is set, then enter the CLOSED state, delete 
                //   the TCB, and return.
                really_close_connection(c);
                DISCARD;

                case TCP_STATE_CLOSED:
                case TCP_STATE_LISTEN:
                case TCP_STATE_SYN_SENT:
                /* UNREACHABLE */
                assert(0);
                DISCARD;
            }
        }

        // TODO: Check security

        if (set(segment, TCP_FLAG_SYN)) {
            bool passive_open = true;
            if (connstate == TCP_STATE_SYN_RCVD && passive_open) {
                // From RFC 9293, Section 3.10.7.4.
                //
                //   If the connection was initiated with a passive OPEN, then 
                //   return this connection to the LISTEN state and return. 
                //   Otherwise, handle per the directions for synchronized states 
                //   below.
                really_close_connection(c);
                DISCARD;

            } else {
                // From RFC 9293, Section 3.10.7.4.
                //
                //   If the SYN bit is set in these synchronized states, it may 
                //   be either a legitimate new connection attempt (e.g., in the 
                //   case of TIME-WAIT), an error where the connection should be 
                //   reset, or the result of an attack attempt, as described in 
                //   RFC 5961 [9]. For the TIME-WAIT state, new connections can 
                //   be accepted if the Timestamp Option is used and meets expectations 
                //   (per [40]). For all other cases, RFC 5961 provides a mitigation 
                //   with applicability to some situations, though there are also 
                //   alternatives that offer cryptographic protection (see Section 7). 
                //   RFC 5961 recommends that in these synchronized states, if 
                //   the SYN bit is set, irrespective of the sequence number, TCP 
                //   endpoints MUST send a "challenge ACK" to the remote peer: 
                //
                //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> 
                //
                //   After sending the acknowledgment, TCP implementations MUST 
                //   drop the unacceptable segment and stop processing further. 
                //   Note that RFC 5961 and Errata ID 4772 [99] contain additional 
                //   ACK throttling notes for an implementation. 
                //
                //   For implementations that do not follow RFC 5961, the original 
                //   behavior described in RFC 793 follows in this paragraph. If 
                //   the SYN is in the window it is an error: send a reset, any 
                //   outstanding RECEIVEs and SEND should receive "reset" responses, 
                //   all segment queues should be flushed, the user should also 
                //   receive an unsolicited general "connection reset" signal, 
                //   enter the CLOSED state, delete the TCB, and return. 
                //
                //   If the SYN is not in the window, 
                //   this step would not be reached and an ACK would have been sent 
                //   in the first step (sequence number check).
                //
                // This is a minimal implementation of TCP, so we only 
                // implement the RFC 793 part.
                transmit_rst(c, false);
                if (c->cb_event) c->cb_event(c->cb_data, TCP_CONNEVENT_RESET);
                really_close_connection(c);
                DISCARD;
            }
        }

        // From RFC 9293, Section 3.10.7.4.
        //
        //   if the ACK bit is off, 
        //
        //     drop the segment and return
        //
        if (!set(segment, TCP_FLAG_ACK))
            DISCARD; // Drop the segment
        
        ack = net_to_cpu_u32(segment->ack_no);
        switch (c->state) {

            case TCP_STATE_CLOSED:
            case TCP_STATE_LISTEN:
            case TCP_STATE_SYN_SENT:
            /* UNREACHABLE */
            assert(0);
            DISCARD;

            case TCP_STATE_SYN_RCVD:
            // From RFC 9293, Section 3.10.7.4.
            //
            //   If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state 
            //   and continue processing with the variables below set to:
            //
            //     SND.WND <- SEG.WND
            //     SND.WL1 <- SEG.SEQ
            //     SND.WL2 <- SEG.ACK
            //
            //   If the segment acknowledgment is not acceptable, form a reset 
            //   segment
            //
            //     <SEQ=SEG.ACK><CTL=RST>
            //
            //   and send it.

            if (c->snd_una >= ack || ack > c->snd_nxt) {
                // Segment isn't acceptable
                transmit_reply_rst(tcp, sender, *segment, ack, 0);
                DISCARD;
            }

            c->state = TCP_STATE_ESTABLISHED;
            c->snd_wnd = net_to_cpu_u16(segment->window);
            c->snd_wl1 = seq;
            c->snd_wl2 = ack;

            // Move connection from the non-established to
            // the queue
            move_from_non_established_list_to_non_accepted_queue(c);
            listener->cb_event(listener->cb_data, TCP_LISTENEVENT_ACCEPT);
            
            /* fallthrough */

            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            case TCP_STATE_CLOSE_WAIT:
            case TCP_STATE_CLOSING:
            // From RFC 9293, Section 3.10.7.4.
            //
            //   If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK. 
            //   Any segments on the retransmission queue that are thereby entirely 
            //   acknowledged are removed. Users should receive positive acknowledgments 
            //   for buffers that have been SENT and fully acknowledged (i.e., 
            //   SEND buffer should be returned with "ok" response). If the ACK 
            //   is a duplicate (SEG.ACK =< SND.UNA), it can be ignored. If the 
            //   ACK acks something not yet sent (SEG.ACK > SND.NXT), then send 
            //   an ACK, drop the segment, and return.
            //
            //   If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be 
            //   updated. If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and 
            //   SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set SND.WL1 <- SEG.SEQ, 
            //   and set SND.WL2 <- SEG.ACK. 
            //
            //   Note that SND.WND is an offset from SND.UNA, that SND.WL1 records 
            //   the sequence number of the last segment used to update SND.WND, 
            //   and that SND.WL2 records the acknowledgment number of the last 
            //   segment used to update SND.WND. The check here prevents using 
            //   old segments to update the window.
            TCP_DEBUG_LOG("ack=%lld, UNA=%lld, NXT=%lld", ack, c->snd_una, c->snd_nxt);
            if (ack > c->snd_nxt) {
                // Peer acked something not sent yet
                transmit(c, TCP_FLAG_ACK, true);
                DISCARD;
            }

            if (ack > c->snd_una) {

                /* ACK isn't a duplicate */

                forget_acked(c, ack);
                
                // If everything was ACKed, disable the retransmission timer
                if (ack == c->snd_nxt)
                    if (c->retr_timer) {
                        tcp_timer_disable(c->retr_timer);
                        c->retr_timer = NULL;
                    }

                // Update send window
                if (c->snd_wl1 < seq || (c->snd_wl1 == seq && c->snd_wl2 <= ack)) {

                    c->snd_wnd = net_to_cpu_u16(segment->window);
                    c->snd_wl1 = seq;
                    c->snd_wl2 = ack;
                }
            }

            switch (c->state) {
                case TCP_STATE_FIN_WAIT_1:
                // From RFC 9293, Section 3.10.7.4.
                //
                //   In addition to the processing for the ESTABLISHED state, if the 
                //   FIN segment is now acknowledged, then enter FIN-WAIT-2 and 
                //   continue processing in that state.
                
                if (ack < c->snd_nxt)
                    break; // Not everything was ACKed by the peer, so the FIN wasn't ACKed

                // The FIN was ACKed so it's possible to transition to the
                // FIN-WAIT-2 state.
                c->state = TCP_STATE_FIN_WAIT_2;

                /* fallthrough */

                case TCP_STATE_FIN_WAIT_2:
                // From RFC 9293, Section 3.10.7.4.
                //   In addition to the processing for the ESTABLISHED state, if the 
                //   retransmission queue is empty, the user's CLOSE can be acknowledged 
                //   ("ok") but do not delete the TCB.
                //
                // Nothing to be done! The fact we sent a FIN implies that
                // the user dropped the reference to the tcp socket, so
                // there's nothing to acknowledge.
                break;

                case TCP_STATE_CLOSING:

                // From RFC 9293, Section 3.10.7.4.
                //
                //   In addition to the processing for the ESTABLISHED state, if the 
                //   ACK acknowledges our FIN, then enter the TIME-WAIT state; 
                //   otherwise, ignore the segment.
                TCP_DEBUG_LOG("ACK with seq=%lld, ack=%lld reached here (NXT=%lld)", seq, ack, c->snd_nxt);
                if (ack == c->snd_nxt) {
                    TCP_DEBUG_LOG("And here");
                    // Everything was ACKed, so if a FIN was sent that was ACKed too.
                    transition_to_time_wait(c);
                }
                DISCARD; // Ignore the segment

                default:
                break;
            }
            break;
            
            case TCP_STATE_LAST_ACK:
            // From RFC 9293, Section 3.10.7.4.
            //   The only thing that can arrive in this state is an acknowledgment 
            //   of our FIN. If our FIN is now acknowledged, delete the TCB, enter 
            //   the CLOSED state, and return.

            if (ack == c->snd_nxt)
                // Everything was ACKed by peer, so the FIN also.
                really_close_connection(c);
            DISCARD;
            
            case TCP_STATE_TIME_WAIT:
            // From RFC 9293, Section 3.10.7.4.
            //
            //   The only thing that can arrive in this state is a retransmission 
            //   of the remote FIN. Acknowledge it, and restart the 2 MSL timeout.

            // TODO
            break;
        }

        if (set(segment, TCP_FLAG_URG)) {
            // This is a minimal implementation, so we ignore the urgent flag
            // .. Do nothing ..
            TCP_DEBUG_LOG("Ignoring URG flag");
        }

        // Process the segment text
        switch (c->state) {
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT_1:
            case TCP_STATE_FIN_WAIT_2:
            // From RFC 9293, Section 3.10.7.4.
            //
            //   Once in the ESTABLISHED state, it is possible to deliver segment 
            //   data to user RECEIVE buffers. Data from segments can be moved 
            //   into buffers until either the buffer is full or the segment is 
            //   empty. If the segment empties and carries a PUSH flag, then the 
            //   user is informed, when the buffer is returned, that a PUSH has 
            //   been received. 
            //
            //   When the TCP endpoint takes responsibility for delivering the 
            //   data to the user, it must also acknowledge the receipt of the data. 
            //
            //   Once the TCP endpoint takes responsibility for the data, it advances 
            //   RCV.NXT over the data accepted, and adjusts RCV.WND as appropriate 
            //   to the current buffer availability. The total of RCV.NXT and RCV.WND 
            //   should not be reduced. 
            //
            //   A TCP implementation MAY send an ACK segment acknowledging RCV.NXT 
            //   when a valid segment arrives that is in the window but not at the 
            //   left window edge (MAY-13). Please note the window management suggestions 
            //   in Section 3.8.
            //
            //   Send an acknowledgment of the form: 
            //
            //     <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> 
            //
            //   This acknowledgment should be piggybacked on a segment being 
            //   transmitted if possible without incurring undue delay.
            {
                size_t num = move_data_into_input_buffer(c, payload);
                if (num > 0) {
                    transmit(c, TCP_FLAG_ACK, false);
                    if (c->cb_event) c->cb_event(c->cb_data, TCP_CONNEVENT_RECV);
                }
            }
            break;

            case TCP_STATE_CLOSE_WAIT:
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
            case TCP_STATE_TIME_WAIT:
            // From RFC 9293, Section 3.10.7.4.
            //   This should not occur since a FIN has been received from the remote side. 
            //   Ignore the segment text.
            break;

            default:
            /* UNREACHABLE */
            DISCARD;
        }

        if (set(segment, TCP_FLAG_FIN)) {
            // From RFC 9293, Section 3.10.7.4.
            //   Do not process the FIN if the state is CLOSED, LISTEN, or SYN-SENT since 
            //   the SEG.SEQ cannot be validated; drop the segment and return.
            //
            //   If the FIN bit is set, signal the user "connection closing" and return 
            //   any pending RECEIVEs with same message, advance RCV.NXT over the FIN, and 
            //   send an acknowledgment for the FIN. Note that FIN implies PUSH for any 
            //   segment text not yet delivered to the user.
            //
            c->rcv_nxt++;
            transmit(c, TCP_FLAG_ACK, true);
            
            switch (c->state) {
                case TCP_STATE_SYN_RCVD:
                case TCP_STATE_ESTABLISHED:
                transmit(c, TCP_FLAG_FIN | TCP_FLAG_ACK, true);
                if (c->cb_event) c->cb_event(c->cb_data, TCP_CONNEVENT_CLOSE);
                c->state = TCP_STATE_CLOSE_WAIT;
                break;

                case TCP_STATE_FIN_WAIT_1:
                // From RFC 9293, Section 3.10.7.4.
                //   If our FIN has been ACKed (perhaps in this segment), then enter TIME-WAIT, 
                //   start the time-wait timer, turn off the other timers; otherwise, enter the 
                //   CLOSING state.

                if (ack == c->snd_nxt) {
                    // Our FIN was ACKed
                    transition_to_time_wait(c);
                }
                else
                    c->state = TCP_STATE_CLOSING;
                break;

                case TCP_STATE_FIN_WAIT_2:
                // From RFC 9293, Section 3.10.7.4.
                //   Enter the TIME-WAIT state. Start the time-wait timer, turn off the other 
                //   timers.
                transition_to_time_wait(c);
                break;

                case TCP_STATE_TIME_WAIT:
                // From RFC 9293, Section 3.10.7.4.
                //   Remain in the TIME-WAIT state. Restart the 2 MSL time-wait timeout.
                
                // TODO: Restart the TIME-WAIT timer
                break;

                default:
                // Possible states here are:
                //   - TCP_STATE_CLOSE_WAIT
                //   - TCP_STATE_CLOSING
                //   - TCP_STATE_LAST_ACK
                //
                // Nothing to be done!
                break;
            }
        }
        break;
    }
}

tcp_listener_t*
tcp_listener_create(tcp_state_t *state, uint16_t port, bool reuse,
                    void *cb_data, tcp_listeneventcb_t cb_event)
{
    tcp_listener_t *listener;

    listener = find_listener(state, port);
    if (listener && (!listener->closed || !reuse)) {
        // ERROR: A connection is already listening on this port
        TCP_DEBUG_LOG("Faile to create listener on port %d because there already exists one", port);
        return NULL;
    }

    if (listener) {
        listener->closed = false;
        listener->cb_data = cb_data;
        listener->cb_event = cb_event;
    } else {

        // Pop a listener connection structure from the free list
        if (state->free_listener_list == NULL) {
            // ERROR: Reached listener connection limit
            TCP_DEBUG_LOG("TCP connection limit");
            return NULL;
        }
        listener = state->free_listener_list;
        state->free_listener_list = listener->next;

        // Initialize listener structure
        listener->state  = state;
        listener->closed = false;
        listener->port = port;
        listener->count = 0;
        listener->accepted = NULL;
        listener->noestab = NULL;
        listener->qhead = NULL;
        listener->qtail = NULL;
        listener->cb_data = cb_data;
        listener->cb_event = cb_event;

        // Push listener connection structure to the used list
        listener->prev = NULL;
        listener->next = state->used_listener_list;
        if (state->used_listener_list)
            state->used_listener_list->prev = listener;
        state->used_listener_list = listener;
    }
    return listener;
}

void tcp_listener_destroy(tcp_listener_t *listener)
{
    listener->closed = true;
    if (listener->count == 0)
        really_close_listener(listener);
}

tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener, void *cb_data, tcp_conneventcb_t cb_event)
{
    if (!listener->qhead)
        // Nothing to accept
        return NULL;
    assert(listener->qtail);

    tcp_connection_t *c;

    // Pop connection from the tail of the accept queue
    {
        c = listener->qtail;
        if (c->prev)
            // ->prev isn't NULL so this isn't the first element of 
            // the queue. Therefore we need to update the ->next pointer
            // of the previous node.
            c->prev->next = NULL;
        else
            // ->prev is NULL so this is the first element of the queue.
            // We need to update the reference to the head of the list
            listener->qhead = NULL;

        assert(c->next == NULL); // This is the last element of the queue so
                                 // it has no following node.
        listener->qtail = c->prev;
    }

    // Push it to the head of the accepted list
    {
        c->prev = NULL;
        c->next = listener->accepted;

        if (listener->accepted)
            listener->accepted->prev = c;
        listener->accepted = c;
    }

    c->cb_data = cb_data;
    c->cb_event = cb_event;
    return c;
}

void tcp_connection_destroy(tcp_connection_t *c)
{
    // The [destroy] method implies the connection was
    // returned throigh [accept], which implies it's
    // at least in an ESTABLISHED state. Therefore
    // the SYN-SENT and SYN-RCVD states are unreachable.
    switch (c->state) {

        case TCP_STATE_CLOSED:
        case TCP_STATE_LISTEN:
        /* UNREACHABLE */
        assert(0);
        break;
        
        case TCP_STATE_SYN_SENT:
        // From RFC 9293, Section 3.10.4.
        //   Delete the TCB and return "error: closing" responses to 
        //   any queued SENDs, or RECEIVEs.
        assert(0);
        break;
        
        case TCP_STATE_SYN_RCVD:
        // From RFC 9293, Section 3.10.4.
        //   If no SENDs have been issued and there is no pending data 
        //   to send, then form a FIN segment and send it, and enter 
        //   FIN-WAIT-1 state; otherwise, queue for processing after 
        //   entering ESTABLISHED state.
        assert(0);
        break;

        case TCP_STATE_ESTABLISHED:
        // From RFC 9293, Section 3.10.4.
        //   Queue this until all preceding SENDs have been segmentized, 
        //   then form a FIN segment and send it. In any case, enter 
        //   FIN-WAIT-1 state.
        c->state = TCP_STATE_FIN_WAIT_1;
        transmit(c, TCP_FLAG_FIN | TCP_FLAG_ACK, true);
        break;

        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        // From RFC 9293, Section 3.10.4.
        //   Strictly speaking, this is an error and should receive an 
        //   "error: connection closing" response. An "ok" response would 
        //   be acceptable, too, as long as a second FIN is not emitted 
        //   (the first FIN may be retransmitted, though).
        //
        // Being in the FIN-WAIT-1 (or FIN-WAIT-2 which follows it)
        // implies that the user already closed the connection, so
        // calling the closing method again is an illegal use of the
        // API.
        assert(0);
        break;

        case TCP_STATE_CLOSE_WAIT:
        // From RFC 9293, Section 3.10.4.
        //   Queue this request until all preceding SENDs have been segmentized; 
        //   then send a FIN segment, enter LAST-ACK state.
        
        transmit(c, TCP_FLAG_FIN | TCP_FLAG_ACK, true);
        // When the FIN will be sent, since it was sent in the
        // CLOSE-WAIT state, the state will change to LAST-ACK.
        break;

        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
        // From RFC 9293, Section 3.10.4.
        //   Respond with "error: connection closing".
        //
        // The user tried to close the socket twice.
        assert(0);
        break;

    }
}

size_t tcp_connection_recv(tcp_connection_t *connection, 
                           void *dst, size_t len)
{
    slice_t s = { .ptr=dst, .len=len };

    size_t num;
    switch (connection->state) {
        
        case TCP_STATE_CLOSED:
        /* UNREACHABLE */
        assert(0);
        break;

        case TCP_STATE_LISTEN:
        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RCVD:
        // From RFC 9293, Section 3.10.3.
        //   Queue for processing after entering ESTABLISHED state. If there is no 
        //   room to queue this request, respond with "error: insufficient resources".
        //
        // The [recv] method can only be called after a connection is returned 
        // throigh [accept], which implied an ESTABLISHED state. This case isn't
        // reachable.
        assert(0);
        break;

        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        // From RFC 9293, Section 3.10.3.
        //   If insufficient incoming segments are queued to satisfy the request, queue 
        //   the request. If there is no queue space to remember the RECEIVE, respond 
        //   with "error: insufficient resources".
        //
        //   Reassemble queued incoming segments into receive buffer and return to user. 
        //   Mark "push seen" (PUSH) if this is the case.
        //
        //   If RCV.UP is in advance of the data currently being passed to the user, 
        //   notify the user of the presence of urgent data.
        //
        //   When the TCP endpoint takes responsibility for delivering data to the user, 
        //   that fact must be communicated to the sender via an acknowledgment. The 
        //   formation of such an acknowledgment is described below in the discussion 
        //   of processing an incoming segment.
        num = move_from_idata(connection, s);
        break;

        case TCP_STATE_CLOSE_WAIT:
        // From RFC 9293, Section 3.10.3.
        //   Since the remote side has already sent FIN, RECEIVEs must be satisfied by 
        //   data already on hand, but not yet delivered to the user. If no text is 
        //   awaiting delivery, the RECEIVE will get an "error: connection closing" 
        //   response. Otherwise, any remaining data can be used to satisfy the RECEIVE.
        num = move_from_idata(connection, s);
        break;

        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
        // From RFC 9293, Section 3.10.3.
        //   Return "error: connection closing".
        //
        // TODO: Find a way to report an error
        num = 0;
        break;
    }
    
    return num;
}

static size_t 
append_to_odata(tcp_connection_t *connection, 
                        const void *src, size_t len)
{
    size_t capacity = TCP_OBUFFER_SIZE - connection->oused;
    size_t num = MIN(len, capacity);

    memcpy(connection->odata + connection->oused, src, num);
    connection->oused += num;

    return num;
}

size_t tcp_connection_send(tcp_connection_t *c, const void *src, size_t len)
{
    size_t num;
    switch (c->state) {

        case TCP_STATE_LISTEN:
        /* UNREACHABLE */
        assert(0);
        break;

        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RCVD:
        // It should not be possible to reach this point
        // since the [send] method can only be called after
        // an [accept], which implies an ESTABLISHED socket.
        assert(0);
        break;

        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_CLOSE_WAIT:
        // From RFC 9293, Section 3.10.2.
        //   Segmentize the buffer and send it with a piggybacked acknowledgment 
        //   (acknowledgment value = RCV.NXT). If there is insufficient space to 
        //   remember this buffer, simply return "error: insufficient resources".
        //
        //   If the URGENT flag is set, then SND.UP <- SND.NXT and set the urgent 
        //   pointer in the outgoing segments.
        //
        // (We don't support the urgent pointer)
        num = append_to_odata(c, src, len);
        if (num > 0)
            transmit(c, TCP_FLAG_ACK, false);
        break;

        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
        // From RFC 9293, Section 3.10.2.
        //   Return "error: connection closing" and do not service request.
        num = 0;
        // TODO: Report an error some way
        break;

        case TCP_STATE_CLOSED:
        assert(0);
        break;

        default:
        assert(0);
        break;
    }
    return num;
}