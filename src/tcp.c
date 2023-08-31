#include <string.h>
#include <stdbool.h>
#include <stdalign.h>

#ifndef MICROTCP_AMALGAMATION
#   include "endian.h"
#   include "tcp.h"
#endif

#ifdef TCP_DEBUG
#   include <stdio.h>
#   define TCP_DEBUG_LOG(fmt, ...) fprintf(stderr, "TCP :: " fmt "\n", ## __VA_ARGS__)
#else
#   define TCP_DEBUG_LOG(...)
#endif

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
connection_create(tcp_listener_t *listener, uint32_t seq_no, 
                  uint32_t ack_no, ip_address_t peer_ip, uint16_t peer_port)
{
    tcp_state_t *state = listener->state;

    // Pop a connection structure from the free list
    tcp_connection_t *connection;
    {
        if (state->free_connection_list == NULL)
            // ERROR: Reached connection limit
            return NULL;
        connection = state->free_connection_list;
        state->free_connection_list = connection->next;
    }

    // Initialize connection structure
    {
        connection->listener = listener;
        
        connection->callback_data = NULL;
        connection->callback_ready_to_recv = NULL;
        connection->callback_ready_to_send = NULL;

        connection->state = TCP_STATE_CLOSED;

        connection->estimated_rtt = 0;
        connection->estimated_dev = 0;

        connection->calculating_rtt = false;
        connection->rtt_calc_seq = 0;
        connection->rtt_calc_time = 0;

        connection->retr_timer = NULL;

        connection->peer_port = peer_port;
        connection->peer_ip   = peer_ip;

        connection->rcv_unread = ack_no;
        connection->rcv_nxt = ack_no;
        connection->rcv_wnd = TCP_INPUT_BUFFER_SIZE;

        connection->snd_una = seq_no;
        connection->snd_wnd = 0;
        connection->snd_nxt = seq_no;

        connection->in_buffer_syn = false;
        connection->in_buffer_fin = false;

        connection->prev = NULL;
        connection->next = NULL;
    }

    // Appent to the list of not yet established connections 
    if (listener->non_established_list)
        listener->non_established_list->prev = connection;
    connection->next = listener->non_established_list;
    listener->non_established_list = connection;

    return connection;
}

static void
signal_ready_to_send(tcp_connection_t *c)
{
    if (c->callback_ready_to_send)
        c->callback_ready_to_send(c->callback_data);
}

static void
signal_ready_to_recv(tcp_connection_t *c)
{
    if (c->callback_ready_to_recv)
        c->callback_ready_to_recv(c->callback_data);
}

static void
signal_ready_to_accept(tcp_listener_t *l)
{
    if (l->callback_ready_to_accept)
        l->callback_ready_to_accept(l->callback_data);
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

typedef struct {
    ip_address_t src_addr;
    ip_address_t dst_addr;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t tcp_length;
} tcp_pseudoheader_t; // Ensure packed?

static uint16_t 
calculate_byte_checksum(const slice_t *slices, size_t num_slices)
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

static tcp_segment_t
compile_segment(uint32_t wnd, uint8_t flags,
                uint16_t sport, uint16_t dport, 
                uint32_t seq_no, uint32_t ack_no)
{
    tcp_segment_t header;
    //memset(header, 0, sizeof(tcp_segment_t));

    int offset = 5; // No options
    header.src_port = cpu_to_net_u16(sport);
    header.dst_port = cpu_to_net_u16(dport);
    header.flags    = flags;
    header.seq_no   = cpu_to_net_u32(seq_no);
    header.ack_no   = cpu_to_net_u32(ack_no);
    header.offset1  = cpu_is_little_endian() ? 0 : offset;
    header.offset2  = cpu_is_little_endian() ? offset : 0;
    header.window   = cpu_to_net_u16(wnd); // Why is a 32 bit integer being backed into a 16 bit?
    header.checksum = 0; // Will be calculated later
    header.urgent_pointer = 0;

    return header;
}

static uint16_t
calculate_header_checksum(tcp_segment_t header, slice_t data,
                          ip_address_t self_ip, ip_address_t peer_ip)
{
    tcp_pseudoheader_t pseudo;

    pseudo.src_addr = self_ip;
    pseudo.dst_addr = peer_ip;
    pseudo.reserved = 0;
    pseudo.protocol = 6; // TCP
    pseudo.tcp_length = cpu_to_net_u16(sizeof(tcp_segment_t) + data.len);

    slice_t list[] = { SLICE(pseudo), SLICE(header), data };
    return calculate_byte_checksum(list, COUNT(list));
}

static void
compile_checksum(tcp_segment_t *header, slice_t data, 
                 ip_address_t self_ip, ip_address_t peer_ip)
{
    header->checksum = calculate_header_checksum(*header, data, self_ip, peer_ip);
}

static int 
emit_segment_bytes(tcp_state_t *tcp, ip_address_t ip, 
                   tcp_segment_t header, slice_t data)
{
    slice_t slices[] = { SLICE(header), data };
    return tcp->callbacks.send(tcp->callbacks.data, ip, slices, COUNT(slices));
}

static slice_t 
get_pending_output_data(tcp_connection_t *c, size_t max)
{
    // [snd_wnd + snd_una - snd_nxt] is the number of bytes that
    // are in the output buffer but weren't sent yet

    size_t available;
    if (c->snd_nxt <= c->snd_wnd + c->snd_una)
        available = c->snd_wnd + c->snd_una - c->snd_nxt;
    else
        available = 0;

    slice_t s;
    s.ptr = c->out_buffer + c->snd_nxt - c->snd_una;
    s.len = MIN(max, available);
    return s;
}

#ifdef TCP_DEBUG
static void 
emit_segment_inner(tcp_connection_t *c, uint8_t flags, 
                   size_t max_payload, bool retransmit,
                   const char *file, int line);
#define emit_segment(c, flags, max_payload, retransmit) \
    emit_segment_inner(c, flags, max_payload, retransmit, __FILE__, __LINE__)
#else
static void 
emit_segment(tcp_connection_t *c, uint8_t flags, 
             size_t max_payload, bool retransmit);
#endif

static void 
timeout_callback_retransmit(void *p)
{
    tcp_connection_t *c = p;
    TCP_DEBUG_LOG("Retransmitting");
    emit_segment(c, TCP_FLAG_ACK, SIZE_MAX, true);
    c->retr_timer = NULL;
}

static uint64_t
calc_retr_timeout(tcp_connection_t *c)
{
    #define MIN_RETRANSMISSION_TIMEOUT  1000
    #define MAX_RETRANSMISSION_TIMEOUT 60000

    uint64_t timeout = c->estimated_rtt + 4 * c->estimated_dev;
    timeout = MIN(timeout, MAX_RETRANSMISSION_TIMEOUT);
    timeout = MAX(timeout, MIN_RETRANSMISSION_TIMEOUT);
    return timeout;
}

static void 
start_retr_timer(tcp_connection_t *c)
{
    tcp_state_t *state = c->listener->state;
    
    uint64_t timeout = calc_retr_timeout(c);
    tcp_timer_t *timer = tcp_timer_create(&state->timers, timeout, "retr", 
                                          timeout_callback_retransmit, c);
    if (timer == NULL)
        TCP_DEBUG_LOG("Failed to start retransmission timer");
    else
        TCP_DEBUG_LOG("Retransmission timer started (%d ms)", (int) timeout);
    c->retr_timer = timer;
}

static void
stop_retr_timer(tcp_connection_t *c)
{
    if (c->retr_timer) {
        TCP_DEBUG_LOG("Retransmission timer disabled");
        tcp_timer_disable(c->retr_timer);
        c->retr_timer = NULL;
    }
}

static slice_t 
get_output_data(tcp_connection_t *c)
{
    slice_t s;
    s.ptr = c->out_buffer;
    s.len = c->snd_wnd;
    return s;
}

// Send a tcp segment on the connection
// with a maximum payload of "payload" and
// the specified flags.

#ifdef TCP_DEBUG
static void 
emit_segment_inner(tcp_connection_t *c, uint8_t flags, 
                   size_t max_payload, bool retransmit,
                   const char *file, int line)
{
    {
        char peer_ip[16];
        snprintf(peer_ip, sizeof(peer_ip), 
                 "%d.%d.%d.%d",
                 c->peer_ip >> 24 & 0xff, 
                 c->peer_ip >> 16 & 0xff,
                 c->peer_ip >> 8  & 0xff, 
                 c->peer_ip >> 0  & 0xff);

        const char *flags_str;
        switch (flags) {
            case TCP_FLAG_FIN: flags_str = "FUN"; break;
            case TCP_FLAG_SYN: flags_str = "SYN"; break;
            case TCP_FLAG_RST: flags_str = "RST"; break;
            case TCP_FLAG_PUSH: flags_str = "PUSH"; break;
            case TCP_FLAG_ACK: flags_str = "ACK"; break;
            case TCP_FLAG_URG: flags_str = "URG"; break;
            case TCP_FLAG_SYN 
               | TCP_FLAG_ACK: flags_str = "SYN|ACK"; break;
            case TCP_FLAG_FIN 
               | TCP_FLAG_ACK: flags_str = "FIN|ACK"; break;
            default: flags_str="??"; break;
        }

        TCP_DEBUG_LOG("emit_segment(peer=%s:%d, flags=%s, retransmit=%s) in %s:%d", 
                      peer_ip, c->peer_port, flags_str, retransmit ? "true" : "false",
                      file, line);
    }
#else
static void 
emit_segment(tcp_connection_t *c, uint8_t flags, 
             size_t max_payload, bool retransmit)
{
#endif
    tcp_listener_t *listener = c->listener;
    tcp_state_t    *state    = listener->state;

    slice_t data;
    if (retransmit) {
        data = get_output_data(c);
        if (c->in_buffer_syn) flags |= TCP_FLAG_SYN;
        if (c->in_buffer_fin) flags |= TCP_FLAG_FIN;
    } else
        data = get_pending_output_data(c, max_payload);

    uint16_t  sport = listener->port;
    uint16_t  dport = c->peer_port;
    uint32_t ack_no = (flags & TCP_FLAG_ACK) ? c->rcv_nxt : 0;
    uint32_t seq_no = c->snd_nxt;

    ip_address_t self_ip = state->ip;
    ip_address_t peer_ip = c->peer_ip;

    tcp_segment_t header = compile_segment(c->rcv_wnd, flags, 
                                           sport, dport, 
                                           seq_no, ack_no);
    compile_checksum(&header, data, 
                     self_ip, peer_ip);
    
    int result = emit_segment_bytes(state, peer_ip, header, data);

    if (result < 0)
        return; // It wasn't possible to send out bytes. 
                // We'll try again later!

    if (result < (int) sizeof(tcp_segment_t)) { // What about options??
        // Not even the TCP header was sent. 
        // I hope this nexer happens!
        assert(0);
        return;
    }

    size_t sent_data = result - sizeof(tcp_segment_t);
    if (flags & TCP_FLAG_SYN) sent_data++;
    if (flags & TCP_FLAG_FIN) sent_data++;

    if (!retransmit) {
        c->snd_nxt += sent_data;
        if (flags & TCP_FLAG_SYN) c->in_buffer_syn = true;
        if (flags & TCP_FLAG_FIN) c->in_buffer_fin = true;
    }

    bool expect_ack = (sent_data > 0);

    if (expect_ack)
        // Something that needs to be ACKed by peer was sent.
        // Start the retransmission timer.
        start_retr_timer(c);

    if (c->calculating_rtt == false && expect_ack) {
        c->calculating_rtt = true;
        c->rtt_calc_seq = seq_no;
        c->rtt_calc_time = c->listener->state->timers.current_time_ms;
    }
}

static slice_t
get_input_data(tcp_connection_t *c)
{
    slice_t s;
    s.ptr = c->in_buffer;
    s.len = TCP_INPUT_BUFFER_SIZE - c->rcv_wnd;
    return s;
}

static size_t
move_data_from_input_buffer(tcp_connection_t *c, slice_t dst)
{
    slice_t buf = get_input_data(c);
    size_t unread = (c->rcv_nxt - c->rcv_unread);
    size_t moving = MIN(dst.len, unread);
    
    if (moving > 0) {
        memcpy(dst.ptr, buf.ptr, moving);
        memmove(buf.ptr, buf.ptr + moving, buf.len - moving);
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
        memcpy(buf.ptr + buf.len, src.ptr, moving);
        c->rcv_wnd -= moving;
        c->rcv_nxt += moving;
    }

    return moving;
}

static tcp_connection_t*
find_connection(tcp_listener_t *listener, ip_address_t peer_ip, uint16_t peer_port)
{
    tcp_connection_t *connection;

    // Check in the accepted list
    connection = listener->accepted_list;
    while (connection) {
        if (connection->peer_port == peer_port && 
            connection->peer_ip == peer_ip)
            break;
        connection = connection->next;
    }
    if (connection) {
        // accepted=true
    } else {
        // accepted=false
        connection = listener->non_accepted_queue_head;
        while (connection) {
            if (connection->peer_port == peer_port && 
                connection->peer_ip == peer_ip)
                break;
            connection = connection->next;
        }
    }
    if (connection) {
        // established=true
    } else {
        // established=false
        connection = listener->non_established_list;
        while (connection) {
            if (connection->peer_port == peer_port && 
                connection->peer_ip == peer_ip)
                break;
            connection = connection->next;
        }
    }
    return connection;
}

static void 
move_from_non_established_list_to_non_accepted_queue(tcp_connection_t *connection)
{
    tcp_listener_t *listener = connection->listener;

    // Unlink the structure from the non established list
    {
        if (connection->prev)
            connection->prev->next = connection->next;
        else
            listener->non_established_list = connection->next;

        if (connection->next)
            connection->next->prev = connection->prev;
    }

    // Push it into the non accepted queue
    connection->prev = NULL;
    connection->next = listener->non_accepted_queue_head;
    if (listener->non_accepted_queue_head)
        listener->non_accepted_queue_head->prev = connection;
    else
        listener->non_accepted_queue_tail = connection;
    listener->non_accepted_queue_head = connection;
}

static void
update_rtt_estimation(tcp_connection_t *c, uint64_t sample_rtt)
{
    uint64_t estimated_rtt = c->estimated_rtt;
    uint64_t estimated_dev = c->estimated_dev;

    uint64_t sample_dev = ABS((int) sample_rtt - (int) estimated_rtt);

    float a = 0.9;
    float b = 0.125;

    estimated_rtt = a * sample_rtt + (1 - a) * estimated_rtt;
    estimated_dev = b * sample_dev + (1 - b) * estimated_dev;

    c->estimated_rtt = estimated_rtt;
    c->estimated_dev = estimated_dev;
}

static bool ack_until(tcp_connection_t *c, uint32_t ack_no)
{
    // Set sent but unacknowledged bytes with sequence
    // numbers up to [ack_no] as acknowledged. This [ack_no]
    // comes from the network so it must be verified.
    //
    // If at least one byte was marked as acknowledged, then
    // true is returned, else false.

    if (ack_no <= c->snd_una) {
        TCP_DEBUG_LOG("Received segment acknowledged again %d", ack_no);
        return false;
    }

    if (ack_no > c->snd_nxt) {
        // Peer ACKed unsent data. The right course of action
        // is probably to drop the c.
        TCP_DEBUG_LOG("Received segment acknowledged unsent data "
                      "with sequence number %d, but %d still wasn't sent", 
                      ack_no, c->snd_nxt);
        return false; // For now we'll just ignore the segment.
    }
    
    size_t newly_acked_bytes = ack_no - c->snd_una;
    
    if (ack_no > 1) {
        
        // Only remove data from the output buffer when
        // the acked data wasn't a ghost byte
        
        memmove(c->out_buffer, 
                c->out_buffer + newly_acked_bytes, 
                c->snd_wnd - newly_acked_bytes);

        c->snd_wnd -= newly_acked_bytes;
    }
    c->snd_una = ack_no;
    c->in_buffer_syn = false;

    if (ack_no >= c->snd_nxt) { // snd_nxt-1?
        // Peer acked everything there was to ack
        stop_retr_timer(c);
        c->in_buffer_fin = false;
    }

    if (c->calculating_rtt) {
        if (ack_no >= c->rtt_calc_seq) {
            uint64_t time_beg = c->rtt_calc_time;
            uint64_t time_end = c->listener->state->timers.current_time_ms;
            uint64_t sample_rtt = (time_end - time_beg);
            update_rtt_estimation(c, sample_rtt);
            c->calculating_rtt = false;
        }
    }

    return true;
}

static void
really_close_listener(tcp_listener_t *listener)
{
    tcp_state_t *state = listener->state;

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

static bool listener_has_no_connections(const tcp_listener_t *listener)
{
    return listener->accepted_list == NULL 
        && listener->non_established_list == NULL 
        && listener->non_accepted_queue_head == NULL;
}

static void 
really_close_connection(tcp_connection_t *connection)
{
    tcp_listener_t *listener = connection->listener;
    tcp_state_t *state = listener->state;

    // Pop connection from the list it's in
    tcp_connection_t *next = connection->next;
    if (connection->prev)
        connection->prev->next = next;
    else if (listener->accepted_list == connection)
        listener->accepted_list = next;
    else if (listener->non_established_list == connection)
        listener->non_established_list = next;
    else if (listener->non_accepted_queue_head == connection)
        listener->non_accepted_queue_head = next;        
    tcp_connection_t *prev = connection->prev;
    if (next)
        connection->next->prev = prev;
    else if (listener->non_accepted_queue_tail == connection)
        listener->non_accepted_queue_tail = prev;

    // Push it into the free connection list
    connection->prev = NULL;
    connection->next = state->free_connection_list;
    state->free_connection_list = connection;

    // If the listener is waiting to be closed
    // and this was the last connection it was
    // holding, then free the listener
    if (listener->closed == true && listener_has_no_connections(listener))
        really_close_listener(listener);
}

static void timeout_callback_time_wait(void *data)
{
    tcp_connection_t *connection = data;
    assert(connection->state == TCP_STATE_TIME_WAIT);

    TCP_DEBUG_LOG("TIME-WAIT -> CLOSED");

    // We can finally free up this connection structure!
    really_close_connection(connection);
}

static void
change_state_to_time_wait(tcp_connection_t *c)
{
    tcp_state_t *state = c->listener->state;
    c->state = TCP_STATE_TIME_WAIT;

    stop_retr_timer(c);

    // Don't close the connection just now but
    // wait for a given amount of time first.
    if (!tcp_timer_create(&state->timers, TCP_TIMEOUT_TIME_WAIT, "wait", 
                          timeout_callback_time_wait, c)) {
        assert(0);
    }
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

static bool 
set(tcp_segment_t *segment, int flags)
{
    return segment->flags & flags != 0;
}

static bool
issyn(tcp_segment_t *segment)
{
    return set(segment, TCP_FLAG_SYN);
}

static bool
isack(tcp_segment_t *segment)
{
    return set(segment, TCP_FLAG_ACK);
}

static bool
isfin(tcp_segment_t *segment)
{
    return set(segment, TCP_FLAG_FIN);
}

void tcp_process_segment(tcp_state_t *state, ip_address_t sender,
                         tcp_segment_t *segment, size_t len)
{
//    TCP_DEBUG_LOG("Received TCP segment");

    {
        tcp_timer_t *timer = state->timers.used_list;
        TCP_DEBUG_LOG("Timers: [ ");
        while (timer) {
            TCP_DEBUG_LOG("  %s - %2.2fs", timer->name, (float) (timer->deadline - state->timers.current_time_ms) / 1000);
            timer = timer->next;
        }
        TCP_DEBUG_LOG("]");
    }

    slice_t payload = segment_payload(segment, len);
    
    uint16_t dport = net_to_cpu_u16(segment->dst_port);
    uint16_t sport = net_to_cpu_u16(segment->src_port);

    tcp_listener_t *listener = find_listener(state, dport);
    if (listener == NULL)
        return; // No connection is listening on this port. 
                // Silently drop the segment

    tcp_connection_t *connection = find_connection(listener, sender, sport);
    if (!connection) {

        if (listener->closed)
            // Listener was closed by the user, so already
            // open connections are ok but new ones are not
            // allowed.
            return;

        // Something sent to an open listener. 

        // We expect it to be a request to connect,
        // which means that the segment should have
        // the SYN flag high (and only that one).
        // If that's true, a connection object must
        // be instanciated and a SYN|ACK message sent.
        //
        // Alongside the SYN, some payload may be
        // associated with the message. Though we must
        // make sure that this data isn't delivered to
        // the parent application until the connection
        // is fully established.
        //
        // From RFC 793, section 3.4:
        //
        // > Several examples of connection initiation follow.  Although these
        // > examples do not show connection synchronization using data-carrying
        // > segments, this is perfectly legitimate, so long as the receiving TCP
        // > doesn't deliver the data to the user until it is clear the data is
        // > valid (i.e., the data must be buffered at the receiver until the
        // > connection reaches the ESTABLISHED state).  The three-way handshake
        // > reduces the possibility of false connections.
        //
        // (https://www.ietf.org/rfc/rfc793.txt)
        
        if (!issyn(segment)) {
            // Received message isn't SYN. Ignore the segment.
            TCP_DEBUG_LOG("Connection request is missing the SYN flag");
            return;
        }

        if (set(segment, ~TCP_FLAG_SYN))
            TCP_DEBUG_LOG("Connection request segment has flags other than SYN set");

        if (payload.len > 0) {
            TCP_DEBUG_LOG("Connection request segment has some payload. "
                          "This is a valid behaviour but we don't handle "
                          "that case yet. Droppong the connection");
            return;
        }

        uint32_t seq_no = choose_sequence_no();
        uint32_t ack_no = net_to_cpu_u32(segment->seq_no)+1;
            
        connection = connection_create(listener, seq_no, ack_no, sender, sport);
        if (connection == NULL) {
            TCP_DEBUG_LOG("Connection limit reached");
            // Should we let the peer know what happened?
            return;
        }
        connection->state = TCP_STATE_SYN_RCVD;

        emit_segment(connection, TCP_FLAG_SYN | TCP_FLAG_ACK, 0, false);
        // Instead of incrementing the snd_una for the SYN we just send,
        // we'll ignore it and also ignore it when the respective ACK si
        // received.

    } else {

        // Something sent to an already instanciated
        // connection. Since there is an instance, it
        // means that at least the first SYN was received
        // and a SYN|ACK message was sent, so the 
        // first state of a connection is SYN_RCVD
        switch (connection->state) {
            
            case TCP_STATE_CLOSED:
            // This state is only used for uninitialized
            // connection structures. If the code behaves
            // well, this code should be unreachable.
            assert(0);
            break;

            case TCP_STATE_SYN_SENT:
            // This is the state where we sent SYN to initiate 
            // the connection with a peer acting as server.
            // At the moment "microtcp_connect" isn't implemented
            // so this state can never be reached.
            assert(0); // UNREACHABLE
            break;
            
            case TCP_STATE_SYN_RCVD:
            // At this point a SYN was received and a SYN|ACK sent.
            // We expect an ACK to establish the connection.

            if (isack(segment)) {

                if (payload.len > 0)
                    TCP_DEBUG_LOG("Incoming segment has a payload alongside the ACK for "
                                  "the SYN we sent. This is valid TCP but we don't support "
                                  "this case yet. We'll just ignore the data. Hopefully "
                                  "the peer will retransmit it");
                
                ack_until(connection, net_to_cpu_u32(segment->ack_no));
                move_from_non_established_list_to_non_accepted_queue(connection);
                signal_ready_to_accept(listener);
                
                /* The connection is now established */
                connection->state = TCP_STATE_ESTAB;
            }
            break;

            case TCP_STATE_ESTAB:

            if (isack(segment)) {
                uint32_t ack_no = net_to_cpu_u32(segment->ack_no);
                if (ack_until(connection, ack_no))
                    // At least one byte was ACKed, so now there's space 
                    // available in the output buffer
                    signal_ready_to_send(connection);
            }

            size_t moved = move_data_into_input_buffer(connection, payload);
            if (moved > 0) {
                // Data is ready to be received by the parent application
                signal_ready_to_recv(connection);
                emit_segment(connection, TCP_FLAG_ACK, SIZE_MAX, false);
            }

            if (isfin(segment)) {
                // An unsolicited FIN was received. We ACK the FIN and
                // set the connection state as waiting to be closed from
                // this end.
                TCP_DEBUG_LOG("ESTAB -> CLOSE_WAIT");
                connection->rcv_nxt++; // FIN ghost byte
                emit_segment(connection, TCP_FLAG_ACK, 0, false);
                connection->state = TCP_STATE_CLOSE_WAIT;
            }
            break;
            
            case TCP_STATE_FIN_WAIT_1:
            // The FIN segment was sent after the user called "close".
            // In this state we're expecting the ACK flag for the fin.
            // The same message could also contain the peer's FIN.

            if (isack(segment) && isfin(segment)) {

                TCP_DEBUG_LOG("FIN-WAIT-1 -> TIME-WAIT");
    
                connection->rcv_nxt++; // FIN ghost byte
                emit_segment(connection, TCP_FLAG_ACK, 0, false);
                change_state_to_time_wait(connection);
                break;
            }

            if (isack(segment)) {
                TCP_DEBUG_LOG("FIN-WAIT-1 -> FIN-WAIT-2");
                connection->state = TCP_STATE_FIN_WAIT_2;
                break;
            }

            if (isfin(segment)) {
                TCP_DEBUG_LOG("FIN-WAIT-1 -> CLOSING");
                connection->rcv_nxt++; // FIN ghost byte
                emit_segment(connection, TCP_FLAG_ACK, 0, false);
                connection->state = TCP_STATE_CLOSING;
                break;
            }

            // Expected FIN and/or ACK but didn't receive them
            break;

            case TCP_STATE_FIN_WAIT_2:
            // Socket was closed from the user so a FIN was sent.
            // The FIN was ACKed and now we're waiting for their
            // FIN to ACK. 

            if (isfin(segment)) {
                connection->rcv_nxt++; // FIN ghost byte
                emit_segment(connection, TCP_FLAG_ACK, 0, false);
                change_state_to_time_wait(connection);
            }

            break;

            case TCP_STATE_CLOSE_WAIT:
            // Nothing to be done here!
            //
            // A FIN was received and ACKed. At this point we're
            // waiting for the user to close the socket, so we
            // can ignore any incoming segment.
            break;
            
            case TCP_STATE_LAST_ACK:
            // FIN was received, ACKed and a FIN was sent.
            // Now we expect the final ACK for our FIN.

            if (isack(segment)) {
                uint32_t ack_no = net_to_cpu_u32(segment->ack_no);
                if (ack_until(connection, ack_no)) {
                    // FIXME!
                    // At least one byte was ACKed. There is not assurance
                    // that it was the FIN, but it's good enough for now!
                    connection->state = TCP_STATE_CLOSED;
                    really_close_connection(connection);
                }
            }
            break;

            case TCP_STATE_TIME_WAIT:
            // Connection is cooling off. Ignore everything
            break;

            case TCP_STATE_CLOSING:
            // FIN was sent and a FIN received. Now we expect 
            // the ACK for our FIN.
            // ..TODO..

            change_state_to_time_wait(connection);
            break;
        }
    }
}

tcp_listener_t*
tcp_listener_create(tcp_state_t *state, uint16_t port, bool reuse,
                    void *cb_data, void (*cb_ready_accept)(void*))
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
        listener->cb_ready_accept = cb_ready_accept;
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
        listener->port   = port;
        listener->accepted_list = NULL;
        listener->non_established_list    = NULL;
        listener->non_accepted_queue_head = NULL;
        listener->non_accepted_queue_tail = NULL;
        listener->cb_data = cb_data;
        listener->cb_ready_accept = cb_ready_accept;

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
}

tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener, void *cb_data, 
                                      void (*cb_ready_recv)(void*), 
                                      void (*cb_ready_send)(void*))
{
    if (!listener->non_accepted_queue_head)
        // Nothing to accept
        return NULL;

    tcp_connection_t *c;

    // Pop connection from the tail of the accept queue
    {
        c = listener->non_accepted_queue_tail;
        if (c->prev)
            // ->prev isn't NULL so this isn't the first element of 
            // the queue. Therefore we need to update the ->next pointer
            // of the previous node.
            c->prev->next = NULL;
        else
            // ->prev is NULL so this is the first element of the queue.
            // We need to update the reference to the head of the list
            listener->non_accepted_queue_head = NULL;

        assert(c->next == NULL); // This is the last element of the queue so
                                          // it has no following node.
        listener->non_accepted_queue_tail = NULL;
    }

    // Push it to the head of the accepted list
    {
        c->prev = NULL;
        c->next = listener->accepted_list;

        if (listener->accepted_list)
            listener->accepted_list->prev = c;
        listener->accepted_list = c;
    }

    c->cb_data = cb_data;
    c->cb_ready_recv = cb_ready_recv;
    c->cb_ready_send = cb_ready_send;
    
    return c;
}

#ifdef TCP_DEBUG
static bool connection_was_accepted(tcp_connection_t *c)
{
    // Get the listener that's associated to
    // the connection and iterate over it's
    // accepted connections list to make sure
    // that is contains the connection.

    tcp_listener_t *listener = c->listener;

    tcp_connection_t *cursor = listener->accepted_list;

    while (cursor) {
        if (cursor == c)
            return true;
        cursor = cursor->next;
    }
    return false;
} 
#endif

void tcp_connection_destroy(tcp_connection_t *c)
{
    // NOTE: This can only be called when the
    //       connection was accepted, so it must
    //       be a node of the accepted_list.

#ifdef TCP_DEBUG
    assert(connection_was_accepted(c));
#endif

    // You can only call destroy on connections
    // that were at least established
    assert(c->state == TCP_STATE_ESTAB || 
           c->state == TCP_STATE_CLOSE_WAIT);

    switch (c->state) {
        
        case TCP_STATE_ESTAB:
        TCP_DEBUG_LOG("ESTAB -> FIN-WAIT-1");
        emit_segment(c, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, false);
        c->state = TCP_STATE_FIN_WAIT_1; 
        break;
    
        case TCP_STATE_CLOSE_WAIT:
        TCP_DEBUG_LOG("ESTAB -> LAST-ACK");
        emit_segment(c, TCP_FLAG_FIN | TCP_FLAG_ACK, 0, false);
        c->state = TCP_STATE_LAST_ACK;
        break;

        default:
        // This point should be unreachable
        assert(0);
        break;
    }

    // TODO: Should start a timeout here prolly
}

size_t tcp_connection_recv(tcp_connection_t *connection, 
                           void *dst, size_t len)
{
    slice_t s = {.ptr=dst, .len=len};
    return move_data_from_input_buffer(connection, s);
}

static size_t 
append_to_output_buffer(tcp_connection_t *connection, 
                        const void *src, size_t len)
{
    size_t capacity = TCP_OUTPUT_BUFFER_SIZE - connection->snd_wnd;
    size_t num = MIN(len, capacity);

    memcpy(connection->out_buffer + connection->snd_wnd, src, num);
    connection->snd_wnd += num;

    return num;
}

size_t tcp_connection_send(tcp_connection_t *connection, const void *src, size_t len)
{
    size_t num = append_to_output_buffer(connection, src, len);
    emit_segment(connection, TCP_FLAG_ACK, SIZE_MAX, false);
    return num;
}