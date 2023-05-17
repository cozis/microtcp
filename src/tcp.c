#include <string.h>
#include <stdbool.h>
#include "endian.h"
#include "tcp.h"

#ifdef TCP_DEBUG
#include <stdio.h>
#define TCP_DEBUG_LOG(fmt, ...) fprintf(stderr, "TCP :: " fmt "\n", ## __VA_ARGS__)
#else
#define TCP_DEBUG_LOG(...)
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
}

void tcp_free(tcp_state_t *tcp_state)
{
    // Destroy all listening connections
    while (tcp_state->used_listener_list != NULL)
        tcp_listener_destroy(tcp_state->used_listener_list);
}

void tcp_seconds_passed(tcp_state_t *state, size_t seconds)
{
    (void) state;
    (void) seconds;
}

static tcp_connection_t*
connection_create(tcp_listener_t *listener, 
                  uint32_t seq_no, uint32_t ack_no,
                  ip_address_t peer_ip, uint16_t peer_port)
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

        connection->peer_port = peer_port;
        connection->peer_ip   = peer_ip;

        connection->rcv_unread = ack_no;
        connection->rcv_nxt = ack_no;
        connection->rcv_wnd = TCP_INPUT_BUFFER_SIZE;

        connection->snd_una = seq_no;
        connection->snd_wnd = 0;
        connection->snd_nxt = 0;

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

static tcp_listener_t*
find_listener_with_port(tcp_state_t *state, uint16_t port)
{
    tcp_listener_t *cursor = state->used_listener_list;
    while (cursor) {
        if (cursor->port == port)
            return cursor;
        cursor = cursor->next;
    }
    return NULL;
}

static uint32_t choose_sequence_no()
{
    return 0;
}

typedef struct {
    ip_address_t src_addr;
    ip_address_t dst_addr;
    uint8_t  reserved;
    uint8_t  protocol;
    uint16_t tcp_length;
} tcp_pseudoheader_t;

static uint16_t 
calculate_checksum(const slice_list_t *slices, size_t num_slices)
{
    uint32_t sum = 0xffff;

    for (size_t slice_idx = 0; slice_idx < num_slices; slice_idx++) {
        
        assert((slices[slice_idx].len & 1) == 0);
        const uint16_t *src = slices[slice_idx].src;
        const size_t    len = slices[slice_idx].len;

        for (size_t i = 0; i < len/2; i++) {
            sum += net_to_cpu_u16(src[i]);
            if (sum > 0xffff)
                sum -= 0xffff;
        }
    }

    return cpu_to_net_u16(~sum);
}

static void emit_segment(tcp_connection_t *connection, bool ack, bool syn, size_t payload)
{
    tcp_listener_t *listener = connection->listener;
    tcp_state_t    *state    = listener->state;

    size_t payload_being_sent = MIN(payload, connection->snd_wnd);
    size_t total_segment_size = sizeof(tcp_segment_t) + payload_being_sent;

    uint8_t   flags = 0;
    uint32_t ack_no = 0;
    if (ack) {
        flags |= TCP_FLAG_ACK;
        ack_no = connection->rcv_nxt;
    }
    if (syn)
        flags |= TCP_FLAG_SYN;

    uint32_t seq_no = connection->snd_una;
    //if (payload_being_sent > 0)
    //    seq_no++;

    int offset = 5; // No options
    tcp_segment_t header = {
        .src_port = cpu_to_net_u16(listener->port),
        .dst_port = cpu_to_net_u16(connection->peer_port),
        .flags    = flags,
        .seq_no   = cpu_to_net_u32(seq_no),
        .ack_no   = cpu_to_net_u32(ack_no),
        .offset1  = cpu_is_little_endian() ? 0 : offset,
        .offset2  = cpu_is_little_endian() ? offset : 0,
        .window   = cpu_to_net_u16(connection->rcv_wnd), // Why is a 32 bit integer being backed into a 16 bit?
        .checksum = 0, // Will be calculated later
        .urgent_pointer = 0,
    };

    tcp_pseudoheader_t pseudo_header = {
        .src_addr = state->ip,
        .dst_addr = connection->peer_ip,
        .reserved = 0,
        .protocol = 6, // TCP
        .tcp_length = cpu_to_net_u16(total_segment_size),
    };

    header.checksum = calculate_checksum((slice_list_t[]) {
        {&pseudo_header, sizeof(tcp_pseudoheader_t)},
        {&header, sizeof(tcp_segment_t)},
        {connection->out_buffer, connection->snd_wnd},
    }, 3);

    int result = state->callbacks.send(state->callbacks.data, connection->peer_ip, (slice_list_t[]) {
        {&header, sizeof(tcp_segment_t)},
        {connection->out_buffer, payload_being_sent},
    }, 2);

    if (result < 0) {
        // It wasn't possible to send out bytes. We'll try again later!
    } else {
        size_t actually_sent_bytes = (size_t) result;

        if (actually_sent_bytes < sizeof(tcp_segment_t)) {
            // Not even the TCP header was sent. I hope this
            // doesn't ever happen!
            assert(0);
        } else {
            size_t actually_sent_payload_bytes = actually_sent_bytes - sizeof(tcp_segment_t);
            connection->snd_nxt = MAX(connection->snd_nxt, connection->snd_una + actually_sent_payload_bytes);
        }
    }

}

static void handle_received_data(tcp_connection_t *connection, 
                                 const void *data, size_t size)
{
    size_t considered = MIN(size, connection->rcv_wnd);

    if (considered > 0) {
        size_t input_buffer_usage = TCP_INPUT_BUFFER_SIZE - connection->rcv_wnd;
        memcpy(connection->in_buffer + input_buffer_usage, data, considered);
        connection->rcv_wnd -= considered;
        connection->rcv_nxt += considered;

        emit_segment(connection, true, false, SIZE_MAX);

        // Data is ready to be received by the parent application
        if (connection->callback_ready_to_recv)
            connection->callback_ready_to_recv(connection->callback_data);
    }
}

static tcp_connection_t*
find_connection_associated_to_listener(tcp_listener_t *listener, 
                                       ip_address_t peer_ip, uint16_t peer_port)
{
    tcp_connection_t *connection;

    // Check in the accepted list
    connection = listener->accepted_list;
    while (connection) {
        if (connection->peer_port == peer_port && connection->peer_ip == peer_ip)
            break;
        connection = connection->next;
    }
    if (connection) {
        // accepted=true
    } else {
        // accepted=false
        connection = listener->non_accepted_queue_head;
        while (connection) {
            if (connection->peer_port == peer_port && connection->peer_ip == peer_ip)
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
            if (connection->peer_port == peer_port && connection->peer_ip == peer_ip)
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

void tcp_process_segment(tcp_state_t *state, ip_address_t sender,
                         tcp_segment_t *segment, size_t len)
{
    TCP_DEBUG_LOG("Received TCP segment");

    assert(len >= sizeof(tcp_segment_t));
    size_t data_offset = SEGMENT_OFFSET(segment) * sizeof(uint32_t); // Length (in bytes) of the TCP header,
                                                             // comprehensive of options.

    size_t options_len = data_offset - sizeof(tcp_segment_t); // The number of bytes of the options is
                                                              // the size of the whole header minus the
                                                              // size of the header without options.
    size_t payload_size = len - data_offset;
    void  *payload_addr = (uint8_t*) segment + data_offset; // The segment->payload doesn't refer to the
                                                            // first byte of the payload but to the first
                                                            // byte of the options!! Use this variable to
                                                            // get the payload.

    uint16_t reordered_dst_port = net_to_cpu_u16(segment->dst_port);
    uint16_t reordered_src_port = net_to_cpu_u16(segment->src_port);

    tcp_listener_t *listener = find_listener_with_port(state, reordered_dst_port);
    if (listener == NULL) {
        // No connection is listening on this port. Silently drop the segment
        TCP_DEBUG_LOG("Segment sent to port %d, which is closed", reordered_dst_port);
        return;
    }

    tcp_connection_t *connection = find_connection_associated_to_listener(listener, sender, reordered_src_port);
    if (!connection) {
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
        
        if (!(segment->flags & TCP_FLAG_SYN)) {
            // Received message isn't SYN. Ignore the segment.
            TCP_DEBUG_LOG("Connection request is missing the SYN flag");
            return;
        }

        if (segment->flags & ~TCP_FLAG_SYN)
            TCP_DEBUG_LOG("Connection request segment has flags other than SYN set");

        if (payload_size > 0) {
            TCP_DEBUG_LOG("Connection request segment has some payload. "
                          "This is a valid behaviour but we don't handle "
                          "that case yet. Droppong the connection");
            return;
        }

        uint32_t seq_no = choose_sequence_no();
        uint32_t ack_no = net_to_cpu_u32(segment->seq_no)+1;
            
        connection = connection_create(listener, seq_no, ack_no, sender, reordered_src_port);
        if (connection == NULL) {
            TCP_DEBUG_LOG("Connection limit reached");
            // Should we let the peer know what happened?
            return;
        }
        connection->state = TCP_STATE_SYN_RCVD;

        emit_segment(connection, true, true, 0);
        connection->snd_una++;

        TCP_DEBUG_LOG("Connection request handled");

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

            if (!(segment->flags & TCP_FLAG_ACK))
                // This isn't what we expected. Ignore it (this is
                // probably not the best action)
                return;
            
            if (segment->flags & ~TCP_FLAG_ACK)
                TCP_DEBUG_LOG("Incoming segment has flags other than ACK set when just an ACK was expected");
            if (payload_size > 0)
                TCP_DEBUG_LOG("Incoming segment has a payload alongside the ACK for "
                              "the SYN we sent. This is valid TCP but we don't support "
                              "this case yet. We'll just ignore the data. Hopefully "
                              "the peer will retransmit it");
            // The connection is now established.
            connection->state = TCP_STATE_ESTAB;

            move_from_non_established_list_to_non_accepted_queue(connection);

            if (listener->callback_ready_to_accept)
                listener->callback_ready_to_accept(listener->callback_data);
            break;

            case TCP_STATE_ESTAB:
            if (segment->flags & TCP_FLAG_ACK) {

                uint32_t ack_no = net_to_cpu_u32(segment->ack_no);

                if (ack_no <= connection->snd_una)
                    TCP_DEBUG_LOG("Received segment acknowledged again %d", ack_no);
                else {
                    if (ack_no > connection->snd_nxt) {
                        // Peer ACKed unsent data. The right course of action
                        // is probably to drop the connection.
                        TCP_DEBUG_LOG("Received segment acknowledged unsent data "
                                      "with sequence number %d, but %d still wasn't sent", 
                                      ack_no, connection->snd_nxt);
                        return; // For now we'll just ignore the segment.
                    }
                
                    size_t newly_acked_bytes = ack_no - connection->snd_una;
                    memmove(connection->out_buffer, connection->out_buffer + newly_acked_bytes, connection->snd_wnd - newly_acked_bytes);
                    connection->snd_wnd -= newly_acked_bytes;
                    connection->snd_una = ack_no;

                    // Now there's space available in the output buffer
                    if (connection->callback_ready_to_send)
                        connection->callback_ready_to_send(connection->callback_data);
                }
            }

            handle_received_data(connection, payload_addr, payload_size);

            if (segment->flags & TCP_FLAG_FIN) {
                
                // Send ACK for the FIN
                emit_segment(connection, true, false, 0);
                connection->snd_una++; // emit_segment doesn't increment the "snd_una" for ghost bytes

                connection->state = TCP_STATE_CLOSE_WAIT;
            }
            break;
            
            case TCP_STATE_FIN_WAIT_1:break;
            case TCP_STATE_FIN_WAIT_2:break;
            case TCP_STATE_CLOSE_WAIT:break;
            case TCP_STATE_LAST_ACK:break;
            case TCP_STATE_TIME_WAIT:break;
        }
    }
}

tcp_listener_t*
tcp_listener_create(tcp_state_t *state, uint16_t port, void *callback_data, 
                    void (*callback_ready_to_accept)(void*))
{
    if (find_listener_with_port(state, port)) {
        // ERROR: A connection is already listening on this port
        TCP_DEBUG_LOG("Faile to create listener on port %d because there already exists one", port);
        return NULL;
    }

    // Pop a listener connection structure from the free list
    if (state->free_listener_list == NULL) {
        // ERROR: Reached listener connection limit
        TCP_DEBUG_LOG("TCP connection limit");
        return NULL;
    }
    tcp_listener_t *listener = state->free_listener_list;
    state->free_listener_list = listener->next;

    // Initialize listener structure
    listener->state = state;
    listener->port = port;
    listener->accepted_list = NULL;
    listener->non_established_list = NULL;
    listener->non_accepted_queue_head = NULL;
    listener->non_accepted_queue_tail = NULL;
    listener->callback_data = callback_data;
    listener->callback_ready_to_accept = callback_ready_to_accept;

    // Push listener connection structure to the used list
    listener->prev = NULL;
    listener->next = state->used_listener_list;
    if (state->used_listener_list)
        state->used_listener_list->prev = listener;
    state->used_listener_list = listener;

    return listener;
}

void tcp_listener_destroy(tcp_listener_t *listener)
{
    // TODO: Close all connections

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

tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener, void *callback_data, 
                                      void (*callback_ready_to_recv)(void*), 
                                      void (*callback_ready_to_send)(void*))
{
    (void) listener;

    if (!listener->non_accepted_queue_head)
        // Nothing to accept
        return NULL;

    tcp_connection_t *connection;

    // Pop connection from the tail of the accept queue
    {
        connection = listener->non_accepted_queue_tail;
        if (connection->prev)
            // ->prev isn't NULL so this isn't the first element of 
            // the queue. Therefore we need to update the ->next pointer
            // of the previous node.
            connection->prev->next = NULL;
        else
            // ->prev is NULL so this is the first element of the queue.
            // We need to update the reference to the head of the list
            listener->non_accepted_queue_head = NULL;

        assert(connection->next == NULL); // This is the last element of the queue so
                                          // it has no following node.
        listener->non_accepted_queue_tail = NULL;
    }

    // Push it to the head of the accepted list
    {
        connection->prev = NULL;
        connection->next = listener->accepted_list;

        if (listener->accepted_list)
            listener->accepted_list->prev = connection;
        listener->accepted_list = connection;
    }

    connection->callback_data = callback_data;
    connection->callback_ready_to_recv = callback_ready_to_recv;
    connection->callback_ready_to_send = callback_ready_to_send;

    return connection;
}

#ifdef TCP_DEBUG
static bool connection_was_accepted(tcp_connection_t *connection)
{
    // Get the listener that's associated to
    // the connection and iterate over it's
    // accepted connections list to make sure
    // that is contains the connection.

    tcp_listener_t *listener = connection->listener;

    tcp_connection_t *cursor = listener->accepted_list;

    while (cursor) {
        if (cursor == connection)
            return true;
        cursor = cursor->next;
    }
    return false;
} 
#endif

void tcp_connection_destroy(tcp_connection_t *connection)
{
    // NOTE: This can only be called when the
    //       connection was accepted, so it must
    //       be a node of the accepted_list.

#ifdef TCP_DEBUG
    assert(connection_was_accepted(connection));
#endif

    // Make sure the connection was first finished
    // by being moved from the idle list to the
    // waiting-for-fin list.
    tcp_connection_finish(connection);

    tcp_listener_t *listener = connection->listener;

    // Pop connection from the waiting-for-fin list
    if (connection->prev)
        connection->prev->next = connection->next;
    else
        listener->accepted_list = connection->next;

    // Push it into the free connection list
    tcp_state_t *state = listener->state;

    connection->prev = NULL;
    connection->next = state->free_connection_list;
    state->free_connection_list = connection;
}

size_t tcp_connection_recv(tcp_connection_t *connection, 
                           void *dst, size_t len)
{
    size_t unread = connection->rcv_nxt - connection->rcv_unread;
    size_t num = MIN(len, unread);
    memcpy(dst, connection->in_buffer, num);


    size_t input_buffer_usage = TCP_INPUT_BUFFER_SIZE - connection->rcv_wnd;

    memmove(connection->in_buffer, connection->in_buffer + num, input_buffer_usage - num);
    connection->rcv_unread += num;
    connection->rcv_wnd    += num;

    assert(connection->rcv_wnd <= TCP_INPUT_BUFFER_SIZE);

    return num;
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
    emit_segment(connection, false, false, SIZE_MAX);
    return num;
}

void tcp_connection_finish(tcp_connection_t *connection)
{
/*
    if (!connection->read_only) {

        // Move connection from idle list to 
        // waiting-for-fin list

        tcp_listener_t *listener = connection->listener;

        // Pop it from the idle list
        {
            if (connection->prev)
                connection->prev->next = connection->next;
            else
                listener->connections = connection->next;

            if (connection->next)
                connection->next->prev = connection->prev;

            connection->prev = NULL;
            connection->next = NULL;
        }

        #warning "The FIN segment should be sent here"

        // Push it to the waiting-for-fin list
        {
            connection->prev = NULL;
            connection->next = listener->connections_waiting_for_fin;
            listener->connections_waiting_for_fin = connection;
        }

        // Now mark the connection as read-only
        connection->read_only = true;
    }
*/
}