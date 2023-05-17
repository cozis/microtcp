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

void tcp_init(tcp_state_t *tcp_state, ip_address_t ip, tcp_callbacks_t callbacks)
{
    tcp_state->ip = ip;
    tcp_state->callbacks = callbacks;

    for (size_t i = 0; i < TCP_MAX_SOCKETS-1; i++)
        tcp_state->connection_pool[i].next = tcp_state->connection_pool + i+1;
    tcp_state->connection_pool[TCP_MAX_SOCKETS-1].next = NULL;
    tcp_state->free_connection_list = tcp_state->connection_pool;
    tcp_state->used_connection_list = NULL;

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
connection_create_waiting_for_ack(tcp_listener_t *listener, 
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

    // Append the connection to the list of connections
    // waiting for the ACK message
    {
        if (listener->connections_waiting_for_ack)
            listener->connections_waiting_for_ack->prev = connection;
        connection->prev = NULL;
        connection->next = listener->connections_waiting_for_ack;
        listener->connections_waiting_for_ack = connection;
    }

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

#include <stdio.h>

typedef enum {
    SOCKET_WAIT,
    SOCKET_IDLE,
    SOCKET_NONE,
} connection_state_t;

static tcp_connection_t *find_connection(tcp_connection_t *list, ip_address_t peer_ip, uint16_t peer_port)
{
    tcp_connection_t *cursor = list;

    while (cursor) {
        if (cursor->peer_ip == peer_ip && cursor->peer_port == peer_port)
            return cursor;
        cursor = cursor->next;
    }

    return NULL;
}

static connection_state_t 
find_connection_associated_to(tcp_listener_t *listener, ip_address_t peer_ip, 
                              uint16_t peer_port, tcp_connection_t **connection)
{
    tcp_connection_t *connection2 = find_connection(listener->connections, peer_ip, peer_port);
    if (connection2) {
        if (connection)
            *connection = connection2;
        return SOCKET_IDLE;
    }

    connection2 = find_connection(listener->connections_waiting_for_accept_head, peer_ip, peer_port);
    if (connection2) {
        if (connection)
            *connection = connection2;
        return SOCKET_IDLE;
    }

    connection2 = find_connection(listener->connections_waiting_for_ack, peer_ip, peer_port);
    if (connection2) {
        if (connection)
            *connection = connection2;
        return SOCKET_WAIT;
    }

    if (connection)
        *connection = NULL;
    return SOCKET_NONE;
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

    return cpu_to_net_u32(~sum);
}

static void 
move_connection_from_wait_for_ack_to_wait_for_accept(tcp_connection_t *connection)
{
    tcp_listener_t *listener = connection->listener;
    
    // Unlink it from the current list
    if (connection->prev)
        connection->prev->next = connection->next;
    else
        listener->connections_waiting_for_ack = connection->next;

    if (connection->next)
        connection->next->prev = connection->prev;


    // Push it to the new one
    connection->prev = NULL;
    connection->next = listener->connections_waiting_for_accept_head;

    if (listener->connections_waiting_for_accept_head)
        // Accept queue isn't empty
        listener->connections_waiting_for_accept_head->prev = connection;
    else
        // Accept queue is empty
        listener->connections_waiting_for_accept_tail = connection;
    listener->connections_waiting_for_accept_head = connection;


    if (listener->callback_ready_to_accept)
        listener->callback_ready_to_accept(listener->callback_data);
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

    tcp_segment_t header = {
        .src_port = cpu_to_net_u32(listener->port),
        .dst_port = cpu_to_net_u32(connection->peer_port),
        .flags    = flags,
        .seq_no   = cpu_to_net_u32(seq_no),
        .ack_no   = cpu_to_net_u32(ack_no),
        .offset   = 5, // No options
        .unused   = 0,
        .window   = cpu_to_net_u32(connection->rcv_wnd),
        .checksum = 0, // Will be calculated later
        .urgent_pointer = 0,
    };

    tcp_pseudoheader_t pseudo_header = {
        .src_addr = state->ip,
        .dst_addr = connection->peer_ip,
        .reserved = 0,
        .protocol = 6, // TCP
        .tcp_length = cpu_to_net_u32(total_segment_size),
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

void tcp_process_segment(tcp_state_t *state, ip_address_t sender,
                         tcp_segment_t *segment, size_t len)
{
    (void) state;
    (void) sender;
    (void) segment;
    (void) len;

    TCP_DEBUG_LOG("Received TCP segment");

    if (len < sizeof(tcp_segment_t))
        return;

    uint16_t reordered_dst_port = net_to_cpu_u16(segment->dst_port);
    uint16_t reordered_src_port = net_to_cpu_u16(segment->src_port);

    tcp_listener_t *listener = find_listener_with_port(state, reordered_dst_port);
    if (listener == NULL) {
        // No connection is listening on this port. Silently drop the packet.
        TCP_DEBUG_LOG("Segment sent to port %d, which is closed", reordered_dst_port);
        return;
    }

    tcp_connection_t *connection;
    connection_state_t connection_state = find_connection_associated_to(listener, sender, reordered_src_port, &connection);
    
    if (segment->flags & TCP_FLAG_SYN) {

        if (segment->flags & TCP_FLAG_ACK) {

            // Drop the packet. We only do servers for now!
            #warning "TODO: Handle TCP second message of three way handshake"

        } else {
    
            /* Connection request */

            if (connection_state != SOCKET_NONE) {
                // Peer wants to connect, but a connection was already created..
                // What to do?
                #warning "TODO: Handle case where an existing connection recieved the SYN message"
                return;
            }

            // Temporary
            uint32_t seq_no = choose_sequence_no();
            uint32_t ack_no = net_to_cpu_u32(segment->seq_no)+1;
            
            tcp_connection_t *connection = connection_create_waiting_for_ack(listener, seq_no, ack_no, sender, reordered_src_port);
            if (connection == NULL) {
                // ERROR: Socket limit reached. Drop the connection silently
                #warning "TODO: Handle connection limit reached (RST?)"
                return;
            }

            emit_segment(connection, true, true, 0);
            connection->snd_una++;
        }

    } else {

        if (segment->flags & TCP_FLAG_ACK) {

            if (connection_state == SOCKET_WAIT)
                move_connection_from_wait_for_ack_to_wait_for_accept(connection);
            else if (connection_state == SOCKET_IDLE) {

            } else {
                #warning "TODO: Handle case where no connection exists"
                assert(connection_state == SOCKET_NONE);
                return;
            }

            uint32_t ack_no = net_to_cpu_u32(segment->ack_no);

            if (ack_no <= connection->snd_una)
                TCP_DEBUG_LOG("Received segment acknowledged again %d", ack_no);
            else {
                if (ack_no > connection->snd_nxt) {
                    TCP_DEBUG_LOG("Received segment acknowledged unsent data with sequence number %d, but %d still wasn't sent", ack_no, connection->snd_nxt);
                    return; // Acknowledged unsent data
                }
            
                size_t newly_acked_bytes = ack_no - connection->snd_una;
                memmove(connection->out_buffer, connection->out_buffer + newly_acked_bytes, connection->snd_wnd - newly_acked_bytes);
                connection->snd_wnd -= newly_acked_bytes;
                connection->snd_una = ack_no;

                // Now there's space available in the output buffer
                if (connection->callback_ready_to_send)
                    connection->callback_ready_to_send(connection->callback_data);
            }

        } else {

            if (connection_state != SOCKET_IDLE) {
                // Either there is no connection associated to this peer
                // at this port, or the connection is waiting for an ACK.
                // What to do?
                #warning "TODO: Handle case where unexpected TCP data message is received"
                return;
            }
        }
        handle_received_data(connection, segment->payload, 
                             len - sizeof(tcp_segment_t));

        if (segment->flags & TCP_FLAG_FIN) {
            #warning "TODO: Handle FIN segment"
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
    listener->connections = NULL;
    listener->connections_waiting_for_ack = NULL;
    listener->connections_waiting_for_fin = NULL;
    listener->connections_waiting_for_accept_head = NULL;
    listener->connections_waiting_for_accept_tail = NULL;
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

    if (!listener->connections_waiting_for_accept_tail)
        return NULL;

    tcp_connection_t *connection;

    // Pop connection from the accept queue
    {
        connection = listener->connections_waiting_for_accept_tail;
        if (connection->prev)
            connection->prev->next = NULL;
        else
            listener->connections_waiting_for_accept_head = NULL;
        listener->connections_waiting_for_accept_tail = connection->next;
    }

    // Push it to idle list
    {
        connection->prev = NULL;
        connection->next = listener->connections;

        if (listener->connections)
            listener->connections->prev = connection;
        listener->connections = connection;
    }

    connection->callback_data = callback_data;
    connection->callback_ready_to_recv = callback_ready_to_recv;
    connection->callback_ready_to_send = callback_ready_to_send;

    return connection;
}

void tcp_connection_destroy(tcp_connection_t *connection)
{
    // NOTE: This can only be called when the
    //       connection was accepted.

    // Make sure the connection was first finished
    // by being moved from the idle list to the
    // waiting-for-fin list.
    tcp_connection_finish(connection);

    tcp_listener_t *listener = connection->listener;

    // Pop connection from the waiting-for-fin list
    if (connection->prev)
        connection->prev->next = connection->next;
    else
        listener->connections_waiting_for_fin = connection->next;

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
    size_t num;
    if (connection->read_only)
        num = 0;
    else {
        num = append_to_output_buffer(connection, src, len);
        emit_segment(connection, false, false, SIZE_MAX);
    }
    return num;
}

void tcp_connection_finish(tcp_connection_t *connection)
{
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
}