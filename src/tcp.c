#include <string.h>
#include <arpa/inet.h>
#include "tcp.h"

#ifdef TCP_DEBUG
#include <stdio.h>
#define TCP_DEBUG_LOG(fmt, ...) fprintf(stderr, "TCP :: " fmt "\n", ## __VA_ARGS__)
#else
#define TCP_DEBUG_LOG(...)
#endif

static int tcp_send(tcp_state_t *tcp_state, ip_address_t ip,
                     const void *src, size_t len)
{
    return tcp_state->callbacks.send(tcp_state->callbacks.data, ip, src, len);
}

void tcp_init(tcp_state_t *tcp_state, tcp_callbacks_t callbacks)
{
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
    if (state->free_connection_list == NULL)
        // ERROR: Reached connection limit
        return NULL;
    tcp_connection_t *connection = state->free_connection_list;
    state->free_connection_list = connection->next;

    // Initialize connection structure
    connection->listener = listener;
    connection->seq_no = seq_no;
    connection->ack_no = ack_no;
    connection->peer_port = peer_port;
    connection->peer_ip   = peer_ip;
    connection->in_used = 0;
    connection->out_used = 0;
    connection->prev = NULL;
    connection->next = NULL;


    // Append the connection to the list of connections
    // waiting for the ACK message
    if (listener->connections_waiting_for_ack)
        listener->connections_waiting_for_ack->prev = connection;
    connection->next = listener->connections_waiting_for_ack;
    listener->connections_waiting_for_ack = connection;

    return connection;
}

static tcp_listener_t*
find_listener_with_port(tcp_state_t *state, uint16_t port)
{
    TCP_DEBUG_LOG("Looking for listener with port %d", port);

    tcp_listener_t *cursor = state->used_listener_list;
    while (cursor) {
        TCP_DEBUG_LOG("port=%d, seeking=%d", cursor->port, port);
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

static connection_state_t find_connection_associated_to(tcp_listener_t *listener, ip_address_t peer_ip, uint16_t peer_port, tcp_connection_t **connection)
{
    tcp_connection_t *connection2 = find_connection(listener->connections, peer_ip, peer_port);
    if (connection2) {
        *connection = connection2;
        return SOCKET_IDLE;
    }

    connection2 = find_connection(listener->connections_waiting_for_accept_head, peer_ip, peer_port);
    if (connection2) {
        *connection = connection2;
        return SOCKET_IDLE;
    }

    connection2 = find_connection(listener->connections_waiting_for_ack, peer_ip, peer_port);
    if (connection2) {
        *connection = connection2;
        return SOCKET_WAIT;
    }

    *connection = NULL;
    return SOCKET_NONE;
}

static uint32_t choose_ack()
{
    return 0;
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

    uint16_t reordered_dst_port = ntohs(segment->dst_port);
    uint16_t reordered_src_port = ntohs(segment->src_port);

    tcp_listener_t *listener = find_listener_with_port(state, reordered_dst_port);
    if (listener == NULL) {
        // No connection is listening on this port. Silently drop the packet.
        TCP_DEBUG_LOG("Segment sent to port %d, which is closed", reordered_dst_port);
        return;
    }

    tcp_connection_t *connection;
    connection_state_t connection_state = find_connection_associated_to(listener, sender, reordered_src_port, &connection);

    if ((segment->flags & TCP_FLAG_SYN) && !(segment->flags & TCP_FLAG_ACK)) {

        /* Connection request */

        if (connection_state != SOCKET_NONE) {
            // Peer wants to connect, but a connection was already created..
            // What to do?
            #warning "TODO: Handle case where an existing connection recieved the SYN message"
            return;
        }

        // Temporary
        uint32_t seq_no = ntohs(segment->seq_no);
        uint32_t ack_no = choose_ack();

        tcp_connection_t *connection = connection_create_waiting_for_ack(listener, seq_no, ack_no, sender, reordered_dst_port);
        if (connection == NULL) {
            // ERROR: Socket limit reached. Drop the connection silently
            #warning "TODO: Handle connection limit reached (RST?)"
            return;
        }

        tcp_segment_t segment2 = {
            .src_port = segment->dst_port,
            .dst_port = segment->src_port,
            .flags    = TCP_FLAG_SYN | TCP_FLAG_ACK, // No need for fixing endianess, it's just one byte!
            .seq_no   = htons(ack_no),
            .ack_no   = htons(seq_no),
            .offset   = 5,
            .unused   = 0,
            .window   = htons(TCP_INPUT_BUFFER_SIZE - connection->in_used),
            .checksum = 0,
            .urgent_pointer = 0,
        };

        #warning "TODO: Calculare checksum"

        tcp_send(state, sender, &segment2, sizeof(segment2));

        #warning "TODO: Handle TCP connection creation"

    } else if ((segment->flags & TCP_FLAG_SYN) && (segment->flags & TCP_FLAG_ACK)) {

        // Drop the packet. We only do servers for now!
        #warning "TODO: Handle TCP second message of three way handshake"
        
    } else if (!(segment->flags & TCP_FLAG_SYN) && (segment->flags & TCP_FLAG_ACK)) {

        if (connection_state != SOCKET_WAIT) {
            // Either there is no connection or the connection wasn't
            // waiting for an ACK segment. What to do?
            #warning "TODO: Handle case where an existing connection recieved the SYN message"
            return;
        }

        // Move connection from the waiting-for-ack list 
        // to the waiting-for-accept queue.

        // Unlink it from the current list
        {
            if (connection->prev)
                connection->prev->next = connection->next;
            else
                listener->connections_waiting_for_ack = connection->next;

            if (connection->next)
                connection->next->prev = connection->prev;
        }

        // Push it to the new one
        {
            connection->prev = NULL;
            connection->next = listener->connections_waiting_for_accept_head;

            if (listener->connections_waiting_for_accept_head)
                // Accept queue isn't empty
                listener->connections_waiting_for_accept_head->prev = connection;
            else
                // Accept queue is empty
                listener->connections_waiting_for_accept_tail = connection;
            listener->connections_waiting_for_accept_head = connection;
        }

        if (listener->callback)
            listener->callback(listener->data);

        // TODO: What about the payload?
        #warning "TODO: Handle payload of TCP ACK message"

    } else {
        
        if (connection_state != SOCKET_IDLE) {
            // Either there is no connection associated to this peer
            // at this port, or the connection is waiting for an ACK.
            // What to do?
            #warning "TODO: Handle case where unexpected TCP data message is received"
            return;
        }

        char *payload = segment->payload;
        size_t payload_arrived    = len - sizeof(tcp_segment_t);
        size_t payload_capacity   = TCP_INPUT_BUFFER_SIZE - connection->in_used;
        size_t payload_considered = MIN(payload_arrived, payload_capacity);

        memcpy(connection->in_buffer + connection->in_used, payload, payload_considered);
        connection->in_used += payload_considered;
        connection->ack_no += payload_considered; // Is this right?
    }
}

tcp_listener_t*
tcp_listener_create(tcp_state_t *state, uint16_t port, void *data, void (*callback)(void*))
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
    listener->connections_waiting_for_accept_head = NULL;
    listener->connections_waiting_for_accept_tail = NULL;
    listener->data = data;
    listener->callback = callback;

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

tcp_connection_t *tcp_listener_accept(tcp_listener_t *listener)
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
    return connection;
}

void tcp_connection_destroy(tcp_connection_t *connection)
{
    // NOTE: This can only be called when the
    //       connection was accepted.

    tcp_listener_t *listener = connection->listener;

    // Pop connection from the idle connection list
    if (connection->prev)
        connection->prev->next = connection->next;
    else
        listener->connections = connection->next;

    // Push it into the free connection list
    tcp_state_t *state = listener->state;

    connection->prev = NULL;
    connection->next = state->free_connection_list;
    state->free_connection_list = connection;
}

size_t tcp_connection_recv(tcp_connection_t *connection, 
                       void *dst, size_t len)
{
    size_t num = MIN(len, connection->in_used);
    memcpy(dst, connection->in_buffer, num);

    memmove(connection->in_buffer, connection->in_buffer + num, connection->in_used - num);
    connection->in_used -= num;

    return num;
}

static size_t 
append_to_output_buffer(tcp_connection_t *connection, 
                        const void *src, size_t len)
{
    size_t num = MIN(len, TCP_OUTPUT_BUFFER_SIZE - connection->out_used);

    memcpy(connection->out_buffer + connection->out_used, src, num);
    connection->out_used += len;

    return num;
}

static uint32_t calculate_checksum(const void *data, size_t size)
{
    (void) data,
    (void) size;

    #warning "TODO: Calculate TCP checksum"
    return 0;
}

static void 
try_flushing_output_buffer(tcp_connection_t *connection)
{
    tcp_state_t *tcp_state = connection->listener->state;

    tcp_segment_t *segment = &connection->out_header;
    segment->src_port = htons(connection->listener->port);
    segment->dst_port = htons(connection->peer_port);
    segment->seq_no = htons(connection->seq_no); // Should this be increased by the segment size?
    segment->ack_no = htons(connection->ack_no);
    segment->unused = 0;
    segment->offset = 5; // No options
    segment->flags  = 0;
    segment->window = htons(TCP_INPUT_BUFFER_SIZE - connection->in_used);
    segment->checksum = 0; // Temporary value
    segment->urgent_pointer = 0; // Don't support urgent data

    segment->checksum = calculate_checksum(segment, sizeof(tcp_segment_t));

    int sent_bytes = tcp_send(tcp_state, connection->peer_ip, segment, sizeof(tcp_segment_t) + connection->out_used);
            
    if (sent_bytes < 0) {
        // It wasn't possible to send out bytes. We'll try again later!
    } else {
        memmove(connection->out_buffer, connection->out_buffer + sent_bytes, connection->out_used - sent_bytes);
        connection->out_used -= sent_bytes;
    }
}

size_t tcp_connection_send(tcp_connection_t *connection, const void *src, size_t len)
{
    size_t num = append_to_output_buffer(connection, src, len);
    try_flushing_output_buffer(connection);
    return num;
}
