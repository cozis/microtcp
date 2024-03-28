/*
 * MIT License
 *
 * Copyright (c) 2024 Francesco Cozzuto
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

#include <stdbool.h>
#include "endian.h"
#include "arp.h"

#ifdef ARP_DEBUG
#include <stdio.h>
#define ARP_DEBUG_LOG(fmt, ...) fprintf(stderr, "ARP :: " fmt "\n", ## __VA_ARGS__)
#else
#define ARP_DEBUG_LOG(...)
#endif

void arp_change_output_buffer(arp_state_t *state, void *ptr, size_t max)
{
    if (max < sizeof(arp_packet_t))
        state->output = NULL;
    else
        state->output = ptr;
}

static void arp_translation_table_seconds_passed(arp_translation_table_t *table, size_t seconds)
{
    table->time += seconds;

    //  Determine all of the elements of the table that have just 
    //  timed out.
    //
    //  The [used_list] contains all of the active table entries
    //  in a doubly linked list. The first element is referred by
    //  [table->used_list_head], and the last by [table->used_list_tail].
    //  The entries are ordered in descending [entry->timeout] 
    //  attribute. The [timeout] attribute indicates the absolute
    //  time at which the entry will be considered invalid, 
    //  relative to [table->time].
    //
    //  Since the list goes from high to low timeout, if an entry
    //  at a given point in time isn't timed-out, all of the
    //  entries that come before it also aren't timed-out. 
    //  Analogously, is an entry in a given point in time is
    //  timed-out, all of the entries after it are also timed-out.
    //
    //  In general, at any given point in time, the list is made 
    //  of a first half of non-timed-out entries and a second half
    //  of timed-out entries.
    //
    //  This function needs to remove the timed-out tail of the
    //  used entries list and add it to the free entry list.
    //

    // Find from the end of the list the first non-timed-out
    // entry. The timed-out elements will be all of the ones
    // that come after it. 
    //
    // NOTE: If all of the entries are timed-out or the list is
    //       empty, the loop will exit with the NULL entry.
    
    arp_translation_table_entry_t *entry = table->used_list_tail;
    while (entry && entry->timeout < table->time)
        entry = entry->prev;

    // First and last element of the timed-out list. We need
    // to determine these.
    arp_translation_table_entry_t *timeout_list;
    arp_translation_table_entry_t *timeout_tail;

    if (entry) {

        // The iteration didn't end with a NULL cursor, so either
        // there are no timed-out elements (in which case the cursor
        // is the tail of the list) or there are both timed-out and
        // non-timed-out entries.
        //
        // Either way, the start of the list is [entry->next].
        timeout_list = entry->next;
        //
        // If there are no timed-out entries, the tail of the timed-out
        // list must be NULL, else it's the tail of the used list.
        timeout_tail = entry->next ? table->used_list_tail : NULL;
        //
        // The entry becomes the new tail
        entry->next = NULL;
        table->used_list_tail = entry;

    } else {

        // If the iteration ended with a NULL cursor, there
        // are no valid entries in the list. Either the list
        // is all timed-out, or it's empty. 
        //
        // Either way we take the list pointers and make them
        // out timed-out list. 
        timeout_list = table->used_list_head;
        timeout_tail = table->used_list_tail;
        //
        // If the list wasn't empty, we make it so.
        table->used_list_head = NULL;
        table->used_list_tail = NULL;
    }

    // Append the timed-out list to the free list
    if (timeout_list) {
        timeout_list->prev = NULL;
        timeout_tail->next = table->free_list;
        table->free_list = timeout_list;
    }
}

void arp_ms_passed(arp_state_t *state, size_t ms)
{
    size_t seconds = ms / 1000;
    
    state->time += seconds;

    // Scan through all of the timed-out entries
    // in the pending request list from the tail
    arp_pending_request_t *cursor = state->pending_request_used_tail;
    while (cursor && cursor->timeout < state->time)
        cursor = cursor->prev;


    // Chop off the list of timed out entries
    arp_pending_request_t *timeout_list;
    arp_pending_request_t *timeout_tail;

    if (cursor) {
        // Cursor holds the first request that's not timed out,
        // therefore all of the entries that come after it are
        // now invalid
        timeout_list = cursor->next;
        timeout_tail = cursor->next ? state->pending_request_used_tail : NULL;

        // Now chop off the list
        cursor->next = NULL;
        state->pending_request_used_tail = cursor;
    } else {
        // Either the list is empty or all of the requests are
        // now invalid.
        timeout_list = state->pending_request_used_list;
        timeout_tail = state->pending_request_used_tail;
        state->pending_request_used_list = NULL;
        state->pending_request_used_tail = NULL;
    }

    // Now walk through the timed out entries and
    // run the callback with the timeout status code
    arp_pending_request_t *timeout_cursor = timeout_list;
    while (timeout_cursor) {
        timeout_cursor->callback(timeout_cursor->callback_data, ARP_RESOLUTION_TIMEOUT, MAC_ZERO);
        timeout_cursor = timeout_cursor->next;
    }

    // Now put the timed out entries back in the free 
    // list (if there are any)
    if (timeout_list) {
        timeout_list->prev = NULL;
        timeout_tail->next = state->pending_request_free_list;
        state->pending_request_free_list = timeout_list;
    }

    arp_translation_table_seconds_passed(&state->table, seconds);
}

static void
arp_translation_table_init(arp_translation_table_t *table)
{
    table->time = 0;
    table->used_list_head = NULL;
    table->used_list_tail = NULL;
    table->free_list = table->entries;
    for (size_t i = 0; i < ARP_TRANSLATION_TABLE_SIZE-1; i++) {
        table->entries[i].prev = NULL;
        table->entries[i].next = table->entries + i+1;
    }
    table->entries[ARP_TRANSLATION_TABLE_SIZE-1].prev = NULL;
    table->entries[ARP_TRANSLATION_TABLE_SIZE-1].next = NULL;
}

static void
arp_translation_table_free(arp_translation_table_t *table)
{
    (void) table;
}


#ifdef ARP_DEBUG
static bool 
arp_translation_table_entry_is_used(arp_translation_table_t *table,
                                    arp_translation_table_entry_t *entry)
{
    arp_translation_table_entry_t *cursor = table->used_list_head;
    while (cursor) {
        if (cursor == entry)
            return true;
        cursor = cursor->next;
    }
    return false;
}

static bool
arp_translation_table_entry_is_unlinked(arp_translation_table_t *table,
                                        arp_translation_table_entry_t *entry)
{
    return entry->prev == NULL 
        && entry->next == NULL 
        && table->free_list != entry 
        && table->used_list_head != entry
        && table->used_list_tail != entry;
}
#endif

static void
arp_translation_table_unlink_used_entry(arp_translation_table_t *table,
                                        arp_translation_table_entry_t *entry)
{

#ifdef ARP_DEBUG
    assert(!arp_translation_table_entry_is_unlinked(table, entry));
#endif

    if (entry->prev)
        entry->prev->next = entry->next;
    else
        table->used_list_head = entry->next;

    if (entry->next)
        entry->next->prev = entry->prev;
    else
        table->used_list_tail = entry->prev;

    entry->prev = NULL;
    entry->next = NULL;

#ifdef ARP_DEBUG
    assert(arp_translation_table_entry_is_unlinked(table, entry));
#endif

}

static void
arp_translation_table_insert_unlinked_entry_into_used_list(arp_translation_table_t *table,
                                                           arp_translation_table_entry_t *entry)
{

#ifdef ARP_DEBUG
    assert(arp_translation_table_entry_is_unlinked(table, entry));
    assert(!arp_translation_table_entry_is_used(table, entry));
#endif

    // Find the first entry with the lower timeout
    arp_translation_table_entry_t *cursor = table->used_list_head;
    while (cursor && cursor->timeout < entry->timeout)
        cursor = cursor->next;

    if (cursor) {
        // Insert the entry before the cursor position.
        entry->prev = cursor->prev;
        entry->next = cursor;

        if (cursor->prev)
            cursor->prev->next = entry;
        else
            table->used_list_head = entry;

        cursor->prev = entry;
    
    } else {

        // Either the list is empty or the entry must
        // be inserted last.

        entry->prev = table->used_list_tail;
        entry->next = NULL;

        if (table->used_list_tail)
            table->used_list_tail->next = entry;
        else
            table->used_list_head = entry;
        table->used_list_tail = entry;
    }

#ifdef ARP_DEBUG
    assert(!arp_translation_table_entry_is_unlinked(table, entry));
    assert(arp_translation_table_entry_is_used(table, entry));
#endif
}

static void 
arp_translation_table_free_least_recently_used_entry(arp_translation_table_t *table)
{
    arp_translation_table_entry_t *entry = table->used_list_tail;
    if (entry) {

#ifdef ARP_DEBUG
        assert(!arp_translation_table_entry_is_unlinked(table, entry));
#endif

        arp_translation_table_unlink_used_entry(table, entry);

#ifdef ARP_DEBUG
        assert(arp_translation_table_entry_is_unlinked(table, entry));
#endif

        // Push the entry to the free list
        entry->next = table->free_list;
        table->free_list = entry;

#ifdef ARP_DEBUG
        assert(!arp_translation_table_entry_is_unlinked(table, entry));
#endif

    }
}

static arp_translation_table_entry_t*
arp_translation_table_find_entry_by_ip(arp_translation_table_t *table,
                                       ip_address_t ip)
{
    arp_translation_table_entry_t *entry = table->used_list_head;
    while (entry) {
        if (entry->ip == ip)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

static bool arp_translation_table_find_mac_by_ip(arp_translation_table_t *table,
                                                 ip_address_t ip, mac_address_t *mac)
{
    arp_translation_table_entry_t *entry = 
        arp_translation_table_find_entry_by_ip(table, ip);

    if (entry)
        *mac = entry->mac;
    return !!entry;
}

static arp_translation_table_entry_t*
arp_translation_table_pop_free_entry(arp_translation_table_t *table)
{
    arp_translation_table_entry_t *entry = table->free_list;
    if (entry)
        table->free_list = entry->next;
    return entry;
}

static void
arp_translation_table_initialize_entry(arp_translation_table_entry_t *entry,
                                       mac_address_t mac, ip_address_t ip,
                                       uint64_t timeout)
{
    entry->mac = mac;
    entry->ip  = ip;
    entry->timeout = timeout;
    entry->prev = NULL;
    entry->next = NULL;
}

static void 
arp_translation_table_insert_or_update(arp_translation_table_t *table,
                                       mac_address_t mac, ip_address_t ip,
                                       uint64_t timeout)
{
    arp_translation_table_entry_t *entry = 
        arp_translation_table_find_entry_by_ip(table, ip);

    if (entry) {
        entry->timeout = table->time + timeout; // Refresh timeout
        arp_translation_table_unlink_used_entry(table, entry);
    } else {
        entry = arp_translation_table_pop_free_entry(table);
        if (!entry) {
            arp_translation_table_free_least_recently_used_entry(table);
            entry = arp_translation_table_pop_free_entry(table);
        }
        assert(entry);
    
        arp_translation_table_initialize_entry(entry, mac, ip, table->time + timeout);
    }
    arp_translation_table_insert_unlinked_entry_into_used_list(table, entry);
}

static bool
arp_translation_table_update(arp_translation_table_t *table,
                             mac_address_t mac, ip_address_t ip,
                             uint64_t timeout)
{
    arp_translation_table_entry_t *entry = 
        arp_translation_table_find_entry_by_ip(table, ip);

    if (entry) {
        arp_translation_table_unlink_used_entry(table, entry);
        arp_translation_table_initialize_entry(entry, mac, ip, table->time + timeout);
        arp_translation_table_insert_unlinked_entry_into_used_list(table, entry);
    }
    return !!entry;
}

void arp_init(arp_state_t *state, ip_address_t ip, mac_address_t mac,
              void *send_data, void (*send)(void*, mac_address_t))
{
    state->time = 0;
    state->request_timeout = 1;
    state->cache_timeout = 10;
    state->output = NULL;
    state->send_data = send_data;
    state->send = send;

    state->self_ip  = ip;
    state->self_mac = mac;
    arp_translation_table_init(&state->table);

    state->pending_request_used_list = NULL;
    state->pending_request_used_tail = NULL;
    state->pending_request_free_list = state->pending_request_pool;
    for (size_t i = 0; i < ARP_MAX_PENDING_REQUESTS; i++)
        state->pending_request_pool[i].next = state->pending_request_pool + i+1;
    state->pending_request_pool[ARP_MAX_PENDING_REQUESTS-1].next = NULL;
}

void arp_free(arp_state_t *state)
{
    arp_translation_table_free(&state->table);
}

static void append_pending_request_to_used_list(arp_state_t *state, arp_pending_request_t *pending_request)
{
    arp_pending_request_t *cursor = state->pending_request_used_list;

    // Find the first pending request in the list 
    // with a lower timeout and insert the request
    // before it.
    while (cursor && cursor->timeout > pending_request->timeout)
        cursor = cursor->next;

    if (cursor) {
        pending_request->prev = cursor->prev;
        pending_request->next = cursor;

        if (cursor->prev)
            cursor->prev->next = pending_request;
        else
            state->pending_request_used_list = pending_request;
        cursor->prev = pending_request;
    } else {
        // Insert the request in the tail of the list
        pending_request->prev = state->pending_request_used_tail;
        pending_request->next = NULL;

        if (state->pending_request_used_tail)
            state->pending_request_used_tail->next = pending_request;
        else
            state->pending_request_used_list = pending_request;
        state->pending_request_used_tail = pending_request;
    }
}

void arp_resolve_mac(arp_state_t *state, ip_address_t ip, void *userp, void (*callback)(void*, arp_resolution_status_t, mac_address_t))
{
    bool found_mac_locally;
    mac_address_t mac;

    if (state->self_ip == ip) {
        mac = state->self_mac;
        found_mac_locally = true;
    } else
        found_mac_locally = arp_translation_table_find_mac_by_ip(&state->table, ip, &mac);

    if (found_mac_locally)
        callback(userp, ARP_RESOLUTION_OK, mac);
    else {

        // MAC isn't in the translation table.
        // We need to make an ARP REQUEST

        arp_pending_request_t *pending_request = state->pending_request_free_list;
        if (pending_request == NULL) {
            callback(userp, ARP_RESOLUTION_FAILED, MAC_ZERO);
            return;
        }
        state->pending_request_free_list = pending_request->next;

        pending_request->ip = ip;
        pending_request->timeout  = state->time + state->request_timeout;
        pending_request->callback = callback;
        pending_request->callback_data = userp;
        pending_request->prev = NULL;
        pending_request->next = NULL;

        append_pending_request_to_used_list(state, pending_request);
        
        arp_packet_t *packet = state->output;
        if (packet != NULL) {
            packet->hardware_type = cpu_to_net_u16(ARP_HARDWARE_ETHERNET);
            packet->protocol_type = cpu_to_net_u16(ARP_PROTOCOL_IP);
            packet->hardware_len = 6;
            packet->protocol_len = 4;
            packet->operation_type = cpu_to_net_u16(ARP_OPERATION_REQUEST);
            packet->sender_hardware_address = state->self_mac;
            packet->sender_protocol_address = state->self_ip;
            packet->target_hardware_address = MAC_ZERO; // This is what we're trying to find
            packet->target_protocol_address = ip;

            ARP_DEBUG_LOG("Sending out ARP request to resolve MAC");

            state->send(state->send_data, MAC_BROADCAST);
        } else {
            ARP_DEBUG_LOG("Couldn't send ARP request because no output buffer was provided");
        }
    }
}

static void
try_resolving_pending_requests(arp_state_t *state, ip_address_t ip, mac_address_t mac)
{
    // NOTE: Could try resolving pending requests from
    //       the tail of the list instead of the head
    //       since the tail entries have been waiting
    //       longer. I think we can assume the older 
    //       entries have higher chances of being resolved.

    arp_pending_request_t *pending_request = state->pending_request_used_list;
    arp_pending_request_t *prev = NULL;
    while (pending_request) {

        arp_pending_request_t *next = pending_request->next;

        if (pending_request->ip == ip) {
            pending_request->callback(pending_request->callback_data, ARP_RESOLUTION_OK, mac);

            pending_request->next = state->pending_request_free_list;
            state->pending_request_free_list = pending_request;

            if (prev)
                prev->next = next;
            else
                state->pending_request_used_list = next;

            if (next)
                next->prev = prev;
            else
                state->pending_request_used_tail = prev;

        } else
            prev = pending_request;

        pending_request = next;
    }
}

arp_process_result_t arp_process_packet(arp_state_t *state, const void *packet, size_t len)
{
    if (len != sizeof(arp_packet_t))
        return ARP_PROCESS_RESULT_INVALID;

    const arp_packet_t *packet2 = packet;

    if (packet2->hardware_type != cpu_to_net_u16(ARP_HARDWARE_ETHERNET)) {
        /* Level 2 protocol not supported */
        ARP_DEBUG_LOG("Hardware type %d not supported", packet2->hardware_type);
        return ARP_PROCESS_RESULT_HWARENOTSUPP;
    }

    if (packet2->protocol_type != cpu_to_net_u16(ARP_PROTOCOL_IP)) {
        /* Level 3 protocol not supported */
        ARP_DEBUG_LOG("Protocol type %d not supported", packet2->protocol_type);
        return ARP_PROCESS_RESULT_PROTONOTSUPP;
    }

    if (packet2->hardware_len != 6 || packet2->protocol_len != 4) {
         /* Invalid fields */
        ARP_DEBUG_LOG("Invalid hardware or protocol address size %d or %d (expected %d and %d)", packet2->hardware_len, packet2->protocol_len, 6, 4);
        return ARP_PROCESS_RESULT_INVALID;
    }
    
    bool merge = arp_translation_table_update(&state->table, packet2->sender_hardware_address, 
                                              packet2->sender_protocol_address, state->cache_timeout);

    if (packet2->target_protocol_address == state->self_ip) {
        
        if (!merge) {
            arp_translation_table_insert_or_update(&state->table, packet2->sender_hardware_address, 
                                                   packet2->sender_protocol_address, state->cache_timeout);
            try_resolving_pending_requests(state, packet2->sender_protocol_address,
                                           packet2->sender_hardware_address);
        }

        if (packet2->operation_type == cpu_to_net_u16(ARP_OPERATION_REQUEST)) {
            
            // Generate the ARP REPLY
            
            arp_packet_t *response = state->output;
            if (state->output) {
                response->hardware_type = packet2->hardware_type;
                response->protocol_type = packet2->protocol_type;
                response->hardware_len  = packet2->hardware_len;
                response->protocol_len  = packet2->protocol_len;
                response->operation_type = cpu_to_net_u16(ARP_OPERATION_REPLY);
                response->sender_hardware_address = state->self_mac;
                response->sender_protocol_address = state->self_ip;
                response->target_hardware_address = packet2->sender_hardware_address;
                response->target_protocol_address = packet2->sender_protocol_address;

                ARP_DEBUG_LOG("Sending reply");

                state->send(state->send_data, packet2->sender_hardware_address);
            }
        }
    } else {
        //ARP_DEBUG_LOG("Request not for me");
    }

    return ARP_PROCESS_RESULT_OK;
}
