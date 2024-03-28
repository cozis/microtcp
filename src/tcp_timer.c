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

#include <string.h>
#include <assert.h>
#include "tcp_timer.h"

#ifdef TCP_DEBUG
#include <stdio.h>
#define TCP_DEBUG_LOG(fmt, ...) fprintf(stderr, "TCP-TIMERS :: " fmt "\n", ## __VA_ARGS__)
#else
#define TCP_DEBUG_LOG(...) {}
#endif

void tcp_timerset_init(tcp_timerset_t *set)
{
    if (TCP_MAX_TIMERS == 0)
        set->free_list = NULL;
    else {
        for (size_t i = 0; i < TCP_MAX_TIMERS-1; i++)
            set->pool[i].next = set->pool + i+1;
        set->pool[TCP_MAX_TIMERS-1].next = NULL;
        set->free_list = set->pool;
    }
    set->used_list = NULL;
    set->current_time_ms = 0;
}

void tcp_timerset_free(tcp_timerset_t *set)
{
    (void) set;
}

void tcp_timer_disable(tcp_timer_t *timer)
{
    tcp_timerset_t *set = timer->set;

    TCP_DEBUG_LOG("Timer %d disabled", (int) (timer - set->pool));

    // Pop the timer from the used list
    if (timer->prev)
        timer->prev->next = timer->next;
    else
        set->used_list = timer->next;
    if (timer->next)
        timer->next->prev = timer->prev;

    // Push it into the free list
    timer->prev = NULL;
    timer->next = set->free_list;
    set->free_list = timer;
}

tcp_timer_t *tcp_timer_create(tcp_timerset_t *set, size_t ms, 
                              const char *name,
                              void (*callback)(void*), void *data)
{
    assert(callback);

    tcp_timer_t *timer = set->free_list;
    if (timer == NULL)
        // Out of timers! This is really bad.
        // What can be done to mitigate this?
        return NULL;

    set->free_list = timer->next;
    // NOTE: Since the free list is singly linked, there's
    //       no need to change the prev member of the new
    //       first item of the free list.

    timer->set = set;
    timer->set_time = set->current_time_ms;
    timer->trg_time = ms;
    timer->deadline = set->current_time_ms + ms;
    timer->data = data;
    timer->callback = callback;
    strncpy(timer->name, name, sizeof(timer->name));
    timer->name[TCP_MAX_TIMER_NAME] = '\0';

    // Insert the timer structure into the timer list
    // in an orderly fashon
    if (set->used_list == NULL) {
        // This is the first timer of the list
        set->used_list = timer;
        timer->prev = NULL;
        timer->next = NULL;
    } else if (timer->deadline < set->used_list->deadline) {
        // This timer should be the first of the list
        timer->prev = NULL;
        timer->next = set->used_list;
        set->used_list->prev = timer;
        set->used_list = timer;
    } else {
        // The timer isn't the first of the list. We need to
        // determine at which position it should be inserted
        //
        // Scan the list until the timer that needs to come
        // after the inserted one is reached
        tcp_timer_t *cursor = set->used_list;
        while (cursor->next && cursor->next->deadline <= timer->deadline)
            cursor = cursor->next;
        tcp_timer_t *prev = cursor;
        cursor = cursor->next;

        if (cursor) {
            // The cursor points to the element that needs to
            // come after. Since we know the inserted item won't
            // be the first, then this one isn't the first element
            // of the list either, so its "prev" isn't NULL.
            assert(cursor != set->used_list);
            assert(cursor->prev);
            timer->prev = cursor->prev;
            timer->next = cursor;
            cursor->prev->next = timer;
            cursor->prev = timer;

        } else {
            // No element that needs to come after was found,
            // so its position should be the last.
            prev->next = timer;
            timer->prev = prev;
            timer->next = NULL;
        }
    }
    TCP_DEBUG_LOG("Timer %d created (%s)", (int) (timer - set->pool), name);
    return timer;
}

void tcp_timerset_step(tcp_timerset_t *set, size_t ms)
{
    set->current_time_ms += ms;

    if (set->used_list == NULL || set->used_list->deadline > set->current_time_ms)
        // No timeouts triggered
        return;
    
    tcp_timer_t *timedout_head = set->used_list; // We know that at least one timeout triggered
    tcp_timer_t *timedout_tail; // This has to be determined by the following loop

    // Scan through all of the timeouts that just triggered
    tcp_timer_t *timeout = set->used_list;
    do {

        if (timeout->deadline > set->current_time_ms)
            // This timeout didn't trigger, so the last 
            // timed out timeout was the previous one.
            break;
        
        TCP_DEBUG_LOG("Timer %d triggered (deadline %d, current %d, set_time=%d, trg_time=%d)", (int) (timeout - set->pool), (int) timeout->deadline, (int) set->current_time_ms, (int) timeout->set_time, (int) timeout->trg_time);
        
        timeout->callback(timeout->data);

        timedout_tail = timeout;
        timeout = timeout->next;
    } while (timeout);

    // Now put the list of timed out timeouts back
    // into the free list
    if (timedout_tail->next)
        timedout_tail->next->prev = NULL;

    set->used_list = timedout_tail->next;

    timedout_tail->prev = NULL;
    timedout_tail->next = set->free_list;

    set->free_list = timedout_head;
}