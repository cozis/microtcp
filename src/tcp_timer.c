#ifndef MICROTCP_AMALGAMATION
#include "tcp_timer.h"
#endif

void tcp_timerset_init(tcp_timerset_t *set)
{
    for (size_t i = 0; i < TCP_MAX_TIMEOUTS-1; i++)
        set->pool[i].next = set->pool + i+1;
    set->pool[TCP_MAX_TIMEOUTS-1].next = NULL;
    set->free_list = set->pool;
    set->used_list = NULL;
}

void tcp_timerset_free(tcp_timerset_t *set)
{
    (void) set;
}

void tcp_timer_disable(tcp_timer_t *timer)
{
    tcp_timerset_t *set = timer->set;

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

tcp_timer_t *tcp_timer_create(tcp_timerset_t *set, size_t seconds, 
                              void (*callback)(void*), void *data)
{
    assert(callback);

    if (set->free_list == NULL)
        // Out of timers! This is really bad.
        // What can be done to mitigate this?
        return NULL;

    tcp_timer_t *timer = set->free_list;
    set->free_list = timer->next;
    // NOTE: Since the free list is singly linked, there's
    //       no need to change the prev member of the new
    //       first item of the free list.

    timer->set = set;
    timer->deadline = set->current_time + seconds;
    timer->data = data;
    timer->callback = callback;
    
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
    return timer;
}

void tcp_timerset_step(tcp_timerset_t *set, size_t seconds)
{
    set->current_time += seconds;

    if (set->used_list == NULL || set->used_list->deadline > set->current_time)
        // No timeouts triggered
        return;

    tcp_timer_t *timedout_head = set->used_list; // We know that at least one timeout triggered
    tcp_timer_t *timedout_tail; // This has to be determined by the following loop

    // Scan through all of the timeouts that just triggered
    tcp_timer_t *timeout = set->used_list;
    while (timeout) {

        if (timeout->deadline > set->current_time)
            // This timeout didn't trigger, so the last 
            // timed out timeout was the previous one.
            break;
        
        // Trigger the callback
        timeout->callback(timeout->data);

        timedout_tail = timeout;
        timeout = timeout->next;
    }

    // Now put the list of timed out timeouts back
    // into the free list
    if (timedout_tail->next)
        timedout_tail->next->prev = NULL;

    set->used_list = timedout_tail->next;

    timedout_tail->prev = NULL;
    timedout_tail->next = set->free_list;

    set->free_list = timedout_head;
}