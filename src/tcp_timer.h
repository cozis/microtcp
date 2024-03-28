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

#include <stddef.h>
#include <stdint.h>

#ifndef TCP_MAX_TIMERS
#define TCP_MAX_TIMERS 1024
#endif

#define TCP_MAX_TIMER_NAME 15

typedef struct tcp_timerset_t tcp_timerset_t;
typedef struct tcp_timer_t    tcp_timer_t;

struct tcp_timer_t {
    tcp_timerset_t *set;
    tcp_timer_t *prev;
    tcp_timer_t *next;
    uint64_t set_time;
    uint64_t trg_time;
    uint64_t deadline;
    void (*callback)(void *data);
    void *data;
    char name[TCP_MAX_TIMER_NAME+1];
};

struct tcp_timerset_t {
    uint64_t current_time_ms;
    tcp_timer_t *used_list;
    tcp_timer_t *free_list;
    tcp_timer_t pool[TCP_MAX_TIMERS];
};

void tcp_timerset_step(tcp_timerset_t *set, size_t ms);
void tcp_timerset_init(tcp_timerset_t *set);
void tcp_timerset_free(tcp_timerset_t *set);
void tcp_timer_disable(tcp_timer_t *timer);
tcp_timer_t *tcp_timer_create(tcp_timerset_t *set, size_t ms, 
                              const char *name,
                              void (*callback)(void*), void *data);
