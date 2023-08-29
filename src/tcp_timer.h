#include <stdint.h>

#ifndef TCP_MAX_TIMERS
#define TCP_MAX_TIMERS 1024
#endif

typedef struct tcp_timerset_t tcp_timerset_t;
typedef struct tcp_timer_t    tcp_timer_t;

struct tcp_timer_t {
    tcp_timerset_t *set;
    tcp_timer_t *prev;
    tcp_timer_t *next;
    uint64_t deadline;
    void (*callback)(void *data);
    void *data;
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
                              void (*callback)(void*), void *data);
