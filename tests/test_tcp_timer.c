#include <assert.h>
#include "../src/tcp_timer.h"

static void set_int_variable_to_1(void *data)
{
    int *n = data;
    *n = 1;
}

static void test_timer(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int resolved = 0;
    tcp_timer_t *t1 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved);
    
    assert(t1);
    assert(resolved == 0);

    tcp_timerset_step(&set, 1);
    assert(resolved == 0);

    tcp_timerset_step(&set, 4);
    assert(resolved == 1);

    tcp_timerset_free(&set);
}

static void test_disabled_timer(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int resolved = 0;
    tcp_timer_t *t1 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved);
    
    assert(t1);
    assert(resolved == 0);

    tcp_timer_disable(t1);

    tcp_timerset_step(&set, 1);
    assert(resolved == 0);

    tcp_timerset_step(&set, 4);
    assert(resolved == 0);

    tcp_timerset_free(&set);
}

static void test_disabled_timer_2(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int resolved = 0;
    tcp_timer_t *t1 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved);
    
    assert(t1);
    assert(resolved == 0);

    tcp_timerset_step(&set, 1);
    assert(resolved == 0);

    tcp_timer_disable(t1);

    tcp_timerset_step(&set, 4);
    assert(resolved == 0);

    tcp_timerset_free(&set);
}

static void test_disabled_timer_3(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int resolved_1 = 0;
    int resolved_2 = 0;
    tcp_timer_t *t1 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved_1);
    tcp_timer_t *t2 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved_2);
    
    assert(t1);
    assert(t2);
    assert(resolved_1 == 0);
    assert(resolved_2 == 0);

    tcp_timerset_step(&set, 1);
    assert(resolved_1 == 0);
    assert(resolved_2 == 0);

    tcp_timer_disable(t1);

    tcp_timerset_step(&set, 4);
    assert(resolved_1 == 0);
    assert(resolved_2 == 1);

    tcp_timerset_free(&set);
}

static void test_disabled_timer_4(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int resolved_1 = 0;
    int resolved_2 = 0;
    tcp_timer_t *t1 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved_1);
    tcp_timer_t *t2 = tcp_timer_create(&set, 5, set_int_variable_to_1, &resolved_2);
    
    assert(t1);
    assert(t2);
    assert(resolved_1 == 0);
    assert(resolved_2 == 0);

    tcp_timerset_step(&set, 1);
    assert(resolved_1 == 0);
    assert(resolved_2 == 0);

    tcp_timer_disable(t2);

    tcp_timerset_step(&set, 4);
    assert(resolved_1 == 1);
    assert(resolved_2 == 0);

    tcp_timerset_free(&set);
}

static void test_out_of_timers(void)
{
    static_assert(TCP_MAX_TIMERS > 0);

    tcp_timerset_t set;
    tcp_timerset_init(&set);

    int temp;
    for (int i = 0; i < TCP_MAX_TIMERS; i++) {
        tcp_timer_t *t = tcp_timer_create(&set, 5, set_int_variable_to_1, &temp);
        assert(t != NULL);
    }
    tcp_timer_t *t = tcp_timer_create(&set, 5, set_int_variable_to_1, &temp);
    assert(t == NULL);

    tcp_timerset_free(&set);
}

void test_tcp_timer(void)
{
    test_timer();
    test_disabled_timer();
    test_disabled_timer_2();
    test_disabled_timer_3();
    test_disabled_timer_4();
    test_out_of_timers();
}