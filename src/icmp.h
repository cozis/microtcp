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
#include "defs.h"

typedef struct {
    void  *output_ptr;
    size_t output_len;
    void *send_data;
    void (*send)(void *send_data, ip_address_t ip, size_t len);
} icmp_state_t;

void icmp_init(icmp_state_t *state, void *send_data, void (*send)(void*, ip_address_t, size_t));
void icmp_free(icmp_state_t *state);
void icmp_process_packet(icmp_state_t *state, ip_address_t ip, const void *src, size_t len);
void icmp_change_output_buffer(icmp_state_t *state, void *ptr, size_t len);
