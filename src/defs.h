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

#ifndef MICROTCP_DEFS_H
#define MICROTCP_DEFS_H
#include <stdint.h>
#include <assert.h> // static_assert

typedef struct {
    uint8_t data[6];
} mac_address_t;

typedef uint32_t ip_address_t;

static_assert(sizeof(mac_address_t) == 6);
static_assert(sizeof(ip_address_t) == 4);

#define MAC_ZERO      (mac_address_t) {.data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
#define MAC_BROADCAST (mac_address_t) {.data = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}

typedef struct {
    void  *ptr;
    size_t len;
} slice_t;

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define ABS(X) ((X) < 0 ? -(X) : (X))
#define COUNT(X) ((int) (sizeof(X) / sizeof((X)[0])))
#define SLICE(X) ((slice_t) {.ptr=&(X), .len=sizeof(X)})

#define UNPACK_IP(IP)    \
    ((IP) >> 0  & 0xff), \
    ((IP) >> 8  & 0xff), \
    ((IP) >> 16 & 0xff), \
    ((IP) >> 24 & 0xff)

#endif /* MICROTCP_DEFS_H */
