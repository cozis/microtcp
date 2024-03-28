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

#include "endian.h"

bool cpu_is_little_endian(void)
{
    uint16_t x = 1;
    return *((uint8_t*) &x);
}

static uint16_t invert_byte_order_u16(uint32_t n)
{
    return (n >> 8) 
         | (n << 8);
}

static uint32_t invert_byte_order_u32(uint32_t n)
{
    return ((n >> 24) & 0x000000FF)
         | ((n >>  8) & 0x0000FF00)
         | ((n <<  8) & 0x00FF0000)
         | ((n << 24) & 0xFF000000);
}

uint16_t net_to_cpu_u16(uint16_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u16(n);
    return n;
}

uint32_t net_to_cpu_u32(uint32_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u32(n);
    return n;
}

uint16_t cpu_to_net_u16(uint16_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u16(n);
    return n;
}

uint32_t cpu_to_net_u32(uint32_t n)
{
    if (cpu_is_little_endian())
        return invert_byte_order_u32(n);
    return n;
}