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

#include <ctype.h>
#include <stdlib.h> // rand
#include <string.h>
#include "utils.h"
#include "endian.h"

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static int int_from_hex_digit(char c)
{
    assert(is_hex_digit(c));
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return c - '0';
}

bool parse_mac(const char *src, size_t len, mac_address_t *mac)
{
    if (src == NULL || len != 17
     || !is_hex_digit(src[0]) 
     || !is_hex_digit(src[1])
     || src[2] != ':'
     || !is_hex_digit(src[3])
     || !is_hex_digit(src[4])
     || src[5] != ':'
     || !is_hex_digit(src[6])
     || !is_hex_digit(src[7])
     || src[8] != ':'
     || !is_hex_digit(src[9])
     || !is_hex_digit(src[10])
     || src[11] != ':'
     || !is_hex_digit(src[12])
     || !is_hex_digit(src[13])
     || src[14] != ':'
     || !is_hex_digit(src[15])
     || !is_hex_digit(src[16]))
        return false;

    static const char max_char_map[] = "0123456789ABCDEF";

    if (mac)
        for (int i = 0; i < 6; i++) {
            int u = int_from_hex_digit(src[i * 3 + 0]);
            int v = int_from_hex_digit(src[i * 3 + 1]);
            mac->data[i] = (max_char_map[u] << 4) | max_char_map[v];
        }
    
    return true;
}

mac_address_t generate_random_mac()
{
    mac_address_t mac = {
        .data = {
            rand() & 0xff,
            rand() & 0xff,
            rand() & 0xff,
            rand() & 0xff,
            rand() & 0xff,
            rand() & 0xff,
        },
    };
    return mac;
}


bool parse_ip(const char *ip, ip_address_t *parsed_ip)
{
    size_t len = strlen(ip);
    size_t i = 0;

    uint32_t value = 0;
    
    for (size_t k = 0; k < 4; k++) {
        if (i == len || !isdigit(ip[i]))
            return false;
        int n = 0; // Used to represent a byte, but it's larger
                   // to detect overflows.
        do {
            // Convert character to number
            int digit = ip[i] - '0';
            if (n > (UINT8_MAX - digit)/10)
                // Adding this digit would make the
                // byte overflow, so it can't be part
                // of the octet.
                break;
            n = n * 10 + digit;
            i++;
        } while (i < len && isdigit(ip[i]));
        
        assert(n >= 0 && n <= UINT8_MAX);
        value = (value << 8) | (uint8_t) n;
        
        // If this isn't the last octet and there is no
        // dot following it, the address is invalid.
        if (k < 3) {
            if (i == len || ip[i] != '.')
                return false;
            i++; // Consume the dot.
        }
    }
    if (i < len)
        // source string contains something 
        // other than the address in it.
        return false;

    *parsed_ip = cpu_to_net_u32(value);
    return true;
}