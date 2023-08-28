#include <ctype.h>
#include <stdlib.h> // rand
#include <string.h>

#ifndef MICROTCP_AMALGAMATION
#include "utils.h"
#include "endian.h"
#endif

static bool is_hex_digit(char c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static int int_from_hex_digit(char c)
{
    assert(is_hex_digit(c));
    if (c >= 'A' || c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' || c <= 'f')
        return c - 'a' + 10;
    return c - '0';
}

bool parse_mac(const char *src, size_t len, 
                      mac_address_t *mac)
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

    if (mac) {
        mac->data[0] = max_char_map[int_from_hex_digit(src[ 0])] << 4
                     | max_char_map[int_from_hex_digit(src[ 1])];
        mac->data[1] = max_char_map[int_from_hex_digit(src[ 3])] << 4
                     | max_char_map[int_from_hex_digit(src[ 4])];
        mac->data[2] = max_char_map[int_from_hex_digit(src[ 6])] << 4
                     | max_char_map[int_from_hex_digit(src[ 7])];
        mac->data[3] = max_char_map[int_from_hex_digit(src[ 9])] << 4
                     | max_char_map[int_from_hex_digit(src[10])];
        mac->data[4] = max_char_map[int_from_hex_digit(src[12])] << 4
                     | max_char_map[int_from_hex_digit(src[13])];
        mac->data[5] = max_char_map[int_from_hex_digit(src[15])] << 4
                     | max_char_map[int_from_hex_digit(src[16])];
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