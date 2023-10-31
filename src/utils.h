#include <stdbool.h>
#include "defs.h"

bool parse_mac(const char *src, size_t len, mac_address_t *mac);
bool parse_ip(const char *ip, ip_address_t *parsed_ip);
mac_address_t generate_random_mac();
