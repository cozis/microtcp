#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define HP_MAX_HEADERS 8

typedef struct {
    const char *str;
    size_t len;
} hp_string_t;

typedef struct {
    bool occurred;
    char msg[256];
} hp_error_t;

typedef enum {
    HP_METHOD_GET,
    HP_METHOD_PUT,
    HP_METHOD_POST,
    HP_METHOD_HEAD,
    HP_METHOD_PATCH,
    HP_METHOD_TRACE,
    HP_METHOD_DELETE,
} hp_method_t;

typedef enum {
    HP_HOSTMODE_NAME,
    HP_HOSTMODE_IPV4,
    HP_HOSTMODE_IPV6,
} hp_hostmode_t;

typedef struct {
    hp_hostmode_t mode;
    union {
        uint32_t ipv4;
        uint16_t ipv6[8];
        hp_string_t name;
    };
    bool  no_port;
    uint16_t port;
} hp_host_t;

typedef struct {
    hp_host_t host;
    hp_string_t path;
    hp_string_t query;
    hp_string_t schema;
    hp_string_t fragment;
    hp_string_t username;
    hp_string_t password;
} hp_url_t;

typedef struct {
    hp_string_t name;
    hp_string_t body;
} hp_header_t;

typedef struct {
    int major, minor;
    hp_url_t url;
    hp_method_t method;
    hp_header_t headers[HP_MAX_HEADERS];
    size_t num_headers;
} hp_request_t;

bool hp_parse(const char *src, size_t len, hp_request_t *out, hp_error_t *err);
bool hp_parse_url(const char *src, size_t len, hp_url_t *url, hp_error_t *err);
hp_header_t *hp_get_header(hp_request_t req, const char *name);
bool hp_get_content_length(hp_request_t req, size_t *out, hp_error_t *error);