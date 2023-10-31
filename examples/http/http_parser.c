#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include "http_parser.h"

typedef struct {
    size_t offset;
    size_t length;
} slice_t;

typedef struct {
    const unsigned char *src;
    size_t len, cur;
} scanner_t;

#define EMPTY_SLICE ((slice_t) {0, 0})
#define EMPTY_STRING ((hp_string_t) {NULL, 0})

static bool is_lower_alpha(unsigned char c)
{
    return c >= 'a' && c <= 'z';
}

static bool is_upper_alpha(unsigned char c)
{
    return c >= 'A' && c <= 'Z';
}

static bool is_alpha(unsigned char c)
{
    return is_upper_alpha(c)
        || is_lower_alpha(c);
}

static bool is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex_digit(unsigned char c)
{
    return is_digit(c) 
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

static bool is_unreserved(unsigned char c)
{
    return is_alpha(c) || is_digit(c) 
        || c == '-' || c == '.' 
        || c == '_' || c == '~';
}

static bool is_subdelim(unsigned char c)
{
    return c == '!' || c == '$' 
        || c == '&' || c == '\'' 
        || c == '(' || c == ')' 
        || c == '*' || c == '+' 
        || c == ',' || c == ';' 
        || c == '=';
}

static bool is_pchar(unsigned char c)
{
    return is_unreserved(c) 
        || is_subdelim(c) 
        || c == ':' || c == '@';
}

static void report(hp_error_t *err, const char *fmt, ...)
{
    if (err != NULL && !err->occurred) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(err->msg, sizeof(err->msg), fmt, args);
        va_end(args);

        err->occurred = true;
    }
}

static slice_t slice_up(scanner_t *scanner, 
                        bool (*is_head)(unsigned char), 
                        bool (*is_body)(unsigned char))
{
    size_t offset = scanner->cur;
    if (scanner->cur < scanner->len && is_head(scanner->src[scanner->cur])) 
        do
            scanner->cur++;
        while (scanner->cur < scanner->len && is_body(scanner->src[scanner->cur]));
    return (slice_t) {offset, scanner->cur-offset};
}

static bool follows_char(scanner_t scanner, unsigned char c)
{
    return scanner.cur < scanner.len && scanner.src[scanner.cur] == c;
}

static bool follows_pchar(scanner_t scanner)
{
    return scanner.cur < scanner.len && is_pchar(scanner.src[scanner.cur]);
}

static bool follows_pair(scanner_t scanner, char pair[2])
{
    return scanner.cur+1 < scanner.len 
        && scanner.src[scanner.cur+0] == (unsigned char) pair[0]
        && scanner.src[scanner.cur+1] == (unsigned char) pair[1];
}

static bool follows_digit(scanner_t scanner)
{
    return scanner.cur < scanner.len
        && is_digit(scanner.src[scanner.cur]);
}

static bool follows_hex_digit(scanner_t scanner)
{
    return scanner.cur < scanner.len
        && is_hex_digit(scanner.src[scanner.cur]);
}

static bool consume_char(scanner_t *scanner, unsigned char c)
{
    if (follows_char(*scanner, c)) {
        scanner->cur++;
        return true;
    } else
        return false;
}

static void unconsume_char(scanner_t *scanner)
{
    assert(scanner->cur > 0);
    scanner->cur--;
}

static bool consume_pchar(scanner_t *scanner)
{
    if (follows_pchar(*scanner)) {
        scanner->cur++;
        return true;
    } else
        return false;
}

static bool consume_pair(scanner_t *scanner, char pair[static 2])
{
    if (follows_pair(*scanner, pair)) {
        scanner->cur += 2;
        return true;
    } else
        return false;
}

static bool consume_digit(scanner_t *scanner, unsigned char *digit)
{
    if (follows_digit(*scanner)) {
        *digit = scanner->src[scanner->cur];
        scanner->cur++;
        return true;
    } else
        return false;
}

static bool consume_hex_digit(scanner_t *scanner, unsigned char *digit)
{
    if (follows_hex_digit(*scanner)) {
        *digit = scanner->src[scanner->cur];
        scanner->cur++;
        return true;
    } else
        return false;
}

static void consume_spaces(scanner_t *scanner)
{
    while (consume_char(scanner, ' '));
}

static bool consume_u64_base_10(scanner_t *scanner, uint64_t max, uint64_t *out)
{
    if (!follows_digit(*scanner))
        return false;

    uint64_t num = 0;
    unsigned char digit;
    while (consume_digit(scanner, &digit)) {
        int u = digit - '0';
        if (num > (max - u) / 10) {
            unconsume_char(scanner);
            break;
        }
        num = num * 10 + u;
    }
    
    *out = num;
    return true;
}

static int hex_digit_to_int(char c)
{
    assert(is_hex_digit(c));
    
    if (is_lower_alpha(c))
        return c - 'a' + 10;
    
    if (is_upper_alpha(c))
        return c - 'A' + 10;
    
    assert(is_digit(c));
    return c - '0';
}

static bool consume_u64_base_16(scanner_t *scanner, uint64_t max, uint64_t *out)
{
    if (!follows_hex_digit(*scanner))
        return false;

    uint64_t num = 0;
    unsigned char digit;
    while (consume_hex_digit(scanner, &digit)) {
        int u = hex_digit_to_int(digit);
        if (num > (max - u) / 16) {
            unconsume_char(scanner);
            break;
        }
        num = num * 16 + u;
    }
    
    *out = num;
    return true;
}

static bool consume_u8_base_10(scanner_t *scanner, uint8_t *out)
{
    uint64_t buffer;
    bool ok = consume_u64_base_10(scanner, UINT8_MAX, &buffer);
    assert(!ok || buffer <= UINT8_MAX);
    *out = buffer;
    return ok;
}

static bool consume_u16_base_16(scanner_t *scanner, uint16_t *out)
{
    uint64_t buffer;
    bool ok = consume_u64_base_16(scanner, UINT16_MAX, &buffer);
    assert(!ok || buffer <= UINT16_MAX);
    *out = buffer;
    return ok;
}

static bool consume_u16_base_10(scanner_t *scanner, uint16_t *out)
{
    uint64_t buffer;
    bool ok = consume_u64_base_10(scanner, UINT16_MAX, &buffer);
    assert(!ok || buffer <= UINT16_MAX);
    *out = buffer;
    return ok;
}

// [<schema> : ] // [ <username> [ : <password> ] @ ] { <name> | <IPv4> | "[" <IPv5> "]" } [ : <port> ] [ </path> ] [ ? <query> ] [ # <fragment> ]

static bool is_schema_first(unsigned char c)
{
    return is_alpha(c);
}

static bool is_schema(unsigned char c)
{
    return is_alpha(c) 
        || is_digit(c) 
        || c == '+' 
        || c == '-'
        || c == '.';
}

static slice_t parse_schema(scanner_t *scanner)
{
    size_t start = scanner->cur;

    slice_t schema = slice_up(scanner, is_schema_first, is_schema);
    if (schema.length > 0)
        if (!consume_char(scanner, ':')) {
            scanner->cur = start;
            return EMPTY_SLICE;
        }
    return schema;
}

static bool is_username(unsigned char c)
{
    return is_unreserved(c) || is_subdelim(c);
}

static bool is_username_first(unsigned char c)
{
    return is_username(c);
}

static bool is_password(unsigned char c)
{
    return is_username(c);
}

static bool is_password_first(unsigned char c)
{
    return is_password(c);
}

static hp_string_t string_from_slice(const unsigned char *src, slice_t slice)
{
    assert(src != NULL);

    if (slice.length == 0)
        return EMPTY_STRING;
    else
        return (hp_string_t) {(char*) src + slice.offset, slice.length};
}

static void parse_userinfo(scanner_t *scanner, slice_t *username, slice_t *password)
{
    size_t start = scanner->cur;

    *password = EMPTY_SLICE;

    *username = slice_up(scanner, is_username_first, is_username);
    if (username->length > 0) {

        if (consume_char(scanner, ':'))
            *password = slice_up(scanner, is_password_first, is_password);

        if (!consume_char(scanner, '@')) {
            *username = EMPTY_SLICE;
            *password = EMPTY_SLICE;
            scanner->cur = start; // Rollback changes
        }
    }
}

static bool parse_ipv4(scanner_t *scanner, uint32_t *out, hp_error_t *err)
{
    uint8_t  byte;
    uint32_t ipv4 = 0;

    for (int u = 0; u < 3; u++) {
        
        if (!consume_u8_base_10(scanner, &byte)) {
            if (u == 0)
                report(err, "Missing IPv4");
            else
                report(err, "Missing IPv4 byte");
            return false;
        }
        ipv4 = (ipv4 << 8) + byte;
        
        if (!consume_char(scanner, '.'))
            return false;
    }

    if (!consume_u8_base_10(scanner, &byte)) {
        report(err, "Missing IPv4 byte");
        return false;
    }
    ipv4 = (ipv4 << 8) + byte;

    *out = ipv4;
    return true;
}

static bool parse_ipv6(scanner_t *scanner, uint16_t ipv6[static 8], hp_error_t *err)
{
    uint16_t tail[8];
    size_t head_count = 0;
    size_t tail_count = 0;

    if (!consume_pair(scanner, "::")) {

        do {
            uint16_t word;
            if (!consume_u16_base_16(scanner, &word)) {
                if (scanner->cur == scanner->len) {
                    if (head_count == 0)
                        report(err, "Missing IPv6");
                    else
                        report(err, "Missing IPv6 hex value");
                } else
                    report(err, "Invalid IPv6");
                return false;
            }

            ipv6[head_count++] = word;
            
            if (head_count == 8)
                break;
            
            if (!consume_char(scanner, ':')) {
                report(err, "Missing ':' after IPv6 hex value");
                return false;
            }

        } while (!consume_char(scanner, ':'));
    }

    if (head_count + tail_count < 8) {
        while (follows_hex_digit(*scanner)) {

            // We know the current character is a
            // hex digit, therefore [parse_ipv6_word]
            // won't fail.
            uint16_t word;
            (void) consume_u16_base_16(scanner, &word);

            tail[tail_count++] = word;
            
            if (head_count + tail_count == 8)
                break;
            
            if (!consume_char(scanner, ':'))
                break;
        }
    }

    assert(head_count + tail_count <= 8);

    for (size_t p = 0; p < 8 - head_count - tail_count; p++)
        ipv6[head_count + p] = 0;

    for (size_t p = 0; p < tail_count; p++)
        ipv6[8 - tail_count + p] = tail[p];

    return true;
}

static bool is_hostname(unsigned char c)
{
    return is_unreserved(c) || is_subdelim(c);
}

static bool is_hostname_first(unsigned char c)
{
    return is_hostname(c);
}

static bool parse_host(scanner_t *scanner, hp_host_t *host, hp_error_t *err)
{
    if (consume_char(scanner, '[')) {
        if (!parse_ipv6(scanner, host->ipv6, err))
            return false;
        if (!consume_char(scanner, ']')) {
            report(err, "Missing ']' after IPv6");
            return false;
        }
        host->mode = HP_HOSTMODE_IPV6;
    } else {

        uint32_t ipv4;
        bool  is_ipv4;

        if (follows_digit(*scanner)) {
            size_t start = scanner->cur;
            is_ipv4 = parse_ipv4(scanner, &ipv4, NULL);
            if (!is_ipv4)
                scanner->cur = start;
        } else
            is_ipv4 = false;

        if (is_ipv4) {
            host->ipv4 = ipv4;
            host->mode = HP_HOSTMODE_IPV4;
        } else {

            slice_t hostname = slice_up(scanner, is_hostname_first, is_hostname);
            if (hostname.length == 0) {
                report(err, "Missing host");
                return false;
            }

            host->mode = HP_HOSTMODE_NAME;
            host->name = string_from_slice(scanner->src, hostname);
        }
    }

    host->no_port = !consume_u16_base_10(scanner, &host->port);
    return true;
}

static bool parse_path(scanner_t *scanner, slice_t *out, hp_error_t *err)
{
    out->offset = scanner->cur;

    if (!consume_char(scanner, '/'))
        if (!follows_pchar(*scanner)) {
            report(err, "Missing path");
            return false;
        }

    while (consume_pchar(scanner)) {
        while (consume_pchar(scanner));
        if (!consume_char(scanner, '/'))
            break;
    }

    out->length = scanner->cur - out->offset;
    return true;
}

static bool is_query(unsigned char c)
{
    return is_pchar(c) || c == '/' || c == '?';
}

static bool is_fragment(unsigned char c)
{
    return is_pchar(c) || c == '/';
}

static bool parse_url(scanner_t *scanner, hp_url_t *url, hp_error_t *err)
{
    url->schema = string_from_slice(scanner->src, parse_schema(scanner));

    if (consume_pair(scanner, "//")) {

        slice_t username, password;
        parse_userinfo(scanner, &username, &password);
        url->username = string_from_slice(scanner->src, username);
        url->password = string_from_slice(scanner->src, password);

        if (!parse_host(scanner, &url->host, err))
            return false;

        if (follows_char(*scanner, '/')) {
            /* absolute path */
            // The parsing of the path can't fail 
            // because we already know there's at
            // leat a '/' for it.
            slice_t path;
            (void) parse_path(scanner, &path, err);
            url->path = string_from_slice(scanner->src, path);
        } else
            url->path = EMPTY_STRING;

    } else {

        url->host.mode = HP_HOSTMODE_NAME;
        url->host.name = EMPTY_STRING;
        url->host.no_port = true;
        url->host.port = 0;

        url->username = EMPTY_STRING;
        url->password = EMPTY_STRING;
        
        // TODO: Since there was no authority,
        //       the path is non optional.

        if (follows_char(*scanner, '?')) {
            report(err, "Missing path before query");
            return false;
        }
        if (follows_char(*scanner, '#')) {
            report(err, "Missing path before fragment");
            return false;
        }

        slice_t path;
        if (!parse_path(scanner, &path, err))
            return false;
        url->path = string_from_slice(scanner->src, path);
    }

    url->query = consume_char(scanner, '?')
               ? string_from_slice(scanner->src, slice_up(scanner, is_query, is_query))
               : EMPTY_STRING;

    url->fragment = consume_char(scanner, '#')
                  ? string_from_slice(scanner->src, slice_up(scanner, is_fragment, is_fragment))
                  : EMPTY_STRING;
    return true;
}

static bool is_header_name_body(unsigned char c)
{
    return is_alpha(c) || is_digit(c) || c == '-';
}

static bool is_header_name_head(unsigned char c)
{
    return is_header_name_body(c);
}

static bool is_header_body_body(unsigned char c)
{
    return c != '\r';
}

static bool is_header_body_head(unsigned char c)
{
    return is_header_body_body(c);
}

static bool parse_header(scanner_t *scanner, hp_header_t *header, hp_error_t *err)
{
    slice_t name, body;

    name = slice_up(scanner, is_header_name_head, is_header_name_body);
    if (name.length == 0) {
        report(err, "Missing header name");
        return false;
    }

    if (!consume_char(scanner, ':')) {
        report(err, "Missing ':' after header name");
        return false;
    }

    body = slice_up(scanner, is_header_body_head, is_header_body_body);

    if (!consume_pair(scanner, "\r\n")) {
        report(err, "Missing CRLF after header");
        return false;
    }

    header->name = string_from_slice(scanner->src, name);
    header->body = string_from_slice(scanner->src, body);
    return true;
}

static bool parse_version(scanner_t *scanner, int *major, int *minor, hp_error_t *err)
{
    unsigned char char_major = '0';
    unsigned char char_minor = '0';

    if (!consume_char(scanner, 'H') ||
        !consume_char(scanner, 'T') ||
        !consume_char(scanner, 'T') ||
        !consume_char(scanner, 'P') ||
        !consume_char(scanner, '/') ||
        !consume_digit(scanner, &char_major)) {
        report(err, "Invalid version token");
        return false;
    }
    if (consume_char(scanner, '.'))
        if (!consume_digit(scanner, &char_minor)) {
            report(err, "Invalid version token");
            return false;
        }
    *major = char_major - '0';
    *minor = char_minor - '0';
    return true;
}

static bool get_method_id(hp_string_t str, hp_method_t *method)
{
    // CONNECT OPTIONS TRACE PATCH
    switch (str.len) {
        case 3:
        if (str.str[0] == 'G' &&
            str.str[1] == 'E' &&
            str.str[2] == 'T') {
            *method = HP_METHOD_GET;
            return true;
        }
        if (str.str[0] == 'P' &&
            str.str[1] == 'U' &&
            str.str[2] == 'T') {
            *method = HP_METHOD_PUT;
            return true;
        }
        break;

        case 4:
        if (str.str[0] == 'P' &&
            str.str[1] == 'O' &&
            str.str[2] == 'S' &&
            str.str[3] == 'T') {
            *method = HP_METHOD_POST;
            return true;
        }
        if (str.str[0] == 'H' &&
            str.str[1] == 'E' &&
            str.str[2] == 'A' &&
            str.str[3] == 'D') {
            *method = HP_METHOD_HEAD;
            return true;
        }
        break;

        case 5:
        if (str.str[0] == 'T' &&
            str.str[1] == 'R' &&
            str.str[2] == 'A' &&
            str.str[3] == 'C' &&
            str.str[4] == 'E') {
            *method = HP_METHOD_TRACE;
            return true;
        }
        if (str.str[0] == 'P' &&
            str.str[1] == 'A' &&
            str.str[2] == 'T' &&
            str.str[3] == 'C' &&
            str.str[4] == 'H') {
            *method = HP_METHOD_PATCH;
            return true;
        }
        break;

        case 6:
        if (str.str[0] == 'D' &&
            str.str[1] == 'E' &&
            str.str[2] == 'L' &&
            str.str[3] == 'E' &&
            str.str[4] == 'T' &&
            str.str[5] == 'E') {
            *method = HP_METHOD_DELETE;
            return true;
        }
        break;
    }
    return false;
}

static bool is_method_body(unsigned char c)
{
    return is_upper_alpha(c);
}

static bool is_method_head(unsigned char c)
{
    return is_method_body(c);
}

static bool parse_method(scanner_t *scanner, hp_method_t *method, hp_error_t *err)
{
    slice_t method_slice = slice_up(scanner, is_method_head, is_method_body);
    if (method_slice.length == 0) {
        report(err, "Missing method");
        return false;
    }
    hp_string_t method_string = string_from_slice(scanner->src, method_slice);
    if (!get_method_id(method_string, method)) {
        report(err, "Invalid method %.*s", (int) method_string.len, method_string.str);
        return false;
    }
    return true;
}

static bool parse_status_line(scanner_t *scanner, 
                              hp_method_t *method, 
                              hp_url_t *url, 
                              int *major, int *minor,
                              hp_error_t *err)
{
    if (!parse_method(scanner, method, err))
        return false;

    if (!consume_char(scanner, ' ')) {
        report(err, "Missing space after method");
        return false;
    }

    if (!parse_url(scanner, url, err))
        return false;
    
    if (!consume_char(scanner, ' ')) {
        report(err, "Missing space after URL");
        return false;
    }

    if (!parse_version(scanner, major, minor, err))
        return false;

    if (!consume_pair(scanner, "\r\n")) {
        report(err, "Missing CRLF after version token");
        return false;
    }

    return true;
}

static void append_header(hp_request_t *req, 
                          hp_header_t header)
{
    if (req->num_headers < HP_MAX_HEADERS)
        req->headers[req->num_headers++] = header;
}

bool hp_parse(const char *src, size_t len, 
              hp_request_t *out, hp_error_t *err)
{
    scanner_t scanner = {(unsigned char*) src, len, 0};

    if (!parse_status_line(&scanner, &out->method, 
                           &out->url, &out->major, 
                           &out->minor, err))
        return false;
    
    out->num_headers = 0;
    while (!consume_pair(&scanner, "\r\n")) {
    
        hp_header_t header;
        if (!parse_header(&scanner, &header, err))
            return false;
    
        append_header(out, header);
    }

    return true;
}

bool hp_parse_url(const char *src, size_t len, 
                  hp_url_t *url, hp_error_t *err)
{
    scanner_t scanner = {(unsigned char*) src, len, 0};
    return parse_url(&scanner, url, err);
}

static char to_lower(char c)
{
    if (is_upper_alpha(c))
        return c - 'A' + 'a';
    else
        return c;
}

static bool case_insensitive_string_compare(hp_string_t s1, hp_string_t s2)
{
    if (s1.len != s2.len)
        return false;

    for (size_t i = 0; i < s1.len; i++)
        if (to_lower(s1.str[i]) != to_lower(s2.str[i]))
            return false;
    return true;
}

hp_header_t *hp_get_header(hp_request_t req, const char *name)
{
    hp_string_t name2 = {name, strlen(name)};
    for (size_t i = 0; i < req.num_headers; i++) {
        hp_header_t *header = req.headers + i;
        if (case_insensitive_string_compare(name2, header->name))
            return header;
    }
    return NULL;
}

static bool parse_content_length(const char *src, size_t len, size_t *out, hp_error_t *error)
{
    scanner_t scanner = {(unsigned char*) src, len, 0};
    consume_spaces(&scanner);
    
    if (!follows_digit(scanner)) {
        report(error, "Non-digit character in Content-Length header");
        return false;
    }
    
    *out = 0;
    unsigned char digit;
    while (consume_digit(&scanner, &digit)) {
        int k = digit - '0';
        if (*out > (SIZE_MAX - k) / 10) {
            report(error, "Unsigned integer is too big");
            return false;
        }
        *out = *out * 10 + k;
    }
    
    if (scanner.cur < scanner.len) {
        report(error, "Invalid character '%c'", scanner.src[scanner.cur]);
        return false;
    }
    return true;
}

bool hp_get_content_length(hp_request_t req, size_t *out, hp_error_t *error)
{
    hp_header_t *header = hp_get_header(req, "Content-Length");
    if (header == NULL)
        return 0;
    return parse_content_length(header->body.str, header->body.len, out, error);
}