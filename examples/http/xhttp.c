#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <microtcp.h>
#include "xhttp.h"


/*                                          __ _________________                                  *
 *                                   __ __ / // /_  __/_  __/ _ \                                 *
 *                                   \ \ // _  / / /   / / / ___/                                 *
 *                                  /_\_\/_//_/ /_/   /_/ /_/                                     *
 *                                                                                                *
 * +--------------------------------------------------------------------------------------------+ *
 * |                                                                                            | *
 * |                                          OVERVIEW                                          | *
 * |                                                                                            | *
 * | The logic starts inside the [xhttp] function, where the server waits in a loop for events  | *
 * | provided by epoll (the event loop).                                                        | *
 * |                                                                                            | *
 * | Each client connection is represented by a [conn_t] structure, which is basically composed | *
 * | by a buffer of input data, a buffer of output data, the parsing state of the input buffer  | *
 * | plus some more fields required to hold the state of the parsing and to manage the          | *
 * | connection. These structures are preallocated at start-up time and determine the capacity  | *
 * | of the server.                                                                             | *
 * |                                                                                            | *
 * | Whenever a client requests to connect, the server decides if it can handle it or not. If   | *
 * | it can, it gives it a [conn_t] structure and registers it into the event loop.             | *
 * |                                                                                            | *
 * | When the event loop signals that a connection sent some data, the data is copied from the  | *
 * | kernel into the user-space buffer of the [conn_t] structure. If the head of the request    | *
 * | wasn't received or was received partially, the character sequence "\r\n\r\n" (a blank line)| *
 * | is searched for inside the downloaded data. The "\r\n\r\n" token signifies the end of the  | *
 * | request's head and the start of it's body. If the head wasn't received the server goes     | *
 * | back to waiting for new events. If the token is found, the head can be parsed and the size | *
 * | of the body determined. If the whole body of the request was received with the head, the   | *
 * | request can already be handled. If the body wasn't received, the servers goes back to      | *
 * | waiting for events until the rest of the body is received. When the body is fully received,| *
 * | the user-provided callback can be called to generate a response.                           | *
 * | One thing to note is that multiple requests could be read from a single [recv], making it  | *
 * | necessary to perform these operations on the input buffer in a loop.                       | *
 * |                                                                                            | *
 * | If at any point of this process the request is determined to be invalid or an internal     | *
 * | error occurres, a 4xx or 5xx response is sent.                                             | *
 * |                                                                                            | *
 * | While handling data input events, the response is never sent directly to the kernel buffer,| *
 * | because the call to [send] could block the server. Instead, the response is written to the | *
 * | [conn_t]'s output buffer. This buffer is only flushed to the kernel when a write-ready     | *
 * | event is triggered for that connection.                                                    | *
 * |                                                                                            | *
 * +--------------------------------------------------------------------------------------------+ *
 *                                                                                                */

typedef enum { 
    XH_REQ, 
    XH_RES 
} struct_type_t;

typedef struct {
    struct_type_t type;
    xh_response public;
    xh_table   headers;
    int capacity;
    bool failed;
} xh_response2;

typedef struct {
    struct_type_t type;
    xh_request  public;
} xh_request2;

typedef struct {
    char    *data;
    uint32_t size;
    uint32_t used;
} buffer_t;

typedef struct conn_t conn_t;
struct conn_t {

    // This is used to hold a free-list
    // of [conn_t] structures.
    conn_t *next;

    // I/O buffers required for async.
    // reads and writes.
    buffer_t in, out;

    // Connection's socked file 
    // descriptor.
    microtcp_socket_t *sock;

    // Number of resources served to
    // this client. This is used to
    // determine which connections to
    // keep alive.
    int served;

    // This flags can be set after a
    // response is written to the output
    // buffer. If set, then all reads
    // from the client stop and when the
    // output buffer is flushed the 
    // connection is closed.
    bool close_when_uploaded;

    // The way writes to the output buffer occur is
    //  through the [append_string_to_output_buffer] 
    // function. Since the output buffer may beed to 
    // be resized, the [append_string_to_output_buffer] 
    // operation may fail. Since checking every time 
    // for the return value makes the code very verbose, 
    // instead of returning an error value, this flag 
    // is set. If this flag is set then 
    // [append_string_to_output_buffer] operations 
    // have no effect and when [upload] is called it 
    // returns the error that the  first 
    // [append_string_to_output_buffer] that failed 
    // would have returned.
    bool failed_to_append;

    bool   head_received;
    uint32_t body_offset;
    uint32_t body_length;
    xh_request2  request;
};

typedef struct {
    bool exiting;
    microtcp_t *mtcp;
    microtcp_socket_t *sock;
    microtcp_mux_t *mux;
    int connum;
    conn_t *freelist;
    xh_callback callback;
    void *userp;
    conn_t pool[MICROHTTP_MAX_CLIENTS];
} context_t;

static const char *statis_code_to_status_text(int code)
{
    switch(code)
    {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 102: return "Processing";

        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 207: return "Multi-Status";
        case 208: return "Already Reported";

        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "Switch Proxy";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";

        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a teapot";
        case 420: return "Enhance your calm";
        case 422: return "Unprocessable Entity";
        case 426: return "Upgrade Required";
        case 429: return "Too many requests";
        case 431: return "Request Header Fields Too Large";
        case 449: return "Retry With";
        case 451: return "Unavailable For Legal Reasons";

        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        case 509: return "Bandwidth Limit Exceeded";
    }
    return "???";
}

/* Symbol: find_header
 *
 *   Finds the header from a header array.
 *
 * Arguments:
 *
 *   - headers: The header set array.
 *
 *   - name: Zero-terminated string that contains the 
 *           header's name. The comparison with each 
 *           header's name is made using [xh_header_cmp],
 *           so it's not case-sensitive.
 *
 * Returns:
 *   The index in the array of the matched header, or
 *   -1 is no header was found.
 */
static int find_header(xh_table headers, const char *name)
{
    for(int i = 0; i < headers.count; i += 1)
        if(xh_header_cmp(name, headers.list[i].key.str))
            return i;
    return -1;
}

/* Symbol: xh_header_add
 *
 *   Add or replace a header into a response object.
 *
 * Arguments:
 *
 *   - res: The response object.
 *
 *   - name: Zero-terminated string that contains
 *           the header's name. The comparison with
 *           each header's name is made using [xh_header_cmp],
 *           so it's not case-sensitive.
 *
 *   - valfmt: A printf-like format string that evaluates
 *             to the header's value.
 *
 * Returns:
 *   Nothing. The header may or may not be added
 *   (or replaced) to the request.
 */
void xh_header_add(xh_response *res, const char *name, const char *valfmt, ...)
{
    xh_response2 *res2 = (xh_response2*) ((char*) res - offsetof(xh_response2, public));

    assert(&res2->public == res);

    if(res2->failed)
        return;

    int i = find_header(res2->headers, name);

    unsigned int name_len, value_len;

    name_len = name == NULL ? 0 : strlen(name);

    char value[512];
    {
        va_list args;
        va_start(args, valfmt);
        int n = vsnprintf(value, sizeof(value), valfmt, args);
        va_end(args);

        if(n < 0)
        {
            // Bad format.
            res2->failed = 1;
            return;
        }

        if((unsigned int) n >= sizeof(value))
        {
            // Static buffer is too small.
            res2->failed = 1;
            return;
        }

        value_len = n;
    }

    // Duplicate name and value.
    char *name2, *value2;
    {
        void *mem = malloc(name_len + value_len + 2);

        if(mem == NULL)
        {
            // ERROR!
            res2->failed = 1;
            return;
        }

        name2  = (char*) mem;
        value2 = (char*) mem + name_len + 1;

        strcpy(name2, name);
        strcpy(value2, value);
    }

    if(i < 0)
    {
        if(res2->headers.count == res2->capacity)
            {
                int new_capacity = res2->capacity == 0 
                                 ? 8 : res2->capacity * 2;

                void *tmp = realloc(res2->headers.list, 
                                new_capacity * sizeof(xh_pair));

                if(tmp == NULL)
                {
                    // ERROR!
                    res2->failed = 1;
                    free(name2);
                    return;
                }

                res2->headers.list = tmp;
                res2->capacity = new_capacity;
            }

        res2->headers.list[res2->headers.count] = (xh_pair) {
            { name2, name_len }, { value2, value_len },
        };
        res2->headers.count += 1;
        res2->public.headers = res2->headers;
    }
    else
    {
        free(res2->headers.list[i].key.str);
        res2->headers.list[i] = (xh_pair) {
            { name2, name_len }, { value2, value_len },
        };
    }
}

/* Symbol: xh_header_rem
 *
 *   Remove a header from a response object.
 *
 * Arguments:
 *
 *   - res: The response object that contains the
 *          header to be removed.
 *
 *   - name: Zero-terminated string that contains
 *           the header's name. The comparison with
 *           each header's name is made using [xh_header_cmp],
 *           so it's not case-sensitive.
 *
 * Returns:
 *   Nothing.
 */
void xh_header_rem(xh_response *res, const char *name)
{
    xh_response2 *res2 = (xh_response2*) ((char*) res - offsetof(xh_response2, public));

    assert(&res2->public == res);

    if(res2->failed)
        return;

    int i = find_header(res2->headers, name);

    if(i < 0)
        return;

    free(res2->headers.list[i].key.str);

    assert(i >= 0);

    for(; i < res2->headers.count-1; i += 1)
        res2->headers.list[i] = res2->headers.list[i+1];

    res2->headers.count -= 1;
    res2->public.headers = res2->headers;
}

static xh_table get_headers_from_req_or_res(void *req_or_res)
{
    _Static_assert(offsetof(xh_response2, public) == offsetof(xh_request2, public), 
                       "The public portion of xh_response2 and xh_request2 must be aligned the same way");

    struct_type_t type = ((xh_request2*) ((char*) req_or_res 
                     - offsetof(xh_request2, public)))->type;

    assert(type == XH_RES || type == XH_REQ);

    xh_table headers = (type == XH_REQ)?
            ((xh_request *) req_or_res)->headers:
            ((xh_response*) req_or_res)->headers;
    return headers;
}

/* Symbol: xh_header_get
 *
 *   Find the contents of a header given it's
 *   name from a response or request object.
 *
 * Arguments:
 *
 *   - req_or_res: The request or response object
 *                 that contains the header. This
 *                 argument must originally be of
 *                 type [xh_request*] or [xh_response*].
 *
 *   - name: Zero-terminated string that contains
 *           the header's name. The comparison with
 *           each header's name is made using [xh_header_cmp],
 *           so it's not case-sensitive.
 *
 * Returns:
 *   A zero-terminated string containing the value of
 *   the header or NULL if the header isn't contained
 *   in the request/response.
 *
 * Notes:
 *   - The returned value is invalidated if
 *     the header is removed using [xh_hrem].
 */
const char *xh_header_get(void *req_or_res, const char *name)
{
    xh_table headers = get_headers_from_req_or_res(req_or_res);

    int i = find_header(headers, name);

    if(i < 0)
        return NULL;

    return headers.list[i].val.str;
}

/* Symbol: xh_header_cmp
 *
 *   This function compares header names.
 *   The comparison isn't case-sensitive.
 *
 * Arguments:
 *
 *   - a: Zero-terminated string that contains
 *        the first header's name.
 *
 *   - b: Zero-terminated string that contains
 *        the second header's name.
 *
 * Returns:
 *   1 if the header names match, 0 otherwise.
 */
bool xh_header_cmp(const char *a, const char *b)
{
    if(a == NULL || b == NULL)
        return a == b;

    while(*a != '\0' && *b != '\0' && tolower(*a) == tolower(*b))
        a += 1, b += 1;

    return tolower(*a) == tolower(*b);
}

static void res_init(xh_response2 *res)
{
    memset(res, 0, sizeof(xh_response2));
    res->type = XH_RES;
    res->public.body.len = -1;
}

static void res_deinit(xh_response2 *res)
{
    if(res->headers.list != NULL)
    {
        assert(res->headers.count > 0);
        for(int i = 0; i < res->headers.count; i += 1)
            free(res->headers.list[i].key.str);
        free(res->headers.list);
    }
}

static void res_reinit(xh_response2 *res)
{
    res_deinit(res);
    res_init(res);
}

static void req_init(xh_request2 *req)
{
    req->type = XH_REQ;
}

static void req_deinit(xh_request *req)
{
    free(req->headers.list);
    req->headers.list = NULL;
    req->headers.count = 0;
}

static conn_t *accept_connection(context_t *ctx)
{
    microtcp_socket_t *accepted_sock = microtcp_accept(ctx->sock);
    if(accepted_sock == NULL) return NULL;
    microtcp_set_blocking(accepted_sock, false);

    if(ctx->freelist == NULL)
    {
        // Connection limit reached.
        microtcp_close(accepted_sock);
        return NULL;
    }

    conn_t *conn = ctx->freelist;
    ctx->freelist = conn->next;

    assert(((intptr_t) conn & 
            (intptr_t) 1) == 0);

    memset(conn, 0, sizeof(conn_t));
    conn->sock = accepted_sock;
    req_init(&conn->request);

    if(!microtcp_mux_register(ctx->mux, accepted_sock, MICROTCP_MUX_RECV|MICROTCP_MUX_SEND, conn))
    {
        microtcp_close(accepted_sock);

        conn->sock = NULL;
        conn->next = ctx->freelist;
        ctx->freelist = conn;
        return NULL;
    }

    ctx->connum += 1;
    return conn;
}

static void close_connection(context_t *ctx, conn_t *conn)
{
    microtcp_close(conn->sock);

    if(conn->in.data != NULL)
    {
        free(conn->in.data);
        conn->in.data = NULL;
    }

    if(conn->out.data != NULL)
    {
        free(conn->out.data);
        conn->out.data = NULL;
    }

    if(conn->request.public.headers.list != NULL)
        free(conn->request.public.headers.list);

    conn->sock = NULL;

    conn->next = ctx->freelist;
    ctx->freelist = conn;

    ctx->connum -= 1;
}

#if DEBUG
static void close_connection_(context_t *ctx, conn_t *conn, const char *file, int line)
{
    fprintf(stderr, "Closing connection at %s:%d.\n", file, line);
    close_connection(ctx, conn);
}
#define close_connection(ctx, conn) close_connection_(ctx, conn, __FILE__, __LINE__)
#endif

static bool is_uppercase_alpha(char c)
{
    return c >= 'A' && c <= 'Z';
}

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_space(char c)
{
    return c == ' ';
}

static void skip(char *str, uint32_t len, uint32_t *i, bool not, bool (*test)(char))
{
    if(not)
        while(*i < len && !test(str[*i]))
            *i += 1;
    else
        while(*i < len && test(str[*i]))
            *i += 1;
}

static void skip_until(char *str, uint32_t len, uint32_t *i, char c)
{
    while(*i < len && str[*i] != c)
        *i += 1;
}

struct parse_err_t {
    bool   internal;
    char        *msg;
    unsigned int len;
};

static struct parse_err_t parse(char *str, uint32_t len, xh_request *req)
{
    #define OK \
        ((struct parse_err_t) { .internal = 0, .msg = NULL})

    #define FAILURE(msg_) \
        ((struct parse_err_t) { .internal = 0, .msg = msg_, .len = sizeof(msg_)-1 })

    #define INTERNAL_FAILURE(msg_) \
        ((struct parse_err_t) { .internal = 1, .msg = msg_, .len = sizeof(msg_)-1 })

    if(len == 0)
        return FAILURE("Empty request");

    uint32_t i = 0;

    uint32_t method_offset = i;

    skip(str, len, &i, 0, is_uppercase_alpha);

    uint32_t method_length = i - method_offset;

    if(method_length == 0)
        return FAILURE("Missing method");

    if(i == len)
        return FAILURE("Missing URL and HTTP version");

    if(!is_space(str[i]))
        return FAILURE("Bad character after method. Methods can only have uppercase alphabetic characters");

    skip(str, len, &i, 0, is_space);

    if(i == len)
        return FAILURE("Missing URL and HTTP version");

    uint32_t URL_offset = i;
    while(i < len && str[i] != ' ' && str[i] != '?')
        i += 1;
    uint32_t URL_length = i - URL_offset;
    
    uint32_t params_offset;
    if(i < len && str[i] == '?')
    {
        params_offset = i+1;
        while(i < len && str[i] != ' ')
            i += 1;
    }
    else params_offset = i;
    uint32_t params_length = i - params_offset;

    if(i == len)
        return FAILURE("Missing HTTP version");

    assert(is_space(str[i]));

    skip(str, len, &i, 0, is_space);

    if(i == len)
        return FAILURE("Missing HTTP version");

    uint32_t version_offset = i;

    skip_until(str, len, &i, '\r');

    uint32_t version_length = i - version_offset;

    if(version_length == 0)
        return FAILURE("Missing HTTP version");

    if(i == len)
        return FAILURE("Missing CRLF after HTTP version");

    assert(str[i] == '\r');

    i += 1; // Skip the \r.

    if(i == len)
        return FAILURE("Missing LF after CR");

    if(str[i] != '\n')
        return FAILURE("Missing LF after CR");

    i += 1; // Skip the \n.

    int capacity = 0;
    xh_table headers = { 
        .list = NULL, .count = 0 };

    while(1)
    {
        if(i == len)
        {
            free(headers.list);
            return FAILURE("Missing blank line");
        }

        if(i+1 < len && str[i] == '\r' && str[i+1] == '\n')
        {
            // Blank line.
            i += 2;
            break;
        }

        uint32_t hname_offset = i;

        skip_until(str, len, &i, ':');

        uint32_t hname_length = i - hname_offset;

        if(i == len)
        {
            free(headers.list);
            return FAILURE("Malformed header");
        }

        if(hname_length == 0)
        {
            free(headers.list);
            return FAILURE("Empty header name");
        }

        assert(str[i] == ':');

        // Make the header name zero-terminated
        // by overwriting the ':' with a '\0'.
        str[i] = '\0';

        i += 1; // Skip the ':'.

        uint32_t hvalue_offset = i;

        do
        {
            skip_until(str, len, &i, '\r');

            if(i == len)
            {
                free(headers.list);
                return FAILURE("Malformed header");
            }

            assert(str[i] == '\r');

            i += 1; // Skip the \r.

            if(i == len)
            {
                free(headers.list);
                return FAILURE("Malformed header");
            }
        }
        while(str[i] != '\n');
        assert(str[i] == '\n');
        i += 1; // Skip the '\n'.

        uint32_t hvalue_length = (i - 2) - hvalue_offset;

        if(headers.count == capacity)
        {
            int new_capacity = capacity == 0 ? 8 : capacity * 2;

            void *temp = realloc(headers.list, 
                new_capacity * sizeof(xh_pair));

            if(temp == NULL)
            {
                free(headers.list);
                return INTERNAL_FAILURE("No memory");
            }

            capacity = new_capacity;
            headers.list = temp;
        }

        headers.list[headers.count++] = (xh_pair) {
            { str +  hname_offset,  hname_length },
            { str + hvalue_offset, hvalue_length },
        };

        str[ hname_offset +  hname_length] = '\0';
        str[hvalue_offset + hvalue_length] = '\0';
    }

    req->headers = headers;

    req->method = xh_string_new(str + method_offset, method_length);
    req->URL    = xh_string_new(str +    URL_offset,    URL_length);
    req->params = xh_string_new(str + params_offset, params_length);

    str[ method_offset +  method_length] = '\0';
    str[    URL_offset +     URL_length] = '\0';
    str[ params_offset +  params_length] = '\0';
    str[version_offset + version_length] = '\0';

    // Validate the header.
    {
        bool unknown_method = 0;

        #define PAIR(p, q) (uint64_t) (((uint64_t) p << 32) | (uint64_t) q)
        switch(PAIR(req->method.str[0], method_length))
        {
            case PAIR('G', 3): req->method_id = XH_GET;     unknown_method = !!strcmp(req->method.str, "GET");  break;
            case PAIR('H', 4): req->method_id = XH_HEAD;    unknown_method = !!strcmp(req->method.str, "HEAD"); break;
            case PAIR('P', 4): req->method_id = XH_POST;    unknown_method = !!strcmp(req->method.str, "POST"); break;
            case PAIR('P', 3): req->method_id = XH_PUT;     unknown_method = !!strcmp(req->method.str, "PUT");  break;
            case PAIR('D', 6): req->method_id = XH_DELETE;  unknown_method = !!strcmp(req->method.str, "DELETE");  break;
            case PAIR('C', 7): req->method_id = XH_CONNECT; unknown_method = !!strcmp(req->method.str, "CONNECT"); break;
            case PAIR('O', 7): req->method_id = XH_OPTIONS; unknown_method = !!strcmp(req->method.str, "OPTIONS"); break;
            case PAIR('T', 5): req->method_id = XH_TRACE;   unknown_method = !!strcmp(req->method.str, "TRACE"); break;
            case PAIR('P', 5): req->method_id = XH_PATCH;   unknown_method = !!strcmp(req->method.str, "PATCH"); break;
            default: unknown_method = 1; break;
        }
        #undef PAIR

        if(unknown_method)
        {
            free(headers.list);
            return FAILURE("Unknown method");
        }
    }

    // Validate the HTTP version
    {
        bool bad_version = 0;
        switch(version_length)
        {
            case sizeof("HTTP/M.N")-1:

            if(!strcmp(str + version_offset, "HTTP/0.9"))
            {
                req->version_major = 0;
                req->version_minor = 9;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/1.0"))
            {
                req->version_major = 1;
                req->version_minor = 0;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/1.1"))
            {
                req->version_major = 1;
                req->version_minor = 1;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/2.0"))
            {
                req->version_major = 2;
                req->version_minor = 0;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/3.0"))
            {
                req->version_major = 3;
                req->version_minor = 0;
                break;
            }

            bad_version = 1;
            break;

            case sizeof("HTTP/M")-1:

            if(!strcmp(str + version_offset, "HTTP/1"))
            {
                req->version_major = 1;
                req->version_minor = 0;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/2"))
            {
                req->version_major = 2;
                req->version_minor = 0;
                break;
            }

            if(!strcmp(str + version_offset, "HTTP/3"))
            {
                req->version_major = 3;
                req->version_minor = 0;
                break;
            }

            bad_version = 1;
            break;

            default:
            bad_version = 1;
            break;
        }

        if(bad_version)
        {
            free(headers.list);
            return FAILURE("Bad HTTP version");
        }
    }

    return OK;

    #undef OK
    #undef FAILURE
    #undef INTERNAL_FAILURE
}

static bool upload(conn_t *conn)
{
    if(conn->failed_to_append)
        return 0;

    
    if(conn->out.used > 0)
    {
        /* Flush the output buffer. */
        uint32_t sent, total;

        sent = 0;
        total = conn->out.used;

        if(total == 0)
            return 1;

        while(sent < total)
        {
            int n = microtcp_send(conn->sock, conn->out.data + sent, total - sent);
            if(n <= 0)
            {
                microtcp_errcode_t errcode = microtcp_get_socket_error(conn->sock);
                microtcp_clear_socket_error(conn->sock);

                if (errcode == MICROTCP_ERRCODE_WOULDBLOCK)
                    break;

                // ERROR!
#ifdef DEBUG
                fprintf(stderr, "XHTTP :: microtcp_send failed (%s)\n", microtcp_strerror(errcode));
#endif
                return 0;
            }

            sent += n;
        }

        memmove(conn->out.data, conn->out.data + sent, total - sent);
        conn->out.used -= sent;
    }
    return 1;
}

static uint32_t find(const char *str, uint32_t len, const char *seq)
{
    if(seq == NULL || seq[0] == '\0')
        return UINT32_MAX;

    if(str == NULL || len == 0)
        return UINT32_MAX;

    uint32_t i = 0, seqlen = strlen(seq);
    while(1)
    {
        while(i < len && str[i] != seq[0])
            i += 1;

        if(i == len)
            return UINT32_MAX;

        assert(str[i] == seq[0]);

        if(i > len - seqlen)
            return UINT32_MAX;

        if(!strncmp(seq, str + i, seqlen))
            return i;

        i += 1;
    }
}

static void append_string_to_output_buffer(conn_t *conn, xh_string data)
{
    if(conn->failed_to_append)
        return;

    if(conn->out.size - conn->out.used < (uint32_t) data.len)
    {
        uint32_t new_size = 2 * conn->out.size;

        if(new_size < conn->out.used + (uint32_t) data.len)
            new_size = conn->out.used + data.len;

        void *temp = realloc(conn->out.data, new_size);

        if(temp == NULL)
        {
            conn->failed_to_append = 1;
            return;
        }

        conn->out.data = temp;
        conn->out.size = new_size;
    }

    memcpy(conn->out.data + conn->out.used, data.str, data.len);
    conn->out.used += data.len;
    return;
}

static bool client_wants_to_keep_alive(xh_request *req)
{
    bool keep_alive;

    const char *h_connection = xh_header_get(req, "Connection");

    if(h_connection == NULL)
        // No [Connection] header. No keep-alive.
        keep_alive = 0;
    else
    {
        // TODO: Make string comparisons case and whitespace insensitive.
        if(!strcmp(h_connection, " Keep-Alive"))
            keep_alive = 1;
        else if(!strcmp(h_connection, " Close"))
            keep_alive = 0;
        else
            keep_alive = 0;
    }

    return keep_alive;
}

static bool server_wants_to_keep_alive(context_t *ctx, conn_t *conn)
{
    bool keep_alive;

    if(conn->served >= 20)
        keep_alive = 0;

    if(ctx->connum > 0.6 * MICROHTTP_MAX_CLIENTS)
        keep_alive = 0;

    return keep_alive;
}

static void append_response_status_line_to_output_buffer(conn_t *conn, int status)
{
    char buffer[256];

    const char *status_text = statis_code_to_status_text(status);
    assert(status_text != NULL);

    int n = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d %s\r\n", 
                     status, status_text);
    assert(n >= 0);

    if((unsigned int) n > sizeof(buffer)-1)
        n = sizeof(buffer)-1;

    append_string_to_output_buffer(conn, xh_string_new(buffer, n));
}

static void append_response_head_to_output_buffer(xh_response *res, conn_t *conn)
{
    append_response_status_line_to_output_buffer(conn, res->status);
    for(int i = 0; i < res->headers.count; i += 1)
    {
        xh_pair header = res->headers.list[i];
        append_string_to_output_buffer(conn, header.key);
        append_string_to_output_buffer(conn, xh_string_from_literal(": "));
        append_string_to_output_buffer(conn, header.val);
        append_string_to_output_buffer(conn, xh_string_from_literal("\r\n"));
    }
    append_string_to_output_buffer(conn, xh_string_from_literal("\r\n"));
}

static void generate_response_by_calling_the_callback(context_t *ctx, conn_t *conn)
{
    xh_request *req = &conn->request.public;

    // If it's a HEAD request, tell the callback that
    // it's a GET request but then throw awaiy the body.
    bool head_only = 0;
    if(req->method_id == XH_HEAD)
    {
        head_only = 1;
        req->method_id = XH_GET;
        req->method = xh_string_from_literal("GET");
    }

    xh_response2 res2;
    xh_response *res = &res2.public;
    {
        res_init(&res2);

        ctx->callback(req, res, ctx->userp);

        req_deinit(req);

        if(res2.failed)
        {
            /* Callback failed to build the response. 
             * Overwrite with a new error response.
             */
            res_reinit(&res2);
            res->status = 500;
        }
    }

    if(res->body.str == NULL)
        res->body.str = "";

    if(res->body.len < 0)
        res->body.len = strlen(res->body.str);
        
    int content_length = res->body.len;

    assert(content_length >= 0);

    bool callback_wants_to_keep_alive = !res->close;
    bool keep_alive = client_wants_to_keep_alive(req) 
                   && server_wants_to_keep_alive(ctx, conn)
                   && callback_wants_to_keep_alive;

    xh_header_add(res, "Content-Length", "%d", content_length);
    xh_header_add(res, "Connection", keep_alive ? "Keep-Alive" : "Close");
    append_response_head_to_output_buffer(res, conn);

    /* Now write the body to the output or, if the *
     * request was originally HEAD, throw the body *
     * away.                                       */

    if(!head_only)
        append_string_to_output_buffer(conn, res->body);

    conn->served += 1;

    if(!keep_alive)
        conn->close_when_uploaded = 1;

    res_deinit(&res2);
}

static uint32_t determine_content_length(xh_request *req)
{
    int i;
    for(i = 0; i < req->headers.count; i += 1)
        if(!strcmp(req->headers.list[i].key.str, 
                   "Content-Length")) // TODO: Make it case-insensitive.
            break;

    if(i == req->headers.count)
        // No Content-Length header.
        // Assume a length of 0.
        return 0;

    const char *s = req->headers.list[i].val.str;
    unsigned int k = 0;

    while(is_space(s[k]))
        k += 1;

    if(s[k] == '\0')
        // Header Content-Length is empty.
        // Assume a length of 0.
        return 0;

    if(!is_digit(s[k]))
        // The first non-space character
        // isn't a digit. That's bad.
        return UINT32_MAX;

    uint32_t result = s[k] - '0';

    k += 1;

    while(is_digit(s[k]))
    {
        result = result * 10 + s[k] - '0';
        k += 1;
    }

    while(is_space(s[k]))
        k += 1;

    if(s[k] != '\0')
        // The header contains something other
        // than whitespace and digits. Bad.
        return UINT32_MAX;

    return result;
}

static void when_data_is_ready_to_be_read(context_t *ctx, conn_t *conn)
{
    // Download the data in the input buffer.
    uint32_t downloaded;
    {
        buffer_t *b = &conn->in;
        uint32_t before = b->used;
        while(1)
        {
            if(b->size - b->used < 128)
            {
                uint32_t new_size = (b->size == 0) ? 512 : (2 * b->size);

                // NOTE: We allocate one extra byte because this
                //       way we're sure that any sub-string of the
                //       buffer can be safely made zero-terminated
                //       by writing a zero after it temporarily.
                void *temp = realloc(b->data, new_size + 1);

                if(temp == NULL)
                {
                    // ERROR!
                    close_connection(ctx, conn);
                    return;
                }

                // TODO: Change the pointers in conn->request
                //       if the head was already parsed.

                b->data = temp;
                b->size = new_size;
            }

            assert(b->size > b->used);

            int n = microtcp_recv(conn->sock, b->data + b->used, b->size - b->used);
            if (n == 0) {
                // Peer disconnected.
                close_connection(ctx, conn);
                return;
            }

            if(n < 0)
            {
                microtcp_errcode_t errcode = microtcp_get_socket_error(conn->sock);
                microtcp_clear_socket_error(conn->sock);

                if(errcode == MICROTCP_ERRCODE_WOULDBLOCK)
                    break; // Done downloading.
#ifdef DEBUG
                fprintf(stderr, "XHTTP :: %s\n", microtcp_strerror(errcode));
#endif
                // An error occurred.
                close_connection(ctx, conn);
                return;
            }

            b->used += n;
        }
        downloaded = b->used - before;
    }

#ifdef DEBUG
    fprintf(stderr, "XHTTP :: Downloaded %d bytes\n", downloaded);
#endif
    
    int served_during_this_while_loop = 0;

    while(1)
    {
        if(!conn->head_received)
        {
            // Search for an \r\n\r\n.
            uint32_t i;
            {
                uint32_t start = 0;
                if(served_during_this_while_loop == 0 && conn->in.used > downloaded + 3)
                    start = conn->in.used - downloaded - 3;

                i = find(conn->in.data + start, conn->in.used - start, "\r\n\r\n");

                if(i == UINT32_MAX)
                    // No \r\n\r\n found. The head of the request wasn't fully received yet.
                    return;

                // i is relative to start.
                i += start;
            }

            struct parse_err_t err = parse(conn->in.data, i+4, &conn->request.public);

            uint32_t len = 0; // Anything other than UINT32_MAX goes.
            if(err.msg == NULL)
                len = determine_content_length(&conn->request.public); // Returns UINT32_MAX on failure.

            if(err.msg != NULL || len == UINT32_MAX)
            {
                char buffer[512];
                if(len == UINT32_MAX)
                {
                    static const char msg[] = "Couldn't determine the content length";
                    (void) snprintf(buffer, sizeof(buffer),
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: text/plain;charset=utf-8\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: Close\r\n"
                        "\r\n%s", (int) sizeof(msg)-1, msg);
                }
                else if(err.internal)
                {
                    (void) snprintf(buffer, sizeof(buffer),
                        "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Type: text/plain;charset=utf-8\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: Close\r\n"
                        "\r\n%s", err.len, err.msg);
                }
                else
                {
                    // 400 Bad Request.
                    (void) snprintf(buffer, sizeof(buffer),
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: text/plain;charset=utf-8\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: Close\r\n"
                        "\r\n%s", err.len, err.msg);
                }

                // NOTE: If the static buffer [buffer] is too small
                //       to hold the response then the response will
                //       be sent truncated. But that's not a problem
                //       since we'll close the connection after this
                //       response either way.

                append_string_to_output_buffer(conn, xh_string_new(buffer, -1));
                conn->close_when_uploaded = 1;
                return;
            }

            conn->head_received = 1;
            conn->body_offset = i + 4;
            conn->body_length = len;
        }

        if(conn->head_received && conn->body_offset + conn->body_length <= conn->in.used)
        {
            /* The rest of the body arrived. */

            // Make the body temporarily zero-terminated: get the byte
            // that comes after the body, then overwrite it with a '\0'.
            // When you don't need it to be zero-terminated anymore,
            // put the saved byte back in.

            char first_byte_after_body_in_input_buffer 
                = conn->in.data[conn->body_offset + conn->body_length];

            conn->in.data[conn->body_offset + conn->body_length] = '\0';

            xh_request *req = &conn->request.public;
            req->body = xh_string_new(conn->in.data + conn->body_offset, conn->body_length);

            generate_response_by_calling_the_callback(ctx, conn);

            // Restore the byte after the body.
            conn->in.data[conn->body_offset + conn->body_length] 
                = first_byte_after_body_in_input_buffer;

            // Remove the request from the input buffer by
            // copying back its remaining contents.
            uint32_t consumed = conn->body_offset + conn->body_length;
            memmove(conn->in.data, conn->in.data + consumed, conn->in.used - consumed);
            conn->in.used -= consumed;
            conn->head_received = 0;

            served_during_this_while_loop += 1;

            if(conn->close_when_uploaded)
                break;
        }
    }
}

void xh_quit(xh_handle handle)
{
    context_t *ctx = handle;
    ctx->exiting = 1;
}

static const char *init(context_t *context, unsigned short port)
{
    microtcp_t *mtcp = microtcp_create("10.0.0.5", "10.0.0.4", NULL, NULL);
    if (!mtcp)
        return "Failed to initialize TCP";
    context->mtcp = mtcp;

    context->sock = microtcp_open(mtcp, port);
    if (!context->sock)
        return microtcp_strerror(microtcp_get_error(mtcp));
    microtcp_set_blocking(context->sock, false);

    context->mux = microtcp_mux_create(mtcp);
    if (!context->mux) 
    {
        microtcp_close(context->sock);
        return "Couldn't craete mux";
    }

    if (!microtcp_mux_register(context->mux, context->sock, MICROTCP_MUX_ACCEPT, NULL)) 
    {
        microtcp_close(context->sock);
        microtcp_mux_destroy(context->mux);
        return "Failed to register the listener into the io multiplexer";
    }

    for(unsigned int i = 0; i < MICROHTTP_MAX_CLIENTS; i += 1) {
        context->pool[i].sock = NULL;
        context->pool[i].next = context->pool + i + 1;
    }

    context->pool[MICROHTTP_MAX_CLIENTS-1].next = NULL;
    context->freelist = context->pool;

    context->connum = 0;
    context->exiting = 0;
    return NULL;
}

const char *xhttp(unsigned short port, xh_callback callback, xh_handle *handle)
{
    context_t context;

    const char *error = init(&context, port);

    if(error != NULL)
        return error;

    context.callback = callback;
    context.userp = NULL;

    if(handle)
        *handle = &context;

    while(!context.exiting)
    {
        microtcp_muxevent_t ev;
        if (!microtcp_mux_wait(context.mux, &ev))
            continue;

#ifdef DEBUG
        const char *event_bitset_string;
        switch (ev.events) {
            case 0: event_bitset_string = ""; break;
            case MICROTCP_MUX_RECV: event_bitset_string = "RECV"; break;
            case MICROTCP_MUX_SEND: event_bitset_string = "SEND"; break;
            case MICROTCP_MUX_ACCEPT: event_bitset_string = "ACCEPT"; break;
            case MICROTCP_MUX_RECV | MICROTCP_MUX_SEND: event_bitset_string = "RECV|SEND"; break;
            case MICROTCP_MUX_RECV | MICROTCP_MUX_ACCEPT: event_bitset_string = "RECV|ACCEPT"; break;
            case MICROTCP_MUX_SEND | MICROTCP_MUX_ACCEPT: event_bitset_string = "SEND|ACCEPT"; break;
            case MICROTCP_MUX_RECV | MICROTCP_MUX_SEND | MICROTCP_MUX_ACCEPT: event_bitset_string = "RECV|SEND|ACCEPT"; break;
            default: event_bitset_string = "???";
        }
        fprintf(stderr, "XHTTP :: Event %s\n", event_bitset_string);
#endif

        if(ev.userp == NULL)
        {
#ifdef DEBUG
            fprintf(stderr, "XHTTP :: New connection\n");
#endif
            // New connection.
            conn_t *newly_accepted = accept_connection(&context);
            if (!newly_accepted)
                continue; // For some reason, although a MICROTCP_MUX_ACCEPT
                          // was received by the MUX, accepting failed.
                          // Wait for the next event.

            // A connection was accepted. Since it may already
            // contain data to be read or space to write we continue
            // by building a fake event ourselves
            ev.userp = newly_accepted;
            ev.events = MICROTCP_MUX_RECV | MICROTCP_MUX_SEND;
            ev.socket = newly_accepted->sock;
        }

        conn_t *conn = ev.userp;
/*
        if(ev.events & EPOLLRDHUP)
        {
            // Disconnection.
            close_connection(&context, conn);
            continue;
        }

        if(ev.events & (EPOLLERR | EPOLLHUP))
        {
            // Connection closed or an error occurred.
            // We continue as nothing happened so that
            // the error is reported on the [recv] or
            // [send] call site.
            ev.events = EPOLLIN | EPOLLOUT;
        }
*/
        int old_connum = context.connum;

        if((ev.events & MICROTCP_MUX_RECV) 
            && conn->close_when_uploaded == 0)
        {
            // Note that this may close the connection. If any logic
            // were to come after this function, it couldn't refer
            // to the connection structure.
            when_data_is_ready_to_be_read(&context, conn);
        }

        if(old_connum == context.connum)
        {
            // The connection wasn't closed. Try to
            // upload the data in the output buffer.

            if(!upload(conn))

                close_connection(&context, conn);

            else
                if(conn->out.used == 0 && conn->close_when_uploaded)
                    close_connection(&context, conn);
        }
    }

    for(unsigned int i = 0; i < MICROHTTP_MAX_CLIENTS; i += 1)
        if(context.pool[i].sock != NULL)
            close_connection(&context, context.pool + i);

    (void) microtcp_close(context.sock);
    (void) microtcp_mux_destroy(context.mux);
    microtcp_destroy(context.mtcp);
    return NULL;
}

int xh_urlcmp(const char *URL, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    int res = xh_vurlcmp(URL, fmt, va);
    va_end(va);
    return res;
}

/* Returns:
 *   0 - Match
 *   1 - No match
 *  -1 - Error
 */
int xh_vurlcmp(const char *URL, const char *fmt, va_list va)
{
#define MATCH   0
#define ERROR  -1
#define NOMATCH 1

    long i = 0; // Cursor over [fmt]
    long j = 0; // Cursor over [URL]
    while(1) {

        while(fmt[i] != '\0' && fmt[i] != ':') {

            if(URL[j] != fmt[i])
                return NOMATCH;
            
            i += 1;
            j += 1;
        }

        if(fmt[i] == '\0' || URL[j] == '\0')
            break;

        assert(URL[j] != '\0');
        assert(fmt[i] == ':');

        i += 1; // Skip ':'

        if(fmt[i] == 'd') {

            if(!isdigit(URL[j]))
                return NOMATCH;

            long long buff = 0;

            do {

                long d = (URL[j] - '0');

                if(buff > (LLONG_MAX - d) / 10)
                    return ERROR; /* Overflow */

                buff = buff * 10 + d;
                
                j += 1;

            } while(isdigit(URL[j]));

            long long *dst = va_arg(va, long long*);
            if(dst != NULL)
                *dst = buff;

        } else if(fmt[i] == 's') {

            long off = j;
            while(URL[j] != '\0' && URL[j] != '/' && URL[j] != fmt[i+1])
                j += 1;
            long len = j - off;

            long  dst_len = va_arg(va, long);
            char *dst_ptr = va_arg(va, char*);

            if(dst_ptr != NULL && dst_len > 0) {
                long copy;
                if(dst_len >= len+1)
                    copy = len;
                else
                    copy = dst_len-1;
                memcpy(dst_ptr, URL + off, copy);
                dst_ptr[copy] = '\0';
            }
        
        } else
            /* Format ended unexpectedly or 
               got an invalid format specifier. */
            return ERROR;

        i += 1; // Skip the 'd' or 's'
    }

    /* If the program gets here it means that either
     * [fmt] or [URL] ended. If that's the case, if
     * the other didn't end, then there's no match.
     */ 
    if(fmt[i] != '\0' || URL[j] != '\0')
        return NOMATCH;

    return MATCH;

#undef MATCH
#undef ERROR
#undef NOMATCH
}