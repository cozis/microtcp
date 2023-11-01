#ifndef XHTTP_H
#define XHTTP_H

#define MICROHTTP_MAX_CLIENTS 64

typedef struct {
    void *userp;
    const char *ip;
    const char *mac;
    int (*send_frame)(void *userp, const void *src, size_t len);
    int (*recv_frame)(void *userp,       void *dst, size_t len);
} microhttp_config_t;

typedef void *xh_handle;

typedef struct {
    char *str; int len;
} xh_string;

typedef struct {
    xh_string key, val;
} xh_pair;

typedef struct {
    xh_pair *list;
    int     count;
} xh_table;

typedef enum {
    XH_GET     =   1, 
    XH_HEAD    =   2,
    XH_POST    =   4,
    XH_PUT     =   8,
    XH_DELETE  =  16,
    XH_CONNECT =  32,
    XH_OPTIONS =  64,
    XH_TRACE   = 128,
    XH_PATCH   = 256,
} xh_method;

typedef struct {
    xh_method method_id;
    xh_string method;
    xh_string params;
    xh_string URL;
    unsigned int version_minor;
    unsigned int version_major;
    xh_table headers;
    xh_string body;
} xh_request;

typedef struct {
    int status;
    xh_table headers;
    xh_string   body;
    _Bool close;
} xh_response;

typedef void (*xh_callback)(xh_request*, xh_response*, void*);

const char *xhttp(unsigned short port, xh_callback callback, xh_handle *handle);
void        xh_quit(xh_handle handle);

void        xh_header_add(xh_response *res, const char *name, const char *valfmt, ...);
void        xh_header_rem(xh_response *res, const char *name);
const char *xh_header_get(void *req_or_res, const char *name);
_Bool       xh_header_cmp(const char *a, const char *b);

int  xh_urlcmp(const char *URL, const char *fmt, ...);
int xh_vurlcmp(const char *URL, const char *fmt, va_list va);

#define xh_string_new(s, l) \
    ((xh_string) { (s), ((int) (l)) < 0 ? (int) strlen(s) : (int) (l) })

#define xh_string_from_literal(s) \
    ((xh_string) { (s), sizeof(s)-1 })

#endif // #ifndef XHTTP_H