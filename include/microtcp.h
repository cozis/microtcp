
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

typedef struct microtcp_t        microtcp_t;
typedef struct microtcp_socket_t microtcp_socket_t;

#define MICROTCP_MAX_BUFFERS 8
#define MICROTCP_MAX_SOCKETS 32

typedef enum {

    MICROTCP_ERRCODE_NONE = 0,

    // Returned by microtcp_open and microtcp_accept
    MICROTCP_ERRCODE_SOCKETLIMIT,

    // Returned by microtcp_open
    MICROTCP_ERRCODE_TCPERROR,
    MICROTCP_ERRCODE_BADCONDVAR,

    // Returned by microtcp_accept
    MICROTCP_ERRCODE_NOTLISTENER,
    MICROTCP_ERRCODE_CANTBLOCK,

    // Returned by microtcp_recv and microtcp_send
    MICROTCP_ERRCODE_NOTCONNECTION,

} microtcp_errcode_t;

typedef struct {
    void *data;
    void (*free)(void *data);
    int  (*send)(void *data, const void *src, size_t len);
    int  (*recv)(void *data, void *dst, size_t len);
} microtcp_callbacks_t;

#ifdef MICROTCP_USING_TAP
bool               microtcp_callbacks_create_for_tap(const char *ip, const char *mac, microtcp_callbacks_t *callbacks);
microtcp_t        *microtcp_create(const char *tap_ip, const char *stack_ip, const char *tap_mac, const char *stack_mac);
#endif

microtcp_t        *microtcp_create_using_callbacks(const char *ip, const char *mac, microtcp_callbacks_t callbacks);
void               microtcp_destroy(microtcp_t *mtcp);
const char        *microtcp_strerror(microtcp_errcode_t errcode);
microtcp_socket_t *microtcp_open(microtcp_t *mtcp, uint16_t port, microtcp_errcode_t *errcode);
microtcp_socket_t *microtcp_accept(microtcp_socket_t *socket, bool no_block, microtcp_errcode_t *errcode);
void               microtcp_close(microtcp_socket_t *socket);
size_t             microtcp_send(microtcp_socket_t *socket, const void *src, size_t len, bool no_block, microtcp_errcode_t *errcode);
size_t             microtcp_recv(microtcp_socket_t *socket,       void *dst, size_t len, bool no_block, microtcp_errcode_t *errcode);
void               microtcp_step(microtcp_t *mtcp);
void               microtcp_process_packet(microtcp_t *mtcp, const void *packet, size_t len);