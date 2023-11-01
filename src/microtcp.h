#ifndef MICROTCP_H
#define MICROTCP_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>

typedef struct microtcp_t        microtcp_t;
typedef struct microtcp_socket_t microtcp_socket_t;

#define MICROTCP_MAX_BUFFERS 8
#define MICROTCP_MAX_SOCKETS 32
#define MICROTCP_MAX_MUX_ENTRIES 32

typedef enum {

    MICROTCP_ERRCODE_NONE = 0,

    MICROTCP_ERRCODE_NOCLEAR,

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

    // Returned by microtcp_accept, microtcp_recv and microtcp_send
    MICROTCP_ERRCODE_WOULDBLOCK,

    // Returned by microtcp_recv, microtcp_send
    MICROTCP_ERRCODE_PEERCLOSED,

} microtcp_errcode_t;

typedef struct {
    void *data;
    void (*free)(void *data);
    int  (*send)(void *data, const void *src, size_t len);
    int  (*recv)(void *data, void *dst, size_t len);
} microtcp_callbacks_t;

bool               microtcp_callbacks_create_for_tap(const char *ip, const char *mac, microtcp_callbacks_t *callbacks);
microtcp_t        *microtcp_create(const char *tap_ip, const char *stack_ip, const char *tap_mac, const char *stack_mac);
microtcp_t        *microtcp_create_using_callbacks(const char *ip, const char *mac, microtcp_callbacks_t callbacks);
void               microtcp_destroy(microtcp_t *mtcp);
microtcp_errcode_t microtcp_get_error(microtcp_t *mtcp);
void               microtcp_clear_error(microtcp_t *mtcp);

microtcp_errcode_t microtcp_get_socket_error(microtcp_socket_t *sock);
void               microtcp_clear_socket_error(microtcp_socket_t *sock);

const char        *microtcp_strerror(microtcp_errcode_t errcode);
microtcp_socket_t *microtcp_open(microtcp_t *mtcp, uint16_t port);
microtcp_socket_t *microtcp_accept(microtcp_socket_t *socket);
void               microtcp_close(microtcp_socket_t *socket);

int                microtcp_send(microtcp_socket_t *socket, const void *src, size_t len);
int                microtcp_recv(microtcp_socket_t *socket, void *dst, size_t len);

bool               microtcp_step(microtcp_t *mtcp);
void               microtcp_set_blocking(microtcp_socket_t *socket, bool block);
bool               microtcp_process_packet(microtcp_t *mtcp, const void *packet, size_t len);

typedef enum {
    MICROTCP_MUX_ACCEPT = 1 << 0,
    MICROTCP_MUX_RECV   = 1 << 1,
    MICROTCP_MUX_SEND   = 1 << 2,
} microtcp_muxeventid_t;

typedef struct {
    void *userp;
    int events;
    microtcp_socket_t *socket;
} microtcp_muxevent_t;

typedef struct microtcp_mux_t microtcp_mux_t;
microtcp_mux_t *microtcp_mux_create(microtcp_t *mtcp);
void            microtcp_mux_destroy(microtcp_mux_t *mux);
bool            microtcp_mux_register(microtcp_mux_t *mux, microtcp_socket_t *sock, int events, void *userp);
bool            microtcp_mux_unregister(microtcp_mux_t *mux, microtcp_socket_t *sock, int events);
bool            microtcp_mux_wait(microtcp_mux_t *mux, microtcp_muxevent_t *ev);

#endif