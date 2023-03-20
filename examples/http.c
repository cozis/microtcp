#include <microtcp.h>

typedef struct microhttp_server_t http_server_t;
http_server_t *microhttp_server_create(microtcp_t *mtcp, uint16_t port);
void           microhttp_server_destroy(http_server_t *server);
void           microhttp_server_serve(microhttp_server_t *server, void *data, void (*callback)(void*, microhttp_request_t*));

struct microhttp_server_t {
    microtcp_t *tcp;
    microtcp_listener_t *listener;
};

microhttp_server_t *microhttp_server_create(microtcp_t *mtcp, uint16_t port)
{
    microhttp_server_t *server = malloc(sizeof(microhttp_server_t));
    if (!server)
        return NULL;

    microtcp_listener_t *listener = microtcp_listener_create(mtcp, port);
    if (!listener) {
        free(server);
        return NULL;
    }

    server->mtcp = mtcp;
    server->listener = listener;
    return server;
}

void microhttp_server_serve(microhttp_server_t *server, void *data, void (*callback)(void*, microhttp_request_t*))
{
    char buffer[65536];

    while (1) {
        
        microtcp_socket_t *socket = microtcp_listener_accept(server->listener);
        if (!socket)
            continue;
        
        int num = microtcp_socket_recv(socket, buffer, sizeof(buffer));
        if (num >= 0) {
            hp_error_t error;
            hp_request_t request;
            if (!hp_parse(buffer, num, &request, &error)) {
                ..
            } else {
                ..
            }
        }
        
        microtcp_socket_destroy(socket);
    }
}

void microhttp_server_destroy(microhttp_server_t *server)
{
    microtcp_listener_destroy(server->listener);
    free(server);
}
