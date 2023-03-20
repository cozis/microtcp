#include "mutcp.h"

int main(void)
{
    mutcp_t state;
    mutcp_create(&state);

    mutcp_listener_socket_t *listener = 
        mutcp_listener_socket_create(&state, 8080);

    while (1) {
        mutcp_socket_t *socket =
            mutcp_listener_socket_accept(listener);

        char buffer[1024];
        size_t num = mutcp_socket_read(socket, buffer, sizeof(buffer));
        mutcp_socket_write(socket, "echo: ", 6);
        mutcp_socket_write(socket, buffer, num);

        mutcp_socket_destroy(socket);
    }

    mutcp_listener_socket_destroy(listener);
    mutcp_destroy(&state);
    return 0;
}
