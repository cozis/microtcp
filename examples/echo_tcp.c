#include <stdio.h>
#include <microtcp.h>

int main(void)
{
    microtcp_t *mtcp = microtcp_create("10.0.0.5", "10.0.0.4", NULL, NULL);
    
    uint16_t port = 8081;
    microtcp_socket_t *server = microtcp_open(mtcp, port, NULL);

    while (1) {
        microtcp_socket_t *client = microtcp_accept(server, false, NULL);
        char buffer[1024];
        size_t num = microtcp_recv(client, buffer, sizeof(buffer), false, NULL);
        microtcp_send(client, "echo: ", 6, false, NULL);
        microtcp_send(client, buffer, num, false, NULL);
        microtcp_close(client);
    }
    
    microtcp_close(server);
    microtcp_destroy(mtcp);
    return 0;
}
