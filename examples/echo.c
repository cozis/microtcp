#include <stdio.h>
#include <microtcp.h>

int main(void)
{
    microtcp_errcode_t err;
    microtcp_t *mtcp = microtcp_create("10.0.0.5", "10.0.0.4", NULL, NULL);
    if (mtcp == NULL) {
        fprintf(stderr, "Error: Couldn't create MicroTCP instance\n");
        return -1;
    }

    uint16_t port = 8081;
    microtcp_socket_t *server = microtcp_open(mtcp, port, &err);
    if (server == NULL) {
        fprintf(stderr, "Error: %s\n", microtcp_strerror(err));
        microtcp_destroy(mtcp);
        return -1;
    }

    while (1) {
        microtcp_socket_t *client = microtcp_accept(server, false, &err);
        if (client == NULL) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(err));
            break;
        }

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
