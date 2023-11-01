#include <stdio.h>
#include <microtcp.h>

int main(void)
{
    microtcp_t *mtcp = microtcp_create("10.0.0.5", "10.0.0.4", NULL, NULL);
    if (mtcp == NULL) {
        fprintf(stderr, "Error: Couldn't create MicroTCP instance\n");
        return -1;
    }

    uint16_t port = 8081;
    microtcp_socket_t *server = microtcp_open(mtcp, port);
    if (server == NULL) {
        fprintf(stderr, "Error: %s\n", microtcp_strerror(microtcp_get_error(mtcp)));
        microtcp_destroy(mtcp);
        return -1;
    }

    while (1) {
    
        microtcp_socket_t *client = microtcp_accept(server);
        if (client == NULL) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(microtcp_get_socket_error(server)));
            break;
        }
        
        char buffer[1024];
        int num = microtcp_recv(client, buffer, sizeof(buffer));
        if (num > 0) {
            microtcp_send(client, "echo: ", 6);
            microtcp_send(client, buffer, num);
        }
        microtcp_close(client);
    }
    
    microtcp_close(server);
    microtcp_destroy(mtcp);
    return 0;
}
