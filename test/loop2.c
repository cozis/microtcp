#include <stdio.h>
#include <microtcp.h>

int main(void)
{
    microtcp_errcode_t errcode;

    microtcp_t *mtcp = microtcp_create("10.0.0.5", "10.0.0.4", NULL, NULL);
    if (mtcp == NULL) {
        fprintf(stderr, "Error: Failed to instanciate microtcp stack\n");
        return -1;
    }
    
    uint16_t port = 80;
    microtcp_socket_t *server = microtcp_open(mtcp, port, &errcode);
    if (errcode) {
        fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
        microtcp_destroy(mtcp);
        return -1;
    }
    assert(server);
    
    fprintf(stderr, "Listening on port %d\n", port);

    while (1) {
        fprintf(stderr, "About to accept\n");
        microtcp_socket_t *client = microtcp_accept(server, false, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            break;
        }

        fprintf(stderr, "Accepted a connection\n");

        char buffer[1024];
        size_t num = microtcp_recv(client, buffer, sizeof(buffer), false, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
        fprintf(stderr, "(%d bytes received)\n", (int) num);

        size_t sent1 = microtcp_send(client, "echo: ", 6, false, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
        fprintf(stderr, "(%d bytes sent 1)\n", (int) sent1);

        size_t sent2 = microtcp_send(client, buffer, num, false, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
        fprintf(stderr, "(%d bytes sent 2)\n", (int) sent2);

handled:
        microtcp_close(client);
    }
    
    microtcp_close(server);
    microtcp_destroy(mtcp);
    return 0;
}
