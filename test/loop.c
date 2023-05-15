/*
#include <stdio.h>
#include <microtcp.h>

int main(void)
{
    microtcp_errcode_t errcode;

    microtcp_t *mtcp = microtcp_create();
    if (mtcp == NULL)
        return -1;
    
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
        if (errcode && errcode != MICROTCP_ERRCODE_NOTHINGTOACCEPT) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            break;
        }

        fprintf(stderr, "Accepted a connection\n");

        char buffer[1024];
        size_t num = microtcp_recv(client, buffer, sizeof(buffer), &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
        microtcp_send(client, "echo: ", 6, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
        microtcp_send(client, buffer, num, &errcode);
        if (errcode) {
            fprintf(stderr, "Error: %s\n", microtcp_strerror(errcode));
            goto handled;
        }
handled:
        microtcp_close(client);
    }
    
    microtcp_close(server);
    microtcp_destroy(mtcp);
    return 0;
}
*/