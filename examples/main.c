#include "net.h"

static size_t send_callback()
{
}

int tun_fd;

static size_t recv_callback(void *context, void *dst, size_t len)
{
    return read(tun_fd, dst, len);
}

int main(void)
{
    net_t net;
    net_init(&net, ip, mac, NULL, send_callback, recv_callback);
    net_spawn_thread(&net);

    uint16_t port = 8080;

    net_listener_t *listener = net_listener_create(&net, port);
    if (listener == NULL) {
        fprintf(stderr, "Failed to start listening\n");
        net_free(&net);
        return -1;
    }

    while (1) {

        net_socket_t *client = net_listener_accept(listener);

        if (client == NULL) 
            continue;

        char   message[1024];
        size_t messlen;

        messlen = net_socket_recv(client, message, sizeof(message));
        net_socket_send(client, "echo: ", sizeof("echo: "));
        net_socket_send(client, message, messlen);

        net_socket_destroy(client);
    }
    
    net_listener_destroy(listener);
    net_free(&net);
    return 0;
}