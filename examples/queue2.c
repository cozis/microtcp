
typedef struct {
    size_t   size;
    size_t   used;
    uint8_t *data;
} buffer_t;

typedef struct client_t client_t;
struct client_t {
    client_t *prev;
    client_t *next;
    microtcp_socket_t *socket;
    buffer_t  input;
    buffer_t output;
};

int main(void)
{
    microtcp_t *mtcp = microtcp_create();

    microtcp_socket_t *server = microtcp_open(mtcp, 80);

    microtcp_queue_t *queue = microtcp_queue_create(mtcp);
    microtcp_queue_register(queue, server, NULL, MICROTCP_EVENT_ACCEPT);
    while (1) {
        microtcp_event_t event = microtcp_queue_next(queue, no_block);
        switch (event.type) {
            
            case MICROTCP_EVENT_NONE:
            break;
            
            case MICROTCP_EVENT_READ:
            break;

            case MICROTCP_EVENT_RECV:
            {
                microtcp_socket_t *client_socket = event.socket;
                microtcp_recv(client_socket, );
            }
            break;
            
            case MICROTCP_EVENT_ACCEPT:
            {
                microtcp_socket_t *client_socket = microtcp_accept(event.socket, true);
                microtcp_queue_register(queue, client_socket, NULL, MICROTCP_EVENT_SEND | MICROTCP_EVENT_RECV);
            }
            break;
        }
    }
    microtcp_queue_destroy(queue);

    microtcp_destroy(mtcp);
    return 0;
}