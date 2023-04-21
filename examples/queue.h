
enum {
    MICROTCP_EVENT_NONE   = 0,
    MICROTCP_EVENT_SEND   = 1,
    MICROTCP_EVENT_RECV   = 2,
    MICROTCP_EVENT_ACCEPT = 4,

    MICROTCP_EVENT_ALL = MICROTCP_EVENT_RECV 
                       | MICROTCP_EVENT_SEND 
                       | MICROTCP_EVENT_ACCEPT,
};

typedef struct microtcp_queue_t microtcp_queue_t;

typedef struct {
    int   type;
    void *data;
    microtcp_socket_t *socket;
} microtcp_event_t;

microtcp_queue_t *microtcp_queue_create(microtcp_t *mtcp);
void              microtcp_queue_destroy(microtcp_queue_t *queue);
microtcp_event_t  microtcp_queue_next(microtcp_queue_t *queue, bool no_block);
bool              microtcp_queue_register(microtcp_queue_t *queue, microtcp_socket_t *socket, void *data, int events);
bool              microtcp_queue_unregister(microtcp_queue_t *queue, microtcp_socket_t *socket, int unregister_events);
