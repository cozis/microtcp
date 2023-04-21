#include "queue.h"

typedef struct queue_entry_t queue_entry_t;
typedef struct queue_event_t queue_event_t;

struct queue_entry_t {
    queue_entry_t *prev;
    queue_entry_t *next;
    void *data;
    int   events;
    microtcp_queue_t  *queue;
    microtcp_socket_t *socket;
    queue_event_t *event_entry;
};

struct queue_event_t {

    queue_event_t *prev;
    queue_event_t *next;

    int events;
    queue_entry_t *socket_entry;
};

struct microtcp_queue_t {
    
    microtcp_t *mtcp;

    pthread_cond_t something_happened;

    queue_event_t *queue_head;
    queue_event_t *queue_tail;

    queue_entry_t *entry_free_list;
    queue_entry_t  entry_pool[MICROTCP_QUEUE_ENTRIES_MAX];

    queue_event_t *event_free_list;
    queue_event_t  event_pool[MICROTCP_QUEUE_ENTRIES_MAX];
};

static event_entry_t*
pop_event_entry_from_queue(microtcp_queue_t *queue)
{
    event_entry_t *event;

    if (queue->queue_tail) {
        
        // An event is present in the queue. Pop it.

        event = queue->queue_tail;

        if (event->prev)
            event->prev->next = NULL;
        else
            queue->queue_head = NULL;
        queue->queue_tail = event->prev;

    } else
        event = NULL;

    return event;
}

microtcp_event_t microtcp_queue_next(microtcp_queue_t *queue, bool no_block)
{
    microtcp_t *mtcp;

    event_entry_t *event = pop_event_entry_from_queue(queue);

    while (!event && !no_block) {
        pthread_cond_wait(&queue->something_happened, &mtcp->lock);
        event = pop_event_entry_from_queue(queue);
    }

    microtcp_event_t result;

    if (event) {
        queue_entry_t *socket_entry = event->socket_entry;

        result.type   = event->events;
        result.data   = socket_entry->data;
        result.socket = socket_entry->socket;

    } else {
        result.type = 0;
        result.data = NULL;
        result.socket = NULL;
    }

    return result;
}

static void signal_socket_events_to_queues(microtcp_socket_t *socket, int events)
{
    queue_entry_t *entry = socket->queue_entry;
    while (entry) {
        
        int interesting_events = events & entry->events;

        if (interesting_events) {
            // Some events that are of interest to 
            // this queue are being signaled.
            // Push them onto the queue's event queue
            
            microtcp_queue_t *queue = entry->queue;

            if (entry->event_entry) {
                // At least one event was already signaled, so
                // an event structure was already created. 
                // We just need to add to it the newly signaled
                // events.
                event_entry_t *event = entry->event_entry;
                event->events |= interesting_events;
            } else {

                // No events related to this socket are in the
                // queue, so we need to create a new event structure.
                //
                // Unused event structure are organized in a free
                // list, so we just need to pop one from there.
                // 
                // We know for sure that a free event structure is
                // available at this point because there is one for
                // each socket registered into the queue.
                assert(queue->event_free_list);

                event_entry_t *event = queue->event_free_list;
                queue->event_free_list = event->next;

                // Set-up the event structure
                event->prev = NULL;
                event->next = NULL;
                event->events = interesting_events;
                event->socket_entry = entry;

                // Now push the event structure into the queue's queue
                event->next = queue->queue_head;
                if (queue->queue_head)
                    queue->queue_head->prev = event;
                else
                    queue->queue_tail = event;
                queue->queue_head = event;
            }
            
            pthread_cond_signal(&queue->something_happened);
        }

        entry = entry->next;
    }
}

microtcp_queue_t *microtcp_queue_create(microtcp_t *mtcp)
{
    microtcp_queue_t *queue = malloc(sizeof(microtcp_queue_t));
    if (!queue)
        return NULL;

    queue->mtcp = mtcp;
    queue->queue_head = NULL;
    queue->queue_tail = NULL;
    queue->entry_free_list = queue->entry_pool;
    queue->event_free_list = queue->event_pool;

    for (size_t i = 0; i < MICROTCP_QUEUE_ENTRIES_MAX-1; i++) {
        mtcp->entry_pool[i].mtcp = NULL;
        mtcp->entry_pool[i].prev = NULL;
        mtcp->entry_pool[i].next = mtcp->entry_pool + i+1;

        mtcp->event_pool[i].mtcp = NULL;
        mtcp->event_pool[i].prev = NULL;
        mtcp->event_pool[i].next = mtcp->event_pool + i+1;
    }
    mtcp->entry_pool[MICROTCP_QUEUE_ENTRIES_MAX-1].mtcp = NULL;
    mtcp->entry_pool[MICROTCP_QUEUE_ENTRIES_MAX-1].prev = NULL;
    mtcp->entry_pool[MICROTCP_QUEUE_ENTRIES_MAX-1].next = NULL;

    mtcp->event_pool[MICROTCP_QUEUE_ENTRIES_MAX-1].prev = NULL;
    mtcp->event_pool[MICROTCP_QUEUE_ENTRIES_MAX-1].next = NULL;

    if (pthread_cond_init(&queue->something_happened, NULL)) {
        free(queue);
        return NULL;
    }

    return queue;
}

void microtcp_queue_destroy(microtcp_queue_t *queue)
{
    for (size_t i = 0; i < MICROTCP_QUEUE_ENTRIES_MAX; i++) {
        if (queue->entries[i].mtcp == NULL)
            continue;
        microtcp_queue_unregister(queue, queue->entries[i].socket, MICROTCP_EVENT_ALL);
    }
    free(queue);
}

bool microtcp_queue_register(microtcp_queue_t *queue, microtcp_socket_t *socket, void *data, int events)
{
    if (!events)
        return true; // No events registered

    if (!queue->free_list)
        return false; // Registration limit reached

    queue_entry_t *entry = queue->free_list;
    queue->free_list = entry->next;

    entry->prev = NULL;
    entry->next = NULL;
    entry->data = data;
    entry->queue  = queue;
    entry->events = events;
    entry->socket = socket;

    entry->next = socket->queue_entry;
    if (socket->queue_entry)
        socket->queue_entry->prev = entry;
    socket->queue_entry = entry;

    return true;
}

static queue_entry_t *find_entry(microtcp_queue_t *queue, microtcp_socket_t *socket)
{
    queue_entry_t *entry = socket->queue_entry;
    while (entry) {
        if (entry->queue == queue)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

static void 
unregister_socket_from_all_queues(microtcp_socket_t *socket)
{
    while (socket->queue_entry)
        microtcp_queue_unregister(socket->queue_entry->queue, socket, MICROTCP_EVENT_ALL);
}

bool microtcp_queue_unregister(microtcp_queue_t *queue, microtcp_socket_t *socket, int unregister_events)
{
    if (!queue || !socket || queue->mtcp != socket->mtcp)
        return false;

    queue_entry_t *entry = find_entry(queue, socket);
    if (!entry)
        return false; // Socket wasn't registered in this queue

    int remaining_events = entry->events & ~unregister_events;

    if (!remaining_events) {

        // All events were unregistered, so the 
        // socket must be removed from the queue.

        // Unlink any events related to this socket
        // from the queue
        queue_event_t *event = entry->event_entry;
        if (event) {

            // Remove the event structure from the queue
            if (event->prev)
                event->prev->next = event->next;
            else
                queue->queue_head = event->next;

            if (event->next)
                event->next->prev = event->prev;
            else
                queue->queue_tail = event->prev;

            // Push the now unlinked event structure onto
            // the free list
            event->prev = NULL;
            event->next = queue->event_free_list;
            queue->event_free_list = event;
        }

        // Unlink the entry from the socket's list
        if (entry->prev)
            entry->prev->next = entry->next;
        else
            socket->queue_entry = entry->next;

        if (entry->next)
            entry->next->prev = entry->prev;

        // Put the entry structure back into the 
        // free list of the queue
        entry->mtcp = NULL; // It's important to set this to NULL because
                            // this way the queue knows it's not used anymore.
        entry->prev = NULL;
        entry->next = queue->free_list;
        queue->free_list = entry;   
    
    } else
        entry->events = remaining_events;

    return true;
}