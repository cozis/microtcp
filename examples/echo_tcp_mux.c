

int main(void)
{
    microtcp_t *mtcp = microtcp_create(..);

    uint16_t port = 8080;
    microtcp_socket_t *socket = microtcp_open(mtcp, port, 0);
    
    microtcp_mux_t *mux = microtcp_mux_create(mtcp);
    for (int i = 0; i < 3; i++) {
        microtcp_socket_t *accepted = microtcp_accept(socket, 0, 0);
        microtcp_mux_register(mux, accepted, MICROTCP_MUX_RECV | MICROTCP_MUX_SEND);
    }

    for (microtcp_muxevent_t event; microtcp_mux_wait(mux, &event)) {
        if (event.events & MICROTCP_MUX_RECV) {
            // Il socket "event.socket" ha dei dati da leggere
        } else {
            // Il socket "event.socket" ha spazio per inviare
        }
    }

    microtcp_destroy(mtcp);
}