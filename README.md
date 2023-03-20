# MicroTCP
Micro TCP is a network stack designed to be easily embeddable, portable and thoroughly tested. It implements ARP, IP, ICMP and TCP. The ideal use-cases are user-space networking and using it in bare-metal microcontrollers.

## Usage
To use it, you need to instanciate a `microtcp_t` structure using either the `microtcp_create` or `microtcp_create_using_callbacks` constructor.

The basic constructor `microtcp_create` behaves differently based on your platform because it needs to plug the stack to the system. At the moment it's assumed a Linux host and the instanciated stack is associated to a tap device `tap0` with IP `10.0.0.5/24`. The stack produces packets with IP `10.0.0.4/24` (being honest, this configuration is only useful for testing).

It's also possible to configure the stack explicitly using the `microtcp_create_using_callbacks`, which lets the caller provide the callbacks to input the ethernet frames to the stack and send frames back on the wire. Each system will need it's specific implementation of these callbacks. 

Each instance of MicroTCP (without considering the callbacks) is completely isolated from the others, therefore, if your specific callback implementation allows it, you can have as many instances as you like! Usually the callbacks introduce a dependency between the stacks because the system is one big global state.

Once instanciated, you can free the stack using `microtcp_destroy`.

Once a `microtcp_t` instance is created, you can create and use sockets with methods analogous to the BSD socket API. For instance, here's a simple TCP echo server which replies to messages with the message itself prefixed with "echo: ":

```c
#include <microtcp.h>

int main(void)
{
    microtcp_t *mtcp = microtcp_create();
    
    uint16_t port = 80;
    microtcp_socket_t *server = microtcp_open(mtcp, port, NULL);
    
    while (1) {

        microtcp_socket_t *client = microtcp_accept(server, false, NULL);

        char buffer[1024];
        size_t num = microtcp_recv(client, buffer, sizeof(buffer), NULL);
        microtcp_send(client, "echo: ", 6, NULL);
        microtcp_send(client, buffer, num, NULL);

        microtcp_close(client);
    }
    
    microtcp_close(server);
    microtcp_destroy(mtcp);
    return 0;
}

// NOTE: Errors checks were omitted for readability's sake.
//       If you want to use this code, you probably want to
//       add some checks!
```
