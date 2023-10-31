# MicroTCP
MicroTCP is a TCP/IP network stack which I started building as a learning exercise while I was attending the Computer Networking course at the Università degli Studi di Napoli Federico II. It's just a hobby project and is intended to just be a minimal, yet complete, implementation.

At this moment MicroTCP implements ARP (RFC 826, complete), IPv4 (no fragmentation), ICMP (minimum necessary to reply to pings) and TCP (complete but not stress-tested). Note that "complete" should be not intended as "fully compliant" but just as a measure of progress on all of the major features. For instance, it's complete enough to handle HTTP traffic on a local network (Look into examples/microhttp to know more).

## Where does it run?
MicroTCP can run on Windows and Linux alongside the OS's network stack. To route the network traffic to MicroTCP, the process running it behaves as a virtual host with its own IP address. This is done using a TAP device, which comes built-in on Linux but needs installing on Windows. It should be very easy to adapt to run MicroTCP on microcontrollers but haven't tried yet. The dream is to serve my [blog](https://cozis.github.io/) from an STM32 board!

## Build and Install
If you are on Windows, you need to install the TAP driver provided by OpenVPN and instanciate a virtual NIC so that MicroTCP can connect to it when started. To build the project from source, make sure you cloned the repository with submodules
```sh
git clone https://github.com/cozis/microtcp.git --recursive
```
and then run
```sh
make
```
You'll need both `make` and `cmake` for it to work. If all goes well, you'll find the library files `libtuntap.a`, `libmicrotcp.a` and header files `tuntap.h`, `tuntap-export.h`, `microtcp.h` in `out/`.

## Usage
MicroTCP's uses the usual socket interface any network programmer is familiar with, the main difference being you need to explicitly instanciate the network stack and pass its handle around.

Here's a simple echo server that shows the basic usage:

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
This should be pretty straight forward to understand. One thing may be worth noting is that `microtcp_open` behaves as the BSD's `socket+bind+listen` all at once to setup a listening TCP server. 

There is more than one way to set up the stack, the main way being `microtcp_create` which creates a virtual network inferface on the host OS with IP 10.0.0.5/24 and a virtual host for the MicroTCP process at 10.0.0.4/24. You can open Wireshark on the virtual NIC to inspect the traffic between the host and the process.

It's also possible to configure the stack using the `microtcp_create_using_callbacks`, which lets you explicitly provide the input L2 frames to it and receive the frames in a buffer. This is how one would configure the stack to run on a microcontroller.

Each instance of MicroTCP (without considering the callbacks) is completely isolated from the others, therefore, if your specific callback implementation allows it, you can have as many instances as you like!

## Testing
There is still no testing infractructure. The way I'm testing it is by setting up an HTTP or echo server and stressing it until something breaks while capturing what happened using Wireshark. 