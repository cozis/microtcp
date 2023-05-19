#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <tuntap.h>
#include "xhttp.h"

static xh_handle handle;

static void callback(xh_request *req, xh_response *res, void *userp)
{
    (void) req;
    (void) userp;
    
    res->status = 200;
    res->body.str = "Hello, world!";
    xh_header_add(res, "Content-Type", "text/plain");
}
/*
static void handle_sigterm(int signum) 
{
    (void) signum;
    xh_quit(handle);
}
*/
int main(void)
{
/*
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT,  handle_sigterm);

#ifndef _WIN32
    signal(SIGQUIT, handle_sigterm);
#endif
*/
    char ip[] = "10.0.0.4";
    char mac[] = "00:01:00:01:00:00";

    struct device *dev = tuntap_init();
    if (!dev) {
        fprintf(stderr, "Error: Couldn't initialize the TAP library\n");
        return -1;
    }

    // This must be set AFTER tuntap_init because
    // it sets the callback function to the default
    // callback which writes to stderr.
    //tuntap_log_set_cb(NULL);

    int netmask = 24; // TODO: Make this configurable

    if (tuntap_start(dev, TUNTAP_MODE_ETHERNET, TUNTAP_ID_ANY)) {
        fprintf(stderr, "Error: Couldn't set up the TAP device\n");
        tuntap_release(dev);
        return -1;
    }

    tuntap_set_ip(dev, ip, netmask);
    tuntap_set_hwaddr(dev, mac);

    if (tuntap_up(dev)) {
        fprintf(stderr, "Error: Couldn't activate the TAP device\n");
        tuntap_release(dev);
    }

    microhttp_config_t config = {
        .userp = dev,
        .ip  = ip,
        .mac = mac,
        .recv_frame = (int(*)(void*, void*, size_t)) tuntap_read,
        .send_frame = (int(*)(void*, const void*, size_t)) tuntap_write,
    };
    
    const char *error = xhttp(80, callback, NULL, &handle, config);
    tuntap_release(dev);
    if(error != NULL) {
        fprintf(stderr, "Error: %s\n", error);
        return 1;
    }
    return 0;
}