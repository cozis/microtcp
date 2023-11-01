#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <tuntap.h>
#include "xhttp.h"

static void callback(xh_request *req, xh_response *res, void *userp)
{
    (void) req;
    (void) userp;
    
    res->status = 200;
    res->body.str = "Hello, world!";
    xh_header_add(res, "Content-Type", "text/plain");
}

int main(void)
{
    const char *error = xhttp(80, callback, NULL);
    if(error != NULL) {
        fprintf(stderr, "Error: %s\n", error);
        return 1;
    }
    return 0;
}