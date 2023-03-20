#ifdef MICROTCP_LINUX

#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "defs.h"
#include "microtcp.h"

static int systemf(const char *fmt, ...)
{
    char buffer[256];

    va_list va;
    va_start(va, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, va);
    va_end(va);

    fprintf(stderr, "INFO: Running [%s]\n", buffer);

    return system(buffer);
}

static int create_tun_device(const char *dev, char dev2[IFNAMSIZ])
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (dev && *dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    int err = ioctl(fd, TUNSETIFF, &ifr);
    if (err) {
        close(fd);
        return -1;
    }

    strncpy(dev2, ifr.ifr_name, IFNAMSIZ);
    return fd;
}

static int send_callback(void *data, const void *src, size_t len)
{
    int tap_fd = (int) data;
    return write(tap_fd, src, len);
}

static int recv_callback(void *data, void *dst, size_t len)
{
    int tap_fd = (int) data;

    int timeout = 1000;

    struct pollfd pfd = {.fd=tap_fd, .events=POLLIN};
    int status = poll(&pfd, 1, timeout);
    if (status < 1) {
        return status;
    }
    
    int num = read(tap_fd, dst, len);
    return num;
}

static void free_callback(void *data)
{
    int tap_fd = (int) data;
    close(tap_fd);
}

/*
static bool get_ip_address(const char *dev, microtcp_ip_t *ip)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    memcpy(ip, &((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr, sizeof(microtcp_ip_t));

    close(fd);
    return true;
}
*/

static bool get_mac_address(const char *dev, microtcp_mac_t *mac)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) 
        return false;

    memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(microtcp_mac_t));

    close(fd);
    return true;
}

microtcp_t *microtcp_create()
{
    char dev[IFNAMSIZ];
    int tap_fd = create_tun_device("tap0", dev);
    if (tap_fd < 0) {
        fprintf(stderr, "ERROR: Failed creating TAP device (%s)\n", strerror(errno));
        return NULL;
    }
    fprintf(stderr, "INFO: Using TAP device %s\n", dev);

    const char *tap_addr  = "10.0.0.5";
    const char *tap_route = "10.0.0.0/24";
    
    systemf("ip link set dev %s up", dev);
    systemf("ip route add dev %s %s", dev, tap_route);
    systemf("ip address add dev %s local %s", dev, tap_addr);
    systemf("sudo sysctl -w net.ipv4.ip_forward=1");

    microtcp_mac_t mac;
    if (!get_mac_address(dev, &mac)) {
        fprintf(stderr, "FATAL: Failed to query NIC for IP or MAC (%s)\n", strerror(errno));
        close(tap_fd);
        return NULL;
    }

    mac.data[5]++;

    microtcp_ip_t ip;
    inet_pton(AF_INET, "10.0.0.4", &ip);

    struct in_addr ip2;
    ip2.s_addr = ip;
    fprintf(stderr, "INFO: Using IP %s\n", inet_ntoa(ip2));
    fprintf(stderr, "INFO: Using MAC %x:%x:%x:%x:%x:%x\n", mac.data[0], mac.data[1], mac.data[2], mac.data[3], mac.data[4], mac.data[5]);

    microtcp_callbacks_t callbacks = {
        .data = (int) tap_fd,
        .send = send_callback,
        .recv = recv_callback,
        .free = free_callback,
    };

    microtcp_t *mtcp = microtcp_create_using_callbacks(ip, mac, callbacks);
    if (!mtcp) {
        close(tap_fd);
        return NULL;
    }

    return mtcp;
}

#endif /* MICROTCP_LINUX */