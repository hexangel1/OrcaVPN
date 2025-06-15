#ifndef TUNNEL_H_SENTRY
#define TUNNEL_H_SENTRY

#include <stddef.h>
#include <sys/types.h>

#define TUN_IF_NAME "orca-gate"
#define TUN_IF_ADDR "10.80.80.1"
#define TUN_IF_NETMASK "255.255.255.0"
#define TUN_IF_MTU 1419
#define TUN_IF_QLEN 1000

/* Create tun device */
int create_tun_if(char *tun_name);
/* Create tap device */
int create_tap_if(char *tap_name);

/* Setup tun device address, mask, mtu, qlen */
int setup_tun_if(const char *ifname, const char *addr, const char *mask);

/* Write packet from buffer to tun device */
ssize_t send_tun(int tunfd, const void *buf, size_t len);
/* Read packet from tun device to buffer */
ssize_t recv_tun(int tunfd, void *buf, size_t len);

#endif /* TUNNEL_H_SENTRY */
