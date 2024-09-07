#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <linux/if.h>

#define TUN_IF_NAME "vpn-tun0"
#define TUN_IF_ADDR "10.0.0.1"
#define TUN_IF_NETMASK "255.255.255.0"
#define TUN_MTU_SIZE 1400
#define TUN_MTU_SIZE_MAX 1500
#define VPN_PORT 778

int create_udp_socket(const char *ip, unsigned short port);
int create_tcp_socket(const char *ip, unsigned short port);

int create_tun_if(char *tun_name);
int create_tap_if(char *tap_name);

int set_if_up(const char *ifname, int flags);
int set_if_mtu(const char *ifname, int mtu);
int set_if_ipv4(const char *ifname, const char *ipv4);
int set_if_netmask(const char *ifname, const char *mask);
int setup_tun_if(const char *ifname, const char *ipv4, const char *mask, int mtu);

int socket_connect(int sockfd, const char *ip, unsigned short port);

void nonblock_io(int fd);
void wait_for_write(int fd);

int tun_if_forward(int tunfd, int sockfd);
int sockfd_forward(int tunfd, int sockfd);

void print_ip_packet(const void *buffer, size_t size);

#endif /* NETWORK_H_SENTRY */