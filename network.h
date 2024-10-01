#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define TUN_IF_NAME "orca-gate"
#define TUN_IF_ADDR "10.0.0.1"
#define TUN_IF_NETMASK "255.255.255.0"
#define TUN_MTU_SIZE 1400
#define PACKET_BUFFER_SIZE 2048
#define MAX_UDP_PAYLOAD 1432
#define MAX_IPV4_ADDR_LEN 16
#define MAX_IF_NAME_LEN 16
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

ssize_t send_udp(int sockfd, const void *buf, size_t len, struct sockaddr_in *addr);
ssize_t recv_udp(int sockfd, void *buf, size_t len, struct sockaddr_in *addr);

uint32_t get_destination_ip(const void *buffer, size_t size);
uint32_t get_source_ip(const void *buffer, size_t size);

const char *ipv4_tostring(uint32_t ip, int host_order);

void print_ip_packet(const void *buffer, size_t size);

#endif /* NETWORK_H_SENTRY */
