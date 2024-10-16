#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define TUN_IF_NAME "orca-gate"
#define TUN_IF_ADDR "10.80.80.1"
#define TUN_IF_NETMASK "255.255.255.0"
#define TUN_IF_MTU 1400
#define TUN_IF_QLEN 1000
#define PACKET_BUFFER_SIZE 2048
#define MAX_UDP_PAYLOAD 1432
#define MAX_IPV4_ADDR_LEN 16
#define MAX_IF_NAME_LEN 16
#define VPN_PORT 778

#define AF_SOCKLEN(af) ((socklen_t)(af == AF_INET ? \
	sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))

int create_udp_socket(const char *ip, unsigned short port);
int create_tcp_socket(const char *ip, unsigned short port);

int create_udp_socket6(const char *ip, unsigned short port);
int create_tcp_socket6(const char *ip, unsigned short port);

int connect_socket(int sockfd, const char *ip, unsigned short port);
int connect_socket6(int sockfd, const char *ip, unsigned short port);

ssize_t send_udp(int sockfd, const void *buf, size_t len,
	struct sockaddr_in *addr);
ssize_t send_udp6(int sockfd, const void *buf, size_t len,
	struct sockaddr_in6 *addr);

ssize_t recv_udp(int sockfd, void *buf, size_t len,
	struct sockaddr_in *addr);
ssize_t recv_udp6(int sockfd, void *buf, size_t len,
	struct sockaddr_in6 *addr);

int create_tun_if(char *tun_name);
int create_tap_if(char *tap_name);

int setup_tun_if(const char *ifname, const char *addr, const char *mask);

void set_nonblock_io(int fd);
void block_for_write(int fd);

uint32_t get_destination_ip(const void *buf, size_t len);
uint32_t get_source_ip(const void *buf, size_t len);

const char *ipv4_tostring(uint32_t ip, int host_order);

void print_ip_packet(const void *buf, size_t len);

#endif /* NETWORK_H_SENTRY */
