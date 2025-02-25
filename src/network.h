#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define TUN_IF_NAME "orca-gate"
#define TUN_IF_ADDR "10.80.80.1"
#define TUN_IF_NETMASK "255.255.255.0"
#define TUN_IF_MTU 1387
#define TUN_IF_QLEN 1000
#define PACKET_BUFFER_SIZE 1536
#define MAX_UDP_PAYLOAD 1432
#define MAX_IPV4_ADDR_LEN 16
#define MAX_IF_NAME_LEN 16
#define PING_DATA_LEN 24
#define VPN_PORT 778

#define AF_SOCKLEN(af) ((socklen_t)(af == AF_INET ? \
	sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))

struct icmp_echo_param {
	uint16_t seq_id;
	uint16_t seq_no;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t data[PING_DATA_LEN];
};

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

ssize_t send_tun(int tunfd, const void *buf, size_t len);
ssize_t recv_tun(int tunfd, void *buf, size_t len);

int set_max_sndbuf(int sockfd);
int set_max_rcvbuf(int sockfd);

void set_nonblock_io(int fd);
void block_for_write(int fd);

uint16_t ip_checksum(uint16_t *addr, unsigned int count);
size_t write_icmp_echo(void *buf, const struct icmp_echo_param *param);

uint32_t get_destination_ip(const void *buf, size_t len);
uint32_t get_source_ip(const void *buf, size_t len);

const char *ipv4tosb(uint32_t ip, int host_order, char *buf);
const char *ipv4tos(uint32_t ip, int host_order);
int ip_in_network(uint32_t ip, uint32_t network, uint32_t mask);

void print_ip_packet(const void *buf, size_t len);

#endif /* NETWORK_H_SENTRY */
