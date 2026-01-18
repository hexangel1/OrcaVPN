#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define PACKET_BUFFER_SIZE 1536
#define MAX_UDP_PAYLOAD 1472
#define MAX_IF_NAME_LEN 16
#define MAX_IPV4_ADDR_LEN 16
#define MAX_IPV4_CONN_LEN (MAX_IPV4_ADDR_LEN + sizeof(":65535") - 1)
#define PING_DATA_LEN 24
#define ORCAVPN_PORT 778

struct icmp_echo_param {
	uint32_t src_ip;
	uint32_t dst_ip;
	unsigned short seq_id;
	unsigned short seq_no;
	unsigned char data[PING_DATA_LEN];
};

/* Create udp socket & bind to local address [ipv4] */
int create_udp_sock(const char *ip, unsigned short port);
/* Create tcp socket & bind to local address [ipv4] */
int create_tcp_sock(const char *ip, unsigned short port);

/* Create udp socket & bind to local address [ipv6] */
int create_udp_sock6(const char *ip, unsigned short port);
/* Create tcp socket & bind to local address [ipv6] */
int create_tcp_sock6(const char *ip, unsigned short port);

/* Connect socket to address [ipv4] */
int connect_sock(int sockfd, const char *ip, unsigned short port);
/* Connect socket to address [ipv6] */
int connect_sock6(int sockfd, const char *ip, unsigned short port);

/* Send udp datagram [ipv4] */
ssize_t send_udp(int sockfd, const void *buf, size_t len,
	const struct sockaddr_in *addr);
/* Send udp datagram [ipv6] */
ssize_t send_udp6(int sockfd, const void *buf, size_t len,
	const struct sockaddr_in6 *addr);

/* Receive udp datagram [ipv4] */
ssize_t recv_udp(int sockfd, void *buf, size_t len,
	struct sockaddr_in *addr);
/* Receive udp datagram [ipv6] */
ssize_t recv_udp6(int sockfd, void *buf, size_t len,
	struct sockaddr_in6 *addr);

/* Get local socket address string [ipv4] */
const char *get_local_addr(int sockfd);
/* Get remote socket address string [ipv4] */
const char *get_remote_addr(int sockfd);

/* Set max udp send buffer size */
int set_max_sndbuf(int sockfd);
/* Set max udp recv buffer size */
int set_max_rcvbuf(int sockfd);

/* Set nonblock io */
int set_nonblock_io(int fd);
/* Block until write to fd is possible */
void block_for_write(int fd);

/* Evaluate IP header checksum */
unsigned short ip_checksum(const unsigned short *addr, unsigned int count);
/* Get IP protocol version */
int get_ip_version(const void *buf, size_t len);
/* Validate IPv4 header */
int check_header_ipv4(const void *buf, size_t len);
/* Write IPv4 icmp echo packet data to buffer */
int write_icmp_echo(void *buf, const struct icmp_echo_param *param);

/* Get destination ip address from IPv4 packet */
uint32_t get_destination_ip(const void *buf);
/* Get source ip address from IPv4 packet */
uint32_t get_source_ip(const void *buf);

/* Convert IPv4 address to string, use provided buffer for return value */
const char *ipv4tosb(uint32_t ip, int host_order, char *buf);
/* Convert IPv4 address to string, use static buffer for return value */
const char *ipv4tos(uint32_t ip, int host_order);
/* Write IPv4 address to buf in format <ip>:<port> */
char *addr_to_str(const struct sockaddr_in *addr, char *buf, size_t len);
/* Check IPv4 address belongs to network */
int ip_in_network(uint32_t ip, uint32_t network, uint32_t mask);

#endif /* NETWORK_H_SENTRY */
