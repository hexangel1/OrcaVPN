#ifndef NETWORK_H_SENTRY
#define NETWORK_H_SENTRY

#include <stddef.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define ORCAVPN_PORT 778
#define PACKET_BUFFER_SIZE 1536
#define MAX_UDP_PAYLOAD 1472

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

#endif /* NETWORK_H_SENTRY */
