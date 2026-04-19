#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "network.h"
#include "ipproto.h"
#include "logger.h"

#define AF_SOCKLEN(af) ((socklen_t)((af) == AF_INET ? \
	sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))

static struct sockaddr *
get_sock_addr(int af, const char *ip, unsigned short port)
{
	static union ipv4_ipv6_sockaddr {
		struct sockaddr  address;
		struct sockaddr_in  ipv4;
		struct sockaddr_in6 ipv6;
	} addr;

	memset(&addr, 0, sizeof(addr));
	if (af == AF_INET) {
		addr.ipv4.sin_family = af;
		addr.ipv4.sin_port = htons(port);
		if (ip && *ip) {
			if (inet_pton(af, ip, &addr.ipv4.sin_addr) < 1)
				return NULL;
		} else {
			addr.ipv4.sin_addr.s_addr = INADDR_ANY;
		}
	} else if (af == AF_INET6) {
		addr.ipv6.sin6_family = af;
		addr.ipv6.sin6_port = htons(port);
		if (ip && *ip) {
			if (inet_pton(af, ip, &addr.ipv6.sin6_addr) < 1)
				return NULL;
		} else {
			memcpy(&addr.ipv6.sin6_addr, &in6addr_any,
				sizeof(in6addr_any));
		}
	} else {
		return NULL;
	}
	return &addr.address;
}

static int
create_sock_af(int af, int type, const char *ip, unsigned short port)
{
	int sockfd, res, opt = 1;
	struct sockaddr *addr;

	addr = get_sock_addr(af, ip, port);
	if (!addr) {
		log_mesg(log_lvl_err, "get_sock_addr: invalid ip address");
		return -1;
	}
	res = socket(af, type, 0);
	if (res < 0) {
		log_perror("socket");
		return -1;
	}
	sockfd = res;

	res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (res < 0) {
		log_perror("setsockopt");
		close(sockfd);
		return -1;
	}
	res = bind(sockfd, addr, AF_SOCKLEN(af));
	if (res < 0) {
		log_perror("bind");
		close(sockfd);
		return -1;
	}
	return sockfd;
}

static int
connect_sock_af(int af, int sockfd, const char *ip, unsigned short port)
{
	int res;
	struct sockaddr *addr;

	addr = get_sock_addr(af, ip, port);
	if (!addr) {
		log_mesg(log_lvl_err, "get_sock_addr: invalid ip address");
		return -1;
	}
	res = connect(sockfd, addr, AF_SOCKLEN(af));
	if (res < 0) {
		log_perror("connect");
		return -1;
	}
	return 0;
}

static ssize_t send_udp_af(int af, int sockfd, const void *buf, size_t len,
	const struct sockaddr *addr)
{
	socklen_t addrlen = addr ? AF_SOCKLEN(af) : 0;
	ssize_t res;
	int success;

	do {
		success = 1;
		res = sendto(sockfd, buf, len, 0, addr, addrlen);
		if (res < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				block_for_write(sockfd);
				success = 0;
			} else if (errno == EINTR) {
				success = 0;
			} else {
				log_perror("sendto");
				return -1;
			}
		}
	} while (!success);
	return res;
}

static ssize_t recv_udp_af(int af, int sockfd, void *buf, size_t len,
	struct sockaddr *addr)
{
	socklen_t addrlen = AF_SOCKLEN(af);
	ssize_t res;

	res = recvfrom(sockfd, buf, len, 0, addr, addr ? &addrlen : NULL);
	if (res < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			log_perror("recvfrom");
			return -1;
		}
		res = 0;
	}
	if (!res)
		log_mesg(log_lvl_normal, "recvfrom: received no data on sock");
	return res;
}

int create_udp_sock(const char *ip, unsigned short port)
{
	return create_sock_af(AF_INET, SOCK_DGRAM, ip, port);
}

int create_tcp_sock(const char *ip, unsigned short port)
{
	return create_sock_af(AF_INET, SOCK_STREAM, ip, port);
}

int create_udp_sock6(const char *ip, unsigned short port)
{
	return create_sock_af(AF_INET6, SOCK_DGRAM, ip, port);
}

int create_tcp_sock6(const char *ip, unsigned short port)
{
	return create_sock_af(AF_INET6, SOCK_STREAM, ip, port);
}

int connect_sock(int sockfd, const char *ip, unsigned short port)
{
	return connect_sock_af(AF_INET, sockfd, ip, port);
}

int connect_sock6(int sockfd, const char *ip, unsigned short port)
{
	return connect_sock_af(AF_INET6, sockfd, ip, port);
}

ssize_t send_udp(int sockfd, const void *buf, size_t len,
	const struct sockaddr_in *addr)
{
	return send_udp_af(AF_INET, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t send_udp6(int sockfd, const void *buf, size_t len,
	const struct sockaddr_in6 *addr)
{
	return send_udp_af(AF_INET6, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t recv_udp(int sockfd, void *buf, size_t len,
	struct sockaddr_in *addr)
{
	return recv_udp_af(AF_INET, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t recv_udp6(int sockfd, void *buf, size_t len,
	struct sockaddr_in6 *addr)
{
	return recv_udp_af(AF_INET6, sockfd, buf, len, (struct sockaddr *)addr);
}

const char *get_local_addr(int sockfd)
{
	static char buffer[MAX_IPV4_CONN_LEN];
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int res;

	res = getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
	if (res < 0) {
		log_perror("getsockname");
		return "";
	}
	return addr_to_str(&addr, buffer, sizeof(buffer));
}

const char *get_remote_addr(int sockfd)
{
	static char buffer[MAX_IPV4_CONN_LEN];
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int res;

	res = getpeername(sockfd, (struct sockaddr *)&addr, &addrlen);
	if (res < 0) {
		log_perror("getpeername");
		return "";
	}
	return addr_to_str(&addr, buffer, sizeof(buffer));
}

int set_max_sndbuf(int sockfd)
{
	int res, snd_bufsize;
	socklen_t optlen = sizeof(snd_bufsize);
	FILE *fp;

	fp = fopen("/proc/sys/net/core/wmem_max", "r");
	if (!fp) {
		log_mesg(log_lvl_warn, "wmem_max value not found");
		return -1;
	}
	res = fscanf(fp, "%d", &snd_bufsize);
	fclose(fp);
	if (res < 1) {
		log_mesg(log_lvl_warn, "invalid wmem_max value");
		return -1;
	}

	res = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &snd_bufsize, optlen);
	if (res < 0) {
		log_perror("setsockopt");
		return -1;
	}
	res = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &snd_bufsize, &optlen);
	if (res < 0) {
		log_perror("getsockopt");
		return -1;
	}
	log_mesg(log_lvl_debug, "SO_SNDBUF = %d", snd_bufsize);
	return 0;
}

int set_max_rcvbuf(int sockfd)
{
	int res, rcv_bufsize;
	socklen_t optlen = sizeof(rcv_bufsize);
	FILE *fp;

	fp = fopen("/proc/sys/net/core/rmem_max", "r");
	if (!fp) {
		log_mesg(log_lvl_warn, "rmem_max value not found");
		return -1;
	}
	res = fscanf(fp, "%d", &rcv_bufsize);
	fclose(fp);
	if (res < 1) {
		log_mesg(log_lvl_warn, "invalid rmem_max value");
		return -1;
	}

	res = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcv_bufsize, optlen);
	if (res < 0) {
		log_perror("setsockopt");
		return -1;
	}
	res = getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcv_bufsize, &optlen);
	if (res < 0) {
		log_perror("getsockopt");
		return -1;
	}
	log_mesg(log_lvl_debug, "SO_RCVBUF = %d", rcv_bufsize);
	return 0;
}

int set_nonblock_io(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		log_perror("fcntl F_GETFL");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		log_perror("fcntl F_SETFL");
		return -1;
	}
	return 0;
}

void block_for_write(int fd)
{
	fd_set writefds;
	FD_ZERO(&writefds);
	FD_SET(fd, &writefds);
	select(fd + 1, NULL, &writefds, NULL, NULL);
}
