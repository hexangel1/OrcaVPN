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
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <linux/icmp.h>

#include "network.h"
#include "logger.h"

static struct sockaddr *
get_sockaddr(int af, const char *ip, unsigned short port)
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
			int res = inet_pton(af, ip, &addr.ipv4.sin_addr);
			if (res <= 0)
				return NULL;
		} else {
			addr.ipv4.sin_addr.s_addr = INADDR_ANY;
		}
	} else if (af == AF_INET6) {
		addr.ipv6.sin6_family = af;
		addr.ipv6.sin6_port = htons(port);
		if (ip && *ip) {
			int res = inet_pton(af, ip, &addr.ipv6.sin6_addr);
			if (res <= 0)
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
create_socket_af(int af, int type, const char *ip, unsigned short port)
{
	int sockfd, res, opt = 1;
	struct sockaddr *addr;

	addr = get_sockaddr(af, ip, port);
	if (!addr) {
		log_mesg(LOG_ERR, "get_sockaddr: invalid ip address");
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
		return -1;
	}
	res = bind(sockfd, addr, AF_SOCKLEN(af));
	if (res < 0) {
		log_perror("bind");
		return -1;
	}
	return sockfd;
}

static int
connect_socket_af(int af, int sockfd, const char *ip, unsigned short port)
{
	int res;
	struct sockaddr *addr;

	addr = get_sockaddr(af, ip, port);
	if (!addr) {
		log_mesg(LOG_ERR, "get_sockaddr: invalid ip address");
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
	struct sockaddr *addr)
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
	ssize_t res;
	socklen_t addrlen = AF_SOCKLEN(af);

	res = recvfrom(sockfd, buf, len, 0, addr, addr ? &addrlen : NULL);
	if (res < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			log_perror("recvfrom");
			return -1;
		}
		res = 0;
	}
	if (!res)
		log_mesg(LOG_NOTICE, "received no data on udp socket");
	return res;
}

int create_udp_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET, SOCK_DGRAM, ip, port);
}

int create_tcp_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET, SOCK_STREAM, ip, port);
}

int create_udp_socket6(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET6, SOCK_DGRAM, ip, port);
}

int create_tcp_socket6(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET6, SOCK_STREAM, ip, port);
}

int connect_socket(int sockfd, const char *ip, unsigned short port)
{
	return connect_socket_af(AF_INET, sockfd, ip, port);
}

int connect_socket6(int sockfd, const char *ip, unsigned short port)
{
	return connect_socket_af(AF_INET6, sockfd, ip, port);
}

ssize_t send_udp(int sockfd, const void *buf, size_t len,
	struct sockaddr_in *addr)
{
	return send_udp_af(AF_INET, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t send_udp6(int sockfd, const void *buf, size_t len,
	struct sockaddr_in6 *addr)
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

const char *get_local_bind_addr(int sockfd)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int res;

	res = getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
	if (res < 0) {
		log_perror("getsockname");
		return "";
	}
	return ipv4tos(addr.sin_addr.s_addr, 0);
}

int get_local_bind_port(int sockfd)
{
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int res;

	res = getsockname(sockfd, (struct sockaddr *)&addr, &addrlen);
	if (res < 0) {
		log_perror("getsockname");
		return -1;
	}
	return ntohs(addr.sin_port);
}

int set_max_sndbuf(int sockfd)
{
	int res, snd_bufsize;
	socklen_t optlen = sizeof(snd_bufsize);
	FILE *fp;

	fp = fopen("/proc/sys/net/core/wmem_max", "r");
	if (!fp) {
		log_mesg(LOG_NOTICE, "wmem_max value not found");
		return -1;
	}
	res = fscanf(fp, "%d", &snd_bufsize);
	fclose(fp);
	if (res < 1) {
		log_mesg(LOG_NOTICE, "invalid wmem_max value");
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
	log_mesg(LOG_DEBUG, "SO_SNDBUF = %d", snd_bufsize);
	return 0;
}

int set_max_rcvbuf(int sockfd)
{
	int res, rcv_bufsize;
	socklen_t optlen = sizeof(rcv_bufsize);
	FILE *fp;

	fp = fopen("/proc/sys/net/core/rmem_max", "r");
	if (!fp) {
		log_mesg(LOG_NOTICE, "rmem_max value not found");
		return -1;
	}
	res = fscanf(fp, "%d", &rcv_bufsize);
	fclose(fp);
	if (res < 1) {
		log_mesg(LOG_NOTICE, "invalid rmem_max value");
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
	log_mesg(LOG_DEBUG, "SO_RCVBUF = %d", rcv_bufsize);
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

uint16_t ip_checksum(const uint16_t *addr, unsigned int count)
{
	register unsigned long sum = 0;

	while (count > 1)  {
		sum += *addr++;
		count -= 2;
	}
	if (count > 0)
		sum += *(unsigned char *)addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = ~sum;
	return sum;
}

int check_ipv4_packet(const void *buf, size_t len, int skip_sum)
{
	const struct iphdr *ip_header = buf;

	if (len < sizeof(struct iphdr))
		return 0;
	if (ip_header->version != 4 || (size_t)ntohs(ip_header->tot_len) != len)
		return 0;
	if (!skip_sum) {
		unsigned int ihl = ip_header->ihl;
		if (ihl < 5 || ihl > 15)
			return 0;
		if (ip_checksum((uint16_t *)ip_header, ihl * 4))
			return 0;
	}
	return 1;
}

int write_icmp_echo(void *buf, const struct icmp_echo_param *param)
{
	struct iphdr *ip_header;
	struct icmphdr *icmp_header;
	unsigned char *echo_data;
	unsigned short total_len;

	ip_header = (void *)buf;
	icmp_header = (void *)((char *)ip_header + sizeof(struct iphdr));
	echo_data = (void *)((char *)icmp_header + sizeof(struct icmphdr));
	total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) +
		sizeof(param->data);

	ip_header->ihl = 5;
	ip_header->version = 4;
	ip_header->tos = 0;
	ip_header->tot_len = htons(total_len);
	ip_header->id = htons(0xffff & rand());
	ip_header->frag_off = htons(0x4000);
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->check = 0;
	ip_header->saddr = htonl(param->src_ip);
	ip_header->daddr = htonl(param->dst_ip);

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->checksum = 0;
	icmp_header->un.echo.id = htons(param->seq_id);
	icmp_header->un.echo.sequence = htons(param->seq_no);

	memcpy(echo_data, param->data, PING_DATA_LEN);

	ip_header->check = ip_checksum((uint16_t *)ip_header,
		sizeof(struct iphdr));
	icmp_header->checksum = ip_checksum((uint16_t *)icmp_header,
		sizeof(struct icmphdr) + PING_DATA_LEN);

	return total_len;
}

uint32_t get_destination_ip(const void *buf)
{
	return ntohl(((struct iphdr *)buf)->daddr);
}

uint32_t get_source_ip(const void *buf)
{
	return ntohl(((struct iphdr *)buf)->saddr);
}

const char *ipv4tosb(uint32_t ip, int host_order, char *buf)
{
	static char ipv4_buffer[MAX_IPV4_ADDR_LEN];

	if (!buf)
		buf = ipv4_buffer;
	if (!host_order)
		ip = ntohl(ip);
	snprintf(buf, sizeof(ipv4_buffer), "%u.%u.%u.%u",
		(ip >> 24) & 0xff, (ip >> 16) & 0xff,
		(ip >> 8)  & 0xff, (ip) & 0xff);
	return buf;
}

const char *ipv4tos(uint32_t ip, int host_order)
{
	return ipv4tosb(ip, host_order, NULL);
}

int ip_in_network(uint32_t ip, uint32_t network, uint32_t mask)
{
	return (ip & mask) == (network & mask);
}
