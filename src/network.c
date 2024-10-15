#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include "network.h"
#include "logger.h"

#define ADDR_LEN(af) ((socklen_t)(af == AF_INET ? \
	sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)))

static struct sockaddr *get_addr_af(int af, const char *ip, uint16_t port)
{
	static union {
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
			memcpy(&addr.ipv6.sin6_addr, &in6addr_any, sizeof(in6addr_any));
		}
	} else {
		return NULL;
	}
	return &addr.address;
}

static int create_socket_af(int af, int type, const char *ip, uint16_t port)
{
	int sockfd, res, opt = 1;
	struct sockaddr *addr = get_addr_af(af, ip, port);
	if (!addr) {
		log_mesg(LOG_ERR, "get_addr_af: invalid ip address");
		return -1;
	}
	sockfd = socket(af, type, IPPROTO_IP);
	if (sockfd == -1) {
		log_perror("socket");
		return -1;
	}
	res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (res == -1) {
		log_perror("setsockopt");
		return -1;
	}
	res = bind(sockfd, addr, ADDR_LEN(af));
	if (res == -1) {
		log_perror("bind");
		return -1;
	}
	return sockfd;
}

static int tuntap_alloc(char *ifname, int flags)
{
	const char *clonedev = "/dev/net/tun";
	struct ifreq ifr;

	int fd = open(clonedev, O_RDWR);
	if (fd == -1) {
		log_perror(clonedev);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		log_perror("ioctl");
		close(fd);
		return -1;
	}

	strcpy(ifname, ifr.ifr_name);
	return fd;
}

static int set_if_options(const char *ifname, struct ifreq *ifr, int op)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return -1;
	}

	strncpy(ifr->ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(sockfd, op, ifr) < 0) {
		log_perror("ioctl");
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 0;
}

int create_udp_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET, SOCK_DGRAM, ip, port);
}

int create_tcp_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET, SOCK_STREAM, ip, port);
}

int create_udp6_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET6, SOCK_DGRAM, ip, port);
}

int create_tcp6_socket(const char *ip, unsigned short port)
{
	return create_socket_af(AF_INET6, SOCK_STREAM, ip, port);
}

int create_tun_if(char *tun_name)
{
	return tuntap_alloc(tun_name, IFF_TUN | IFF_NO_PI);
}

int create_tap_if(char *tap_name)
{
	return tuntap_alloc(tap_name, IFF_TAP | IFF_NO_PI);
}

int set_if_up(const char *ifname, int flags)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_UP | flags;
	return set_if_options(ifname, &ifr, SIOCSIFFLAGS);
}

int set_if_mtu(const char *ifname, int mtu)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	return set_if_options(ifname, &ifr, SIOCSIFMTU);
}

int set_if_ipv4(const char *ifname, const char *ipv4)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int res;
	memset(&ifr, 0, sizeof(ifr));

	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	res = inet_pton(AF_INET, ipv4, &addr->sin_addr);
	if (res <= 0) {
		log_mesg(LOG_ERR, "inet_pton: Invalid IPv4 address");
		return -1;
	}
	return set_if_options(ifname, &ifr, SIOCSIFADDR);
}

int set_if_netmask(const char *ifname, const char *mask)
{
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int res;
	memset(&ifr, 0, sizeof(ifr));

	addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	res = inet_pton(AF_INET, mask, &addr->sin_addr);
	if (res <= 0) {
		log_mesg(LOG_ERR, "inet_pton: Invalid IPv4 subnet mask");
		return -1;
	}
	return set_if_options(ifname, &ifr, SIOCSIFNETMASK);
}

int setup_tun_if(const char *ifname, const char *ipv4, const char *mask)
{
	int res;
	res = set_if_up(ifname, IFF_NOARP);
	if (res == -1) {
		log_mesg(LOG_ERR, "set_if_up failed");
		return -1;
	}
	res = set_if_mtu(ifname, TUN_MTU_SIZE);
	if (res == -1) {
		log_mesg(LOG_ERR, "set_if_mtu failed");
		return -1;
	}
	res = set_if_ipv4(ifname, ipv4);
	if (res == -1) {
		log_mesg(LOG_ERR, "set_if_ipv4 failed");
		return -1;
	}
	res = set_if_netmask(ifname, mask);
	if (res == -1) {
		log_mesg(LOG_ERR, "set_if_netmask failed");
		return -1;
	}
	return 0;
}

void nonblock_io(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void wait_for_write(int fd)
{
	fd_set writefds;
	FD_ZERO(&writefds);
	FD_SET(fd, &writefds);
	select(fd + 1, NULL, &writefds, NULL, NULL);
}

static int socket_connect_af(int af, int sockfd, const char *ip, uint16_t port)
{
	int res;
	struct sockaddr *addr = get_addr_af(af, ip, port);
	if (!addr) {
		log_mesg(LOG_ERR, "get_addr_af: invalid ip address");
		return -1;
	}
	res = connect(sockfd, addr, ADDR_LEN(af));
	if (res == -1) {
		log_perror("connect");
		return -1;
	}
	return 0;
}

int socket_connect(int sockfd, const char *ip, unsigned short port)
{
	return socket_connect_af(AF_INET, sockfd, ip, port);
}

int socket_connect6(int sockfd, const char *ip, unsigned short port)
{
	return socket_connect_af(AF_INET6, sockfd, ip, port);
}

static ssize_t
send_udp_af(int af, int sockfd, const void *buf, size_t len,
	struct sockaddr *addr)
{
	ssize_t res;
	socklen_t addrlen = addr ? ADDR_LEN(af) : 0;
	int success;
	do {
		success = 1;
		res = sendto(sockfd, buf, len, 0, addr, addrlen);
		if (res == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				wait_for_write(sockfd);
				success = 0;
			} else {
				log_perror("sendto");
				return -1;
			}
		}
	} while (!success);
	return res;
}

static ssize_t
recv_udp_af(int af, int sockfd, void *buf, size_t len, struct sockaddr *addr)
{
	socklen_t addrlen = ADDR_LEN(af);
	ssize_t res;
	res = recvfrom(sockfd, buf, len, 0, addr, addr ? &addrlen : NULL);
	if (res <= 0) {
		log_perror("recvfrom");
		return -1;
	}
	return res;
}

ssize_t
send_udp(int sockfd, const void *buf, size_t len, struct sockaddr_in *addr)
{
	return send_udp_af(AF_INET, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t
send_udp6(int sockfd, const void *buf, size_t len, struct sockaddr_in6 *addr)
{
	return send_udp_af(AF_INET6, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t
recv_udp(int sockfd, void *buf, size_t len, struct sockaddr_in *addr)
{
	return recv_udp_af(AF_INET, sockfd, buf, len, (struct sockaddr *)addr);
}

ssize_t
recv_udp6(int sockfd, void *buf, size_t len, struct sockaddr_in6 *addr)
{
	return recv_udp_af(AF_INET6, sockfd, buf, len, (struct sockaddr *)addr);
}

uint32_t get_destination_ip(const void *buffer, size_t size)
{
	if (size < sizeof(struct iphdr))
		return 0;
	return ntohl(((struct iphdr *)buffer)->daddr);
}

uint32_t get_source_ip(const void *buffer, size_t size)
{
	if (size < sizeof(struct iphdr))
		return 0;
	return ntohl(((struct iphdr *)buffer)->saddr);
}

const char *ipv4_tostring(uint32_t ip, int host_order)
{
	struct in_addr addr;
	addr.s_addr = host_order ? htonl(ip) : ip;
	return inet_ntoa(addr);
}

void print_ip_packet(const void *buffer, size_t size)
{
	struct in_addr addr;
	const struct iphdr *ip = buffer;
	if (size < sizeof(struct iphdr))
		return;
	fprintf(stderr, "protocol = %u\n", ip->protocol);
	fprintf(stderr, "ihl = %u\n", ip->ihl);
	fprintf(stderr, "version = %u\n", ip->version);
	fprintf(stderr, "total len = %u\n", ntohs(ip->tot_len));
	fprintf(stderr, "id = %u\n", ntohs(ip->id));
	fprintf(stderr, "ttl = %u\n", ip->ttl);
	fprintf(stderr, "frag off = %u\n", ip->frag_off);
	fprintf(stderr, "check = %u\n", ip->check);
	addr.s_addr = ip->saddr;
	fprintf(stderr, "ip source = %s\n", inet_ntoa(addr));
	addr.s_addr = ip->daddr;
	fprintf(stderr, "ip dest = %s\n", inet_ntoa(addr));
}
