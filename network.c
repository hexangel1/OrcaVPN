#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include "network.h"
#include "helper.h"

static int create_socket(const char *ip, unsigned short port, int type)
{
	int sockfd, res;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	sockfd = socket(AF_INET, type, 0);
	if (sockfd == -1) {
		perror("socket");
		return -1;
	}
	res = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (res == -1) {
		perror("bind");
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
		perror(clonedev);
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		perror("ioctl");
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
		perror("socket");
		return -1;
	}

	strncpy(ifr->ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sockfd, op, ifr) < 0) {
		perror("ioctl");
		close(sockfd);
		return -1;
	}

	close(sockfd);
	return 0;
}

int create_udp_socket(const char *ip, unsigned short port)
{
	return create_socket(ip, port, SOCK_DGRAM);
}

int create_tcp_socket(const char *ip, unsigned short port)
{
	return create_socket(ip, port, SOCK_STREAM);
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
		fprintf(stderr, "inet_pton: Invalid IPv4 address\n");
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
		fprintf(stderr, "inet_pton: Invalid IPv4 subnet mask\n");
		return -1;
	}
	return set_if_options(ifname, &ifr, SIOCSIFNETMASK);
}

int setup_tun_if(const char *ifname, const char *ipv4, const char *mask, int mtu)
{
	int res;
	res = set_if_up(ifname, IFF_NOARP);
	if (res == -1) {
		fprintf(stderr, "set_if_up failed\n");
		return -1;
	}
	res = set_if_mtu(ifname, mtu);
	if (res == -1) {
		fprintf(stderr, "set_if_mtu failed\n");
		return -1;
	}
	res = set_if_ipv4(ifname, ipv4);
	if (res == -1) {
		fprintf(stderr, "set_if_ipv4 failed\n");
		return -1;
	}
	res = set_if_netmask(ifname, mask);
	if (res == -1) {
		fprintf(stderr, "set_if_netmask failed\n");
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

int socket_connect(int sockfd, const char *ip, unsigned short port)
{
	int res;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	res = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (res == -1) {
		perror("connect");
		return -1;
	}
	return 0;
}

ssize_t send_udp(int sockfd, const void *buf, size_t len, struct sockaddr_in *addr)
{
	ssize_t res;
	socklen_t addrlen = addr ? sizeof(struct sockaddr_in) : 0;
	int success;
	do {
		success = 1;
		res = sendto(sockfd, buf, len, 0, (struct sockaddr *)addr, addrlen);
		if (res == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				wait_for_write(sockfd);
				success = 0;
			} else {
				perror("sendto");
				return -1;
			}
		}
	} while (!success);
	return res;
}

ssize_t recv_udp(int sockfd, void *buf, size_t len, struct sockaddr_in *addr)
{
	socklen_t addrlen = sizeof(struct sockaddr_in);
	ssize_t res;
	res = recvfrom(sockfd, buf, len, 0,
		(struct sockaddr *)addr, addr ? &addrlen : NULL);
	if (res <= 0) {
		perror("recvfrom");
		return -1;
	}
	return res;
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
