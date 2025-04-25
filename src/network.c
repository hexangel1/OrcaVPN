#define _XOPEN_SOURCE 500
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
#include <linux/icmp.h>

#include "network.h"
#include "logger.h"

static struct sockaddr *get_sockaddr(int af, const char *ip, uint16_t port)
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

static int connect_socket_af(int af, int sockfd, const char *ip, uint16_t port)
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
	ssize_t res;
	int success;

	do {
		success = 1;
		res = sendto(sockfd, buf, len, 0, addr, addr ? AF_SOCKLEN(af) : 0);
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

static int tuntap_alloc(char *ifname, int flags)
{
	const char *clonedev = "/dev/net/tun";
	struct ifreq ifr;
	int fd;

	fd = open(clonedev, O_RDWR);
	if (fd < 0) {
		log_perror(clonedev);
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;
	if (*ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
		log_perror("ioctl TUNSETIFF");
		close(fd);
		return -1;
	}
	strcpy(ifname, ifr.ifr_name);
	log_mesg(LOG_INFO, "Created dev %s", ifname);
	return fd;
}

static int set_if_option(const char *ifname, struct ifreq *ifr, int opt)
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_perror("socket");
		return -1;
	}
	strncpy(ifr->ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(sockfd, opt, (void *)ifr) < 0) {
		log_perror("ioctl");
		close(sockfd);
		return -1;
	}
	close(sockfd);
	return 0;
}

static int set_if_up(const char *ifname, int flags)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_UP | flags;
	return set_if_option(ifname, &ifr, SIOCSIFFLAGS);
}

static int set_if_mtu(const char *ifname, int mtu)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	return set_if_option(ifname, &ifr, SIOCSIFMTU);
}

static int set_if_qlen(const char *ifname, int qlen)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_qlen = qlen;
	return set_if_option(ifname, &ifr, SIOCSIFTXQLEN);
}

static int set_if_address(const char *ifname, const char *address)
{
	int res;
	struct sockaddr_in *addr;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	res = inet_pton(AF_INET, address, &addr->sin_addr);
	if (res <= 0) {
		log_mesg(LOG_ERR, "inet_pton: Invalid IPv4 address");
		return -1;
	}
	return set_if_option(ifname, &ifr, SIOCSIFADDR);
}

static int set_if_netmask(const char *ifname, const char *netmask)
{
	int res;
	struct sockaddr_in *addr;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	addr->sin_family = AF_INET;
	res = inet_pton(AF_INET, netmask, &addr->sin_addr);
	if (res <= 0) {
		log_mesg(LOG_ERR, "inet_pton: Invalid IPv4 netmask");
		return -1;
	}
	return set_if_option(ifname, &ifr, SIOCSIFNETMASK);
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

int create_tun_if(char *tun_name)
{
	return tuntap_alloc(tun_name, IFF_TUN | IFF_NO_PI);
}

int create_tap_if(char *tap_name)
{
	return tuntap_alloc(tap_name, IFF_TAP | IFF_NO_PI);
}

int setup_tun_if(const char *ifname, const char *addr, const char *mask)
{
	int res;
	res = set_if_up(ifname, IFF_NOARP);
	if (res < 0) {
		log_mesg(LOG_ERR, "set dev %s up failed", ifname);
		return -1;
	}
	res = set_if_mtu(ifname, TUN_IF_MTU);
	if (res < 0) {
		log_mesg(LOG_ERR, "set dev %s mtu failed", ifname);
		return -1;
	}
	res = set_if_qlen(ifname, TUN_IF_QLEN);
	if (res < 0) {
		log_mesg(LOG_ERR, "set dev %s qlen failed", ifname);
		return -1;
	}
	res = set_if_address(ifname, addr);
	if (res < 0) {
		log_mesg(LOG_ERR, "set dev %s address failed", ifname);
		return -1;
	}
	res = set_if_netmask(ifname, mask);
	if (res < 0) {
		log_mesg(LOG_ERR, "set dev %s netmask failed", ifname);
		return -1;
	}
	return 0;
}

ssize_t send_tun(int tunfd, const void *buf, size_t len)
{
	ssize_t res;
	res = write(tunfd, buf, len);
	if (res < 0) {
		log_perror("write tun device");
		return -1;
	}
	return res;
}

ssize_t recv_tun(int tunfd, void *buf, size_t len)
{
	ssize_t res;
	res = read(tunfd, buf, len);
	if (res < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
			log_perror("read tun device");
			return -1;
		}
		res = 0;
	}
	if (!res)
		log_mesg(LOG_NOTICE, "received no data on tun device");
	return res;
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
		if (ihl < 5 || ihl > 15 || ip_checksum((uint16_t *)ip_header, ihl * 4))
			return 0;
	}
	return 1;
}

int write_icmp_echo(void *buf, const struct icmp_echo_param *param)
{
	struct iphdr *ip_header;
	struct icmphdr *icmp_header;
	uint8_t *echo_data;
	uint16_t total_len;

	ip_header = (void *)buf;
	icmp_header = (void *)((char *)ip_header + sizeof(struct iphdr));
	echo_data = (void *)((char *)icmp_header + sizeof(struct icmphdr));
	total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + PING_DATA_LEN;

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
		(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
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
