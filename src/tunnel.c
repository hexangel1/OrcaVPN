#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include "tunnel.h"
#include "logger.h"

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
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int res;

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
	struct ifreq ifr;
	struct sockaddr_in *addr;
	int res;

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
	ssize_t res = write(tunfd, buf, len);
	if (res < 0) {
		log_perror("write tun device");
		return -1;
	}
	return res;
}

ssize_t recv_tun(int tunfd, void *buf, size_t len)
{
	ssize_t res = read(tunfd, buf, len);
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
