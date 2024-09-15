#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "network.h"
#include "encryption.h"
#include "sigevent.h"
#include "helper.h"

struct vpnclient {
	int tunfd;
	int sockfd;
	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];
	char tun_name[MAX_IF_NAME_LEN];
	int tun_mtu;
	unsigned short server_port;
	char server_ip[MAX_IPV4_ADDR_LEN];
	void *cipher_key;
	uint32_t private_ip;
	uint8_t point_id;
};

static int tun_if_forward(struct vpnclient *clnt)
{
	ssize_t res;
	size_t length;
	char buffer[TUN_MTU_SIZE_MAX];
	res = recv_udp(clnt->sockfd, buffer, MAX_UDP_PAYLOAD, NULL);
	if (res == -1) {
		fprintf(stderr, "receiving packet failed\n");
		return -1;
	}
	length = res;
	decrypt_packet(buffer, &length, clnt->cipher_key);
	if (!check_signature(buffer, length)) {
		fprintf(stderr, "bad packet signature\n");
		return -1;
	}
	res = write(clnt->tunfd, buffer, length);
	if (res == -1) {
		perror("write to tun failed");
		return -1;
	}
	return 0;
}

static int sockfd_forward(struct vpnclient *clnt)
{
	ssize_t res;
	size_t length;
	char buffer[TUN_MTU_SIZE_MAX];
	res = read(clnt->tunfd, buffer, TUN_MTU_SIZE);
	if (res <= 0) {
		perror("read from tun failed");
		return -1;
	}
	length = res;
	if (clnt->private_ip != get_source_ip(buffer, length))
		return -1;
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, clnt->cipher_key);
	buffer[length++] = clnt->point_id;
	res = send_udp(clnt->sockfd, buffer, length, NULL);
	if (res == -1) {
		fprintf(stderr, "sending packet failed\n");
		return -1;
	}
	return 0;
}

static void vpn_client_handle(struct vpnclient *clnt)
{
	fd_set readfds;
	sigset_t origmask;
	int res, nfds = MAX(clnt->tunfd, clnt->sockfd) + 1;

	setup_signal_events(&origmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(clnt->tunfd, &readfds);
		FD_SET(clnt->sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, NULL, &origmask);
		if (res == -1) {
			if (errno != EINTR) {
				perror("pselect");
				break;
			}
			res = get_signal_event();
			if (res == sigevent_shutdown)
				break;
			continue;
		}
		if (FD_ISSET(clnt->tunfd, &readfds))
			sockfd_forward(clnt);
		if (FD_ISSET(clnt->sockfd, &readfds))
			tun_if_forward(clnt);
	}
}

static struct vpnclient *create_client(const char *config)
{
	struct vpnclient *clnt;
	(void)config;
	clnt = malloc(sizeof(struct vpnclient));
	memset(clnt, 0, sizeof(struct vpnclient));
	clnt->tunfd = -1;
	clnt->sockfd = -1;
	clnt->port = VPN_PORT;
	strcpy(clnt->ip_addr, "192.168.1.9");
	strcpy(clnt->tun_addr, "10.0.0.2");
	strcpy(clnt->tun_netmask, TUN_IF_NETMASK);
	strcpy(clnt->tun_name, TUN_IF_NAME);
	clnt->tun_mtu = TUN_MTU_SIZE;
	clnt->server_port = VPN_PORT;
	strcpy(clnt->server_ip, "192.168.1.10");
	clnt->point_id = 0;
	clnt->private_ip = inet_network(clnt->tun_addr);
	init_encryption(16);
	clnt->cipher_key = get_expanded_key("token12345678900");
	return clnt;
}

static int vpn_client_up(struct vpnclient *clnt)
{
	int res;
	res = create_udp_socket(clnt->ip_addr, clnt->port);
	if (res == -1) {
		fprintf(stderr, "Create socket failed\n");
		return -1;
	}
	clnt->sockfd = res;
	res = socket_connect(clnt->sockfd, clnt->server_ip, clnt->server_port);
	if (res == -1) {
		fprintf(stderr, "Connection failed\n");
		return -1;
	}
	res = create_tun_if(clnt->tun_name);
	if (res == -1) {
		fprintf(stderr, "Allocating interface failed\n");
		return -1;
	}
	clnt->tunfd = res;
	fprintf(stderr, "created dev %s\n", clnt->tun_name);
	res = setup_tun_if(clnt->tun_name, clnt->tun_addr, clnt->tun_netmask, clnt->tun_mtu);
	if (res == -1) {
		fprintf(stderr, "Setting up %s failed\n", clnt->tun_name);
		return -1;
	}
	nonblock_io(clnt->sockfd);
	nonblock_io(clnt->tunfd);
	return 0;
}

static void vpn_client_down(struct vpnclient *clnt)
{
	close(clnt->sockfd);
	close(clnt->tunfd);
	free(clnt->cipher_key);
	free(clnt);
}

int main()
{
	struct vpnclient *clnt = create_client("vpn.conf");
	int res = vpn_client_up(clnt);
	if (res == -1) {
		fprintf(stderr, "Failed to bring client up\n");
		exit(1);
	}
	fprintf(stderr, "Running client...\n");
	vpn_client_handle(clnt);
	vpn_client_down(clnt);
	fprintf(stderr, "Gracefully finished\n");
	return 0;
}
