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
#include "carray.h"

struct vpn_peer {
	uint32_t private_ip;
	void *cipher_key;
	int is_addr_valid;
	struct sockaddr_in addr;
};

struct vpnserver {
	int tunfd;
	int sockfd;
	unsigned short port;
	char ip_addr[MAX_IPV4_ADDRLEN];
	char tun_addr[MAX_IPV4_ADDRLEN];
	char tun_netmask[MAX_IPV4_ADDRLEN];
	char tun_name[IFNAMSIZ];
	int tun_mtu;
	carray_t *peers;
};

static struct vpn_peer *get_peer_by_addr(struct vpnserver *serv, uint32_t vpn_ip)
{
	struct vpn_peer *peers = serv->peers->items;
	size_t i, npeers = serv->peers->nitems;
	for (i = 0; i < npeers; i++) {
		if (peers[i].private_ip == vpn_ip)
			return &peers[i];
	}
	return NULL;
}

static void push_new_peer(struct vpnserver *serv, uint32_t vpn_ip, const void *key)
{
	struct vpn_peer *peer = array_push(serv->peers);
	peer->private_ip = vpn_ip;
	peer->cipher_key = get_expanded_key(key);
}

static int tun_if_forward(struct vpnserver *serv)
{
	ssize_t res;
	size_t length;
	uint8_t point_id;
	struct vpn_peer *peer;
	struct sockaddr_in addr;
	char buffer[TUN_MTU_SIZE_MAX];
	res = recv_udp(serv->sockfd, buffer, MAX_UDP_PAYLOAD, &addr);
	if (res == -1) {
		fprintf(stderr, "receiving packet failed\n");
		return -1;
	}
	length = res;
	point_id = buffer[--length];
	peer = array_get(serv->peers, point_id);
	if (!peer) {
		fprintf(stderr, "peer %u not found\n", point_id);
		return -1;
	}
	decrypt_packet(buffer, &length, peer->cipher_key);
	if (!check_signature(buffer, length, NULL)) {
		fprintf(stderr, "bad packet signature\n");
		return -1;
	}
	peer->is_addr_valid = 1;
	memcpy(&peer->addr, &addr, sizeof(struct sockaddr_in));
	res = write(serv->tunfd, buffer, length);
	if (res == -1) {
		perror("write to tun failed");
		return -1;
	}
	return 0;
}

static int sockfd_forward(struct vpnserver *serv)
{
	ssize_t res;
	size_t length;
	uint32_t vpn_ip;
	struct vpn_peer *peer;
	char buffer[TUN_MTU_SIZE_MAX];
	res = read(serv->tunfd, buffer, serv->tun_mtu);
	if (res <= 0) {
		perror("read from tun failed");
		return -1;
	}
	length = res;
	vpn_ip = get_destination_ip(buffer, length);
	if (!vpn_ip) {
		fprintf(stderr, "bad vpn ip address\n");
		return -1;
	}
	peer = get_peer_by_addr(serv, vpn_ip);
	if (!peer || !peer->is_addr_valid) {
		fprintf(stderr, "peer remote address not found\n");
		return -1;
	}
	sign_packet(buffer, &length, NULL);
	encrypt_packet(buffer, &length, peer->cipher_key);
	res = send_udp(serv->sockfd, buffer, length, &peer->addr);
	if (res == -1) {
		fprintf(stderr, "sending packet failed\n");
		return -1;
	}
	return 0;
}

static void vpn_server_handle(struct vpnserver *serv)
{
	fd_set readfds;
	sigset_t origmask;
	int res, nfds = MAX(serv->tunfd, serv->sockfd) + 1;

	setup_signal_events(&origmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(serv->tunfd, &readfds);
		FD_SET(serv->sockfd, &readfds);
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
		if (FD_ISSET(serv->tunfd, &readfds))
			sockfd_forward(serv);
		if (FD_ISSET(serv->sockfd, &readfds))
			tun_if_forward(serv);
	}
}

static struct vpnserver *create_server(const char *config)
{
	struct vpnserver *serv;
	(void)config;
	serv = malloc(sizeof(struct vpnserver));
	memset(serv, 0, sizeof(struct vpnserver));
	serv->tunfd = -1;
	serv->sockfd = -1;
	serv->port = VPN_PORT;
	strcpy(serv->ip_addr, "192.168.1.10");
	strcpy(serv->tun_addr, TUN_IF_ADDR);
	strcpy(serv->tun_netmask, TUN_IF_NETMASK);
	strcpy(serv->tun_name, TUN_IF_NAME);
	serv->tun_mtu = TUN_MTU_SIZE;
	serv->peers = create_array_of(struct vpn_peer);
	init_encryption(16);
	push_new_peer(serv, inet_network("10.0.0.2"), "token12345678900");
	return serv;
}

static int vpn_server_up(struct vpnserver *serv)
{
	int res;
	res = create_udp_socket(serv->ip_addr, serv->port);
	if (res == -1) {
		fprintf(stderr, "Create socket failed\n");
		return -1;
	}
	serv->sockfd = res;
	res = create_tun_if(serv->tun_name);
	if (res == -1) {
		fprintf(stderr, "Allocating interface failed\n");
		return -1;
	}
	serv->tunfd = res;
	fprintf(stderr, "created dev %s\n", serv->tun_name);
	res = setup_tun_if(serv->tun_name, serv->tun_addr, serv->tun_netmask, serv->tun_mtu);
	if (res == -1) {
		fprintf(stderr, "Setting up %s failed\n", serv->tun_name);
		return -1;
	}
	nonblock_io(serv->sockfd);
	nonblock_io(serv->tunfd);
	return 0;
}

static void vpn_server_down(struct vpnserver *serv)
{
	size_t i, npeers = serv->peers->nitems;
	struct vpn_peer *peers = serv->peers->items;
	for (i = 0; i < npeers; i++)
		free(peers[i].cipher_key);
	array_destroy(serv->peers);
	close(serv->sockfd);
	close(serv->tunfd);
	free(serv);
}

int main()
{
	struct vpnserver *serv = create_server("vpn.conf");
	int res = vpn_server_up(serv);
	if (res == -1) {
		fprintf(stderr, "Failed to bring server up\n");
		exit(1);
	}
	fprintf(stderr, "Running server...\n");
	vpn_server_handle(serv);
	vpn_server_down(serv);
	fprintf(stderr, "Gracefully finished\n");
	return 0;
}
