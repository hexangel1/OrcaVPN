#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>

#include "vpnserver.h"
#include "network.h"
#include "encrypt/encryption.h"
#include "sigevent.h"
#include "configparser.h"
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
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];
	char tun_name[MAX_IF_NAME_LEN];
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

static void push_new_peer(struct vpnserver *serv, const char *ip, const char *key)
{
	uint8_t cipher_key[CIPHER_KEY_LEN];
	struct vpn_peer *peer;
	uint32_t vpn_ip = inet_network(ip);
	if (vpn_ip == (uint32_t)-1) {
		fprintf(stderr, "bad ip address: %s\n", ip);
		return;
	}
	if (strlen(key) != CIPHER_KEY_HEX_LEN) {
		fprintf(stderr, "invalid cipher key length\n");
		return;
	}
	if (!binarize(key, CIPHER_KEY_HEX_LEN, cipher_key)) {
		fprintf(stderr, "invalid cipher key format\n");
		return;
	}
	peer = array_push(serv->peers);
	peer->private_ip = vpn_ip;
	peer->cipher_key = get_expanded_key(cipher_key);
}

static int tun_if_forward(struct vpnserver *serv)
{
	ssize_t res;
	size_t length;
	uint8_t point_id;
	struct vpn_peer *peer;
	struct sockaddr_in addr;
	char buffer[PACKET_BUFFER_SIZE];
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
	if (!check_signature(buffer, &length)) {
		fprintf(stderr, "bad packet signature\n");
		return -1;
	}
	if (peer->private_ip != get_source_ip(buffer, length)) {
		fprintf(stderr, "wrong peer private ip address\n");
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
	char buffer[PACKET_BUFFER_SIZE];
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
	sign_packet(buffer, &length);
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

#define CONFIG_ERROR(message) \
	do { \
		free_config(config); \
		fputs(message "\n", stderr); \
		return NULL; \
	} while (0)

static struct vpnserver *create_server(const char *file)
{
	struct vpnserver *serv;
	struct config_section *client, *config;
	int port;
	const char *ip_addr, *tun_addr, *tun_netmask, *tun_name;
	const char *private_ip, *cipher_key;

	config = read_config(file);
	if (!config)
		return NULL;

	ip_addr = get_str_var(config, "ip_addr", MAX_IPV4_ADDR_LEN - 1);
	if (!ip_addr)
		CONFIG_ERROR("ip_addr var not set");

	tun_addr = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN - 1);
	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN - 1);
	tun_name = get_str_var(config, "tun_name", MAX_IF_NAME_LEN - 1);
	port = get_int_var(config, "port");

	serv = malloc(sizeof(struct vpnserver));
	memset(serv, 0, sizeof(struct vpnserver));

	strcpy(serv->ip_addr, ip_addr);
	strcpy(serv->tun_addr, tun_addr ? tun_addr : TUN_IF_ADDR);
	strcpy(serv->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_NETMASK);
	strcpy(serv->tun_name, tun_name ? tun_name : TUN_IF_NAME);

	serv->tunfd = -1;
	serv->sockfd = -1;
	serv->port = port ? port : VPN_PORT;
	serv->tun_mtu = TUN_MTU_SIZE;
	serv->peers = create_array_of(struct vpn_peer);

	for (client = config->next; client; client = client->next) {
		private_ip = get_str_var(client, "vpn_ip", MAX_IPV4_ADDR_LEN - 1);
		cipher_key = get_str_var(client, "cipher_key", CIPHER_KEY_HEX_LEN);
		if (private_ip && cipher_key)
			push_new_peer(serv, private_ip, cipher_key);
		else
			fprintf(stderr, "check section [%s]! \n", client->section_name);
	}

	free_config(config);
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

void run_vpnserver(const char *config)
{
	int res;
	struct vpnserver *serv;
	serv = create_server(config);
	if (!serv) {
		fprintf(stderr, "Failed to create init server\n");
		exit(EXIT_FAILURE);
	}
	res = vpn_server_up(serv);
	if (res == -1) {
		fprintf(stderr, "Failed to bring server up\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Running server...\n");
	vpn_server_handle(serv);
	vpn_server_down(serv);
	fprintf(stderr, "Gracefully finished\n");
}
