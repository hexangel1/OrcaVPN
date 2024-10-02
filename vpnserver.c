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
#include "logger.h"
#include "helper.h"
#include "hashmap.h"
#include "carray.h"

typedef unsigned char point_id_t;

struct vpn_peer {
	point_id_t point_id;
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
	uint8_t point_id_map[256];
	hashmap_t *vpn_ip_hash;
	hashmap_t *ip_hash;
	carray_t *peers;
};

static void log_ip_address(hashmap_t *ip_hash, struct sockaddr_in *addr)
{
	const char *ip_addr = ipv4_tostring(addr->sin_addr.s_addr, 0);
	uint64_t counter = hashmap_get(ip_hash, ip_addr);
	if (counter != HASHMAP_MISS) {
		hashmap_insert(ip_hash, ip_addr, ++counter);
		if (counter % 100000 == 0)
			log_mesg(LOG_NOTICE, "got %ld datagram from %s", counter, ip_addr);
	} else {
		hashmap_insert(ip_hash, ip_addr, 1);
		log_mesg(LOG_INFO, "received datagram from new address %s", ip_addr);
	}
}

static struct vpn_peer *get_peer_by_id(struct vpnserver *serv, point_id_t point_id)
{
	uint8_t idx = serv->point_id_map[point_id];
	if (idx == 0xFF)
		return NULL;
	return array_get(serv->peers, idx);
}

static struct vpn_peer *get_peer_by_addr(struct vpnserver *serv, uint32_t vpn_ip)
{
	uint64_t point_id = hashmap_get(serv->vpn_ip_hash, ipv4_tostring(vpn_ip, 1));
	if (point_id == HASHMAP_MISS)
		return NULL;
	return get_peer_by_id(serv, point_id);
}

static void push_new_peer(struct vpnserver *serv, point_id_t point_id,
	const char *ip, const char *key)
{
	uint8_t cipher_key[CIPHER_KEY_LEN];
	struct vpn_peer *peer;
	uint32_t vpn_ip = inet_network(ip);
	if (vpn_ip == (uint32_t)-1) {
		log_mesg(LOG_ERR, "bad ip address: %s", ip);
		return;
	}
	if (strlen(key) != CIPHER_KEY_HEX_LEN) {
		log_mesg(LOG_ERR, "invalid cipher key length");
		return;
	}
	if (!binarize(key, CIPHER_KEY_HEX_LEN, cipher_key)) {
		log_mesg(LOG_ERR, "invalid cipher key format");
		return;
	}
	peer = array_push(serv->peers);
	peer->point_id = point_id;
	peer->private_ip = vpn_ip;
	peer->cipher_key = get_expanded_key(cipher_key);
	hashmap_insert(serv->vpn_ip_hash, ip, point_id);
	serv->point_id_map[point_id] = serv->peers->nitems - 1;
}

static int tun_if_forward(struct vpnserver *serv)
{
	ssize_t res;
	size_t length;
	point_id_t point_id;
	struct vpn_peer *peer;
	struct sockaddr_in addr;
	char buffer[PACKET_BUFFER_SIZE];
	res = recv_udp(serv->sockfd, buffer, MAX_UDP_PAYLOAD, &addr);
	if (res == -1) {
		log_mesg(LOG_ERR, "receiving packet failed");
		return -1;
	}
	log_ip_address(serv->ip_hash, &addr);
	length = res;
	point_id = buffer[--length];
	peer = get_peer_by_id(serv, point_id);
	if (!peer) {
		log_mesg(LOG_NOTICE, "peer %u not found", point_id);
		return -1;
	}
	decrypt_packet(buffer, &length, peer->cipher_key);
	if (!check_signature(buffer, &length)) {
		log_mesg(LOG_NOTICE, "bad packet signature");
		return -1;
	}
	if (peer->private_ip != get_source_ip(buffer, length)) {
		log_mesg(LOG_NOTICE, "wrong peer private ip address");
		return -1;
	}
	peer->is_addr_valid = 1;
	memcpy(&peer->addr, &addr, sizeof(struct sockaddr_in));
	res = write(serv->tunfd, buffer, length);
	if (res == -1) {
		log_perror("write to tun failed");
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
		log_perror("read from tun failed");
		return -1;
	}
	length = res;
	vpn_ip = get_destination_ip(buffer, length);
	if (!vpn_ip) {
		log_mesg(LOG_NOTICE, "bad vpn ip address");
		return -1;
	}
	peer = get_peer_by_addr(serv, vpn_ip);
	if (!peer || !peer->is_addr_valid) {
		log_mesg(LOG_NOTICE, "peer remote address not found");
		return -1;
	}
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, peer->cipher_key);
	res = send_udp(serv->sockfd, buffer, length, &peer->addr);
	if (res == -1) {
		log_mesg(LOG_ERR, "sending packet failed");
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
				log_perror("pselect");
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
		log_mesg(LOG_ERR, message); \
		return NULL; \
	} while (0)

static struct vpnserver *create_server(const char *file)
{
	struct vpnserver *serv;
	struct config_section *client, *config;
	int port;
	point_id_t point_id;
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
	serv->vpn_ip_hash = make_map();
	serv->ip_hash = make_map();
	serv->peers = create_array_of(struct vpn_peer);
	memset(serv->point_id_map, 0xFF, sizeof(serv->point_id_map));

	for (client = config->next; client; client = client->next) {
		point_id = get_int_var(client, "point_id");
		private_ip = get_str_var(client, "vpn_ip", MAX_IPV4_ADDR_LEN - 1);
		cipher_key = get_str_var(client, "cipher_key", CIPHER_KEY_HEX_LEN);
		if (private_ip && cipher_key)
			push_new_peer(serv, point_id, private_ip, cipher_key);
		else
			log_mesg(LOG_WARNING, "check section [%s]!", client->section_name);
	}

	free_config(config);
	return serv;
}

static int vpn_server_up(struct vpnserver *serv)
{
	int res;
	res = create_udp_socket(serv->ip_addr, serv->port);
	if (res == -1) {
		log_mesg(LOG_ERR, "Create socket failed");
		return -1;
	}
	serv->sockfd = res;
	res = create_tun_if(serv->tun_name);
	if (res == -1) {
		log_mesg(LOG_ERR, "Allocating interface failed");
		return -1;
	}
	serv->tunfd = res;
	log_mesg(LOG_INFO, "created dev %s", serv->tun_name);
	res = setup_tun_if(serv->tun_name, serv->tun_addr, serv->tun_netmask, serv->tun_mtu);
	if (res == -1) {
		log_mesg(LOG_ERR, "Setting up %s failed", serv->tun_name);
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
	delete_map(serv->vpn_ip_hash);
	delete_map(serv->ip_hash);
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
		log_mesg(LOG_ERR, "Failed to create init server");
		exit(EXIT_FAILURE);
	}
	res = vpn_server_up(serv);
	if (res == -1) {
		log_mesg(LOG_ERR, "Failed to bring server up");
		exit(EXIT_FAILURE);
	}
	log_mesg(LOG_INFO, "Running server...");
	vpn_server_handle(serv);
	vpn_server_down(serv);
	log_mesg(LOG_INFO, "Gracefully finished");
}
