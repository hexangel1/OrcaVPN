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

#define PEERS_LIMIT 256
#define PEER_ADDR_EXPIRE 600

typedef unsigned char point_id_t;

struct vpn_peer {
	uint32_t private_ip;
	point_id_t point_id;
	struct sockaddr_in addr;
	time_t last_update;
	void *cipher_key;
};

struct vpnserver {
	int tunfd;
	int sockfd;
	uint32_t private_ip;
	uint32_t private_mask;
	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];
	char tun_name[MAX_IF_NAME_LEN];
	struct vpn_peer peers[PEERS_LIMIT];
	uint8_t point_id_map[PEERS_LIMIT];
	uint8_t peers_count;
	hashmap_t *vpn_ip_hash;
	hashmap_t *ip_hash;
};

static void log_ip_address(hashmap_t *ip_hash, struct sockaddr_in *addr)
{
	uint32_t ip_addr = addr->sin_addr.s_addr;
	uint64_t counter;
	hashstring_t ip_key;

	ip_key.data = (uint8_t *)&ip_addr;
	ip_key.len = 4;
	counter = hashmap_get(ip_hash, &ip_key);
	if (counter != HASHMAP_MISS) {
		hashmap_insert(ip_hash, &ip_key, ++counter);
		if (counter % 100000 == 0)
			log_mesg(LOG_NOTICE, "received %lu datagram from %s",
				counter, ipv4tos(ip_addr, 0));
	} else {
		hashmap_insert(ip_hash, &ip_key, 1);
		log_mesg(LOG_INFO, "received datagram from %s", ipv4tos(ip_addr, 0));
	}
}

static struct vpn_peer *get_peer_by_id(struct vpnserver *serv, point_id_t point_id)
{
	uint8_t idx = serv->point_id_map[point_id];
	return idx < serv->peers_count ? &serv->peers[idx] : NULL;
}

static struct vpn_peer *get_peer_by_addr(struct vpnserver *serv, uint32_t vpn_ip)
{
	uint64_t point_id;
	hashstring_t ip_key;

	ip_key.data = (uint8_t *)&vpn_ip;
	ip_key.len = 4;
	point_id = hashmap_get(serv->vpn_ip_hash, &ip_key);
	if (point_id == HASHMAP_MISS)
		return NULL;
	return get_peer_by_id(serv, point_id);
}

static void push_new_peer(struct vpnserver *serv, point_id_t point_id,
	const char *ip, const char *key)
{
	uint8_t cipher_key[CIPHER_KEY_LEN];
	hashstring_t ip_key;
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
	if (serv->peers_count == PEERS_LIMIT - 1) {
		log_mesg(LOG_ERR, "too many peers, ignoring peer %u", point_id);
		return;
	}
	if (serv->point_id_map[point_id] != 0xFF) {
		log_mesg(LOG_ERR, "peer with same id %u already exists", point_id);
		return;
	}
	serv->point_id_map[point_id] = serv->peers_count;
	peer = &serv->peers[serv->peers_count++];
	peer->private_ip = vpn_ip;
	peer->point_id = point_id;
	peer->last_update = 0;
	peer->cipher_key = get_expanded_key(cipher_key);
	ip_key.data = (uint8_t *)&vpn_ip;
	ip_key.len = 4;
	hashmap_insert(serv->vpn_ip_hash, &ip_key, point_id);
}

static int is_private_peer(struct vpnserver *serv, uint32_t ip)
{
	uint32_t private_net = serv->private_ip & serv->private_mask;
	if (ip == serv->private_ip || ip == private_net)
		return 0;
	return ip_in_network(ip, private_net, serv->private_mask);
}

static int proxy_packet(struct vpnserver *serv, void *buf, size_t len)
{
	ssize_t res;
	uint32_t ip = get_destination_ip(buf, len);
	if (is_private_peer(serv, ip)) {
		struct vpn_peer *peer = get_peer_by_addr(serv, ip);
		if (!peer || !peer->last_update) {
			log_mesg(LOG_NOTICE, "peer %s not found", ipv4tos(ip, 1));
			return -1;
		}
		if (get_unix_time() > peer->last_update + PEER_ADDR_EXPIRE) {
			log_mesg(LOG_NOTICE, "peer %s address expired", ipv4tos(ip, 1));
			return -1;
		}
		len += PACKET_SIGNATURE_LEN;
		encrypt_packet(buf, &len, peer->cipher_key);
		res = send_udp(serv->sockfd, buf, len, &peer->addr);
		if (res == -1) {
			log_mesg(LOG_ERR, "sending packet failed");
			return -1;
		}
	} else {
		res = write(serv->tunfd, buf, len);
		if (res == -1) {
			log_perror("write to tun failed");
			return -1;
		}
	}
	return 0;
}

static int socket_handler(struct vpnserver *serv)
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
	peer->last_update = get_unix_time();
	memcpy(&peer->addr, &addr, sizeof(struct sockaddr_in));
	return proxy_packet(serv, buffer, length);
}

static int tun_if_handler(struct vpnserver *serv)
{
	ssize_t res;
	size_t length;
	uint32_t vpn_ip;
	struct vpn_peer *peer;
	char buffer[PACKET_BUFFER_SIZE];
	res = read(serv->tunfd, buffer, TUN_IF_MTU);
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
	if (!peer || !peer->last_update) {
		log_mesg(LOG_NOTICE, "peer %s not found", ipv4tos(vpn_ip, 1));
		return -1;
	}
	if (get_unix_time() > peer->last_update + PEER_ADDR_EXPIRE) {
		log_mesg(LOG_NOTICE, "peer %s address expired", ipv4tos(vpn_ip, 1));
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
			tun_if_handler(serv);
		if (FD_ISSET(serv->sockfd, &readfds))
			socket_handler(serv);
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
	serv->private_ip = inet_network(serv->tun_addr);
	serv->private_mask = inet_network(serv->tun_netmask);
	serv->port = port ? port : VPN_PORT;
	serv->vpn_ip_hash = make_map();
	serv->ip_hash = make_map();
	serv->peers_count = 0;
	memset(serv->peers, 0, sizeof(serv->peers));
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
	res = setup_tun_if(serv->tun_name, serv->tun_addr, serv->tun_netmask);
	if (res == -1) {
		log_mesg(LOG_ERR, "Setting up %s failed", serv->tun_name);
		return -1;
	}
	set_nonblock_io(serv->sockfd);
	set_nonblock_io(serv->tunfd);
	return 0;
}

static void vpn_server_down(struct vpnserver *serv)
{
	uint8_t i;
	for (i = 0; i < serv->peers_count; i++)
		free(serv->peers[i].cipher_key);
	delete_map(serv->vpn_ip_hash);
	delete_map(serv->ip_hash);
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
