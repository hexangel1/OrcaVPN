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

struct vpn_peer {
	uint32_t private_ip;
	uint8_t point_id;
	uint8_t inet_on;
	uint8_t lan_on;
	void *encrypt_key;
	time_t last_update;
	struct sockaddr_in addr;
};

struct vpnserver {
	int tunfd;
	int sockfd;
	int reload_flag;

	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];

	char tun_name[MAX_IF_NAME_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];

	uint32_t private_ip;
	uint32_t private_mask;

	uint8_t peers_count;
	uint8_t point_id_map[PEERS_LIMIT];
	struct vpn_peer *peers[PEERS_LIMIT];

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

static struct vpn_peer *get_peer_by_id(struct vpnserver *serv, uint8_t point_id)
{
	return serv->peers[serv->point_id_map[point_id]];
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

static struct vpn_peer *alloc_peer(
	uint8_t point_id,
	const char *ip,
	const char *cipher_key,
	uint8_t inet_on,
	uint8_t lan_on)
{
	uint8_t bin_cipher_key[64];
	void *encrypt_key;
	size_t keylen = strlen(cipher_key);
	uint32_t private_ip;
	struct vpn_peer *peer;

	private_ip = inet_network(ip);
	if (private_ip == (uint32_t)-1) {
		log_mesg(LOG_ERR, "peer %u: bad ip address: %s", point_id, ip);
		return NULL;
	}
	if (keylen > sizeof(bin_cipher_key) * 2) {
		log_mesg(LOG_ERR, "peer %u: cipher key too long", point_id);
		return NULL;
	}
	if (!binarize(cipher_key, keylen, bin_cipher_key)) {
		log_mesg(LOG_ERR, "peer %u: cipher key has not hex format", point_id);
		return NULL;
	}
	encrypt_key = gen_encrypt_key(bin_cipher_key, keylen / 2);
	if (!encrypt_key) {
		log_mesg(LOG_ERR, "peer %u: encrypt keygen failed", point_id);
		return NULL;
	}

	peer = malloc(sizeof(struct vpn_peer));
	memset(peer, 0, sizeof(struct vpn_peer));
	peer->private_ip = private_ip;
	peer->point_id = point_id;
	peer->inet_on = inet_on;
	peer->lan_on = lan_on;
	peer->encrypt_key = encrypt_key;
	return peer;
}

static int create_peer(struct vpnserver *serv, uint8_t point_id,
	const char *ip, const char *cipher_key, int inet, int lan)
{
	struct vpn_peer *peer;
	hashstring_t ip_key;

	if (serv->peers_count == PEERS_LIMIT - 1) {
		log_mesg(LOG_ERR, "peer %u: too many peers", point_id);
		return -1;
	}
	if (serv->point_id_map[point_id] != 0xFF) {
		log_mesg(LOG_ERR, "peer %u: already exists, duplicated id", point_id);
		return -1;
	}

	peer = alloc_peer(point_id, ip, cipher_key, inet, lan);
	if (!peer)
		return -1;

	serv->point_id_map[point_id] = serv->peers_count;
	serv->peers[serv->peers_count++] = peer;

	ip_key.data = (uint8_t *)&peer->private_ip;
	ip_key.len = 4;
	hashmap_insert(serv->vpn_ip_hash, &ip_key, point_id);
	return 0;
}

static int is_private_peer(struct vpnserver *serv, uint32_t ip)
{
	uint32_t private_net = serv->private_ip & serv->private_mask;
	if (ip != serv->private_ip && ip != private_net)
		return ip_in_network(ip, private_net, serv->private_mask);
	return 0;
}

static void log_drop_packet(const char *mesg, uint32_t src_ip, uint32_t dst_ip)
{
	char src_addr[MAX_IPV4_ADDR_LEN];
	char dst_addr[MAX_IPV4_ADDR_LEN];

	ipv4tosb(src_ip, 1, src_addr);
	ipv4tosb(dst_ip, 1, dst_addr);

	log_mesg(LOG_NOTICE, "packet from %s to %s dropped: %s",
		src_addr, dst_addr, mesg);
}

static int route_packet(struct vpnserver *serv, struct vpn_peer *src,
	void *buf, size_t len)
{
	ssize_t res;
	uint32_t dest_ip, src_ip = src->private_ip;

	dest_ip = get_destination_ip(buf, len);
	if (is_private_peer(serv, dest_ip)) {
		struct vpn_peer *dest = get_peer_by_addr(serv, dest_ip);
		if (!dest || !dest->last_update) {
			log_drop_packet("destination not found", src_ip, dest_ip);
			return -1;
		}
		if (!src->lan_on) {
			log_drop_packet("source lan disabled", src_ip, dest_ip);
			return -1;
		}
		if (!dest->lan_on) {
			log_drop_packet("destination lan disabled", src_ip, dest_ip);
			return -1;
		}
		if (get_unix_time() > dest->last_update + PEER_ADDR_EXPIRE) {
			log_drop_packet("destination address expired", src_ip, dest_ip);
			return -1;
		}
		len += PACKET_SIGNATURE_LEN;
		encrypt_packet(buf, &len, dest->encrypt_key);
		res = send_udp(serv->sockfd, buf, len, &dest->addr);
	} else {
		if (!src->inet_on && dest_ip != serv->private_ip) {
			log_drop_packet("source inet disabled", src_ip, dest_ip);
			return -1;
		}
		res = send_tun(serv->tunfd, buf, len);
	}
	if (res < 0) {
		log_mesg(LOG_ERR, "forwarding client packet failed");
		return -1;
	}
	return 0;
}

static int socket_handler(struct vpnserver *serv)
{
	uint8_t buffer[PACKET_BUFFER_SIZE];
	struct sockaddr_in addr;
	struct vpn_peer *peer;
	ssize_t res;
	size_t length;
	uint8_t point_id;

	res = recv_udp(serv->sockfd, buffer, MAX_UDP_PAYLOAD, &addr);
	if (res < 0) {
		log_mesg(LOG_EMERG, "fatal error reading udp socket");
		exit(EXIT_FAILURE);
	}
	if (!res)
		return 0;

	log_ip_address(serv->ip_hash, &addr);
	length = res;
	point_id = buffer[--length];
	peer = get_peer_by_id(serv, point_id);
	if (!peer) {
		log_mesg(LOG_NOTICE, "peer %u not found", point_id);
		return -1;
	}
	decrypt_packet(buffer, &length, peer->encrypt_key);
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
	return route_packet(serv, peer, buffer, length);
}

static int tun_if_handler(struct vpnserver *serv)
{
	uint8_t buffer[PACKET_BUFFER_SIZE];
	struct vpn_peer *peer;
	ssize_t res;
	size_t length;
	uint32_t src_ip, dest_ip;

	res = recv_tun(serv->tunfd, buffer, TUN_IF_MTU);
	if (res < 0) {
		log_mesg(LOG_EMERG, "fatal error reading tun device");
		exit(EXIT_FAILURE);
	}
	if (!res)
		return 0;

	length = res;
	src_ip = get_source_ip(buffer, length);
	dest_ip = get_destination_ip(buffer, length);
	if (!src_ip || !dest_ip) {
		log_mesg(LOG_NOTICE, "dropped not ipv4 packet");
		return -1;
	}
	peer = get_peer_by_addr(serv, dest_ip);
	if (!peer || !peer->last_update) {
		log_drop_packet("destination not found", src_ip, dest_ip);
		return -1;
	}
	if (!peer->inet_on && src_ip != serv->private_ip) {
		log_drop_packet("destination inet disabled", src_ip, dest_ip);
		return -1;
	}
	if (get_unix_time() > peer->last_update + PEER_ADDR_EXPIRE) {
		log_drop_packet("destination address expired", src_ip, dest_ip);
		return -1;
	}
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, peer->encrypt_key);
	res = send_udp(serv->sockfd, buffer, length, &peer->addr);
	if (res < 0) {
		log_mesg(LOG_ERR, "forwarding tun packet failed");
		return -1;
	}
	return 0;
}

static int sigevent_handler(struct vpnserver *serv)
{
	switch (get_signal_event()) {
	case sigevent_reload:
		serv->reload_flag = 1;
		/* fallthrough */
	case sigevent_stop:
		return -1;
	case sigevent_absent:
		;
	}
	return 0;
}

static void vpn_server_handle(struct vpnserver *serv)
{
	fd_set readfds;
	sigset_t sigmask;
	int res, nfds = MAX(serv->tunfd, serv->sockfd) + 1;

	setup_signal_events(&sigmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(serv->tunfd, &readfds);
		FD_SET(serv->sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, NULL, &sigmask);
		if (res < 0) {
			if (errno != EINTR) {
				log_perror("pselect");
				break;
			}
			res = sigevent_handler(serv);
			if (res < 0)
				break;
			continue;
		}
		if (FD_ISSET(serv->tunfd, &readfds))
			tun_if_handler(serv);
		if (FD_ISSET(serv->sockfd, &readfds))
			socket_handler(serv);
	}
	restore_signal_mask(&sigmask);
}

#define ADD_PEER_ERROR(message, peer) \
	do { \
		has_errors = 1; \
		current_peer_ok = 0; \
		log_mesg(LOG_ERR, "[%s] " message, (peer)->scope); \
	} while (0)

static int add_peers(struct vpnserver *serv, struct config_section *cfg)
{
	struct config_section *peer;
	const char *private_ip, *cipher_key;
	uint8_t point_id;
	int res, inet, lan, has_errors = 0;

	serv->peers_count = 0;
	memset(serv->peers, 0, sizeof(serv->peers));
	memset(serv->point_id_map, 0xFF, sizeof(serv->point_id_map));

	for (peer = cfg; peer; peer = peer->next) {
		int current_peer_ok = 1;
		point_id = get_int_var(peer, "point_id");
		private_ip = get_str_var(peer, "private_ip", MAX_IPV4_ADDR_LEN - 1);
		cipher_key = get_var_value(peer, "cipher_key");
		inet = get_bool_var(peer, "inet");
		lan = get_bool_var(peer, "lan");

		if (!private_ip)
			ADD_PEER_ERROR("private ip not set", peer);
		if (!cipher_key)
			ADD_PEER_ERROR("cipher key not set", peer);
		if (inet < 0)
			ADD_PEER_ERROR("bad inet option value", peer);
		if (lan < 0)
			ADD_PEER_ERROR("bad lan option value", peer);
		if (!current_peer_ok)
			continue;

		res = create_peer(serv, point_id, private_ip, cipher_key, inet, lan);
		if (res < 0)
			ADD_PEER_ERROR("create peer failed", peer);
	}
	return has_errors ? -1 : 0;
}

#define CONFIG_ERROR(message) \
	do { \
		free_server(serv); \
		free_config(config); \
		log_mesg(LOG_ERR, message); \
		return NULL; \
	} while (0)

static void free_server(struct vpnserver *serv)
{
	uint8_t i;
	if (!serv)
		return;
	for (i = 0; i < serv->peers_count; i++) {
		free(serv->peers[i]->encrypt_key);
		free(serv->peers[i]);
	}

	delete_map(serv->vpn_ip_hash);
	delete_map(serv->ip_hash);
	free(serv);
}

static struct vpnserver *create_server(const char *file)
{
	struct vpnserver *serv = NULL;
	struct config_section *config;
	int port, res;
	const char *ip, *tun_name, *tun_addr, *tun_netmask;

	config = read_config(file);
	if (!config)
		return NULL;

	port = get_int_var(config, "port");
	ip = get_str_var(config, "ip", MAX_IPV4_ADDR_LEN - 1);
	if (!ip)
		CONFIG_ERROR("ip var not set");

	tun_name = get_str_var(config, "tun_name", MAX_IF_NAME_LEN - 1);
	tun_addr = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN - 1);
	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN - 1);

	serv = malloc(sizeof(struct vpnserver));
	memset(serv, 0, sizeof(struct vpnserver));

	strcpy(serv->ip_addr, ip);
	strcpy(serv->tun_name, tun_name ? tun_name : TUN_IF_NAME);
	strcpy(serv->tun_addr, tun_addr ? tun_addr : TUN_IF_ADDR);
	strcpy(serv->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_NETMASK);

	serv->tunfd = -1;
	serv->sockfd = -1;
	serv->reload_flag = 0;
	serv->private_ip = inet_network(serv->tun_addr);
	serv->private_mask = inet_network(serv->tun_netmask);
	serv->port = port ? port : VPN_PORT;
	serv->vpn_ip_hash = make_map();
	serv->ip_hash = make_map();

	res = add_peers(serv, config->next);
	if (res < 0)
		CONFIG_ERROR("adding peers failed");

	free_config(config);
	return serv;
}

static int vpn_server_up(struct vpnserver *serv)
{
	int res;
	res = create_tun_if(serv->tun_name);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Allocating interface failed");
		return -1;
	}
	serv->tunfd = res;
	log_mesg(LOG_INFO, "Created dev %s", serv->tun_name);
	res = setup_tun_if(serv->tun_name, serv->tun_addr, serv->tun_netmask);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Setting up %s failed", serv->tun_name);
		return -1;
	}
	res = create_udp_socket(serv->ip_addr, serv->port);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Create socket failed");
		return -1;
	}
	serv->sockfd = res;
	set_nonblock_io(serv->tunfd);
	set_nonblock_io(serv->sockfd);
	return 0;
}

static void vpn_server_down(struct vpnserver *serv)
{
	close(serv->tunfd);
	close(serv->sockfd);
	free_server(serv);
}

void run_vpnserver(const char *config)
{
	struct vpnserver *serv;
	int res, reload;

reload_server:
	serv = create_server(config);
	if (!serv) {
		log_mesg(LOG_EMERG, "Failed to create server configuration");
		exit(EXIT_FAILURE);
	}
	res = vpn_server_up(serv);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Failed to bring server up");
		exit(EXIT_FAILURE);
	}

	log_mesg(LOG_INFO, "Running server...");
	vpn_server_handle(serv);
	reload = serv->reload_flag;
	vpn_server_down(serv);
	if (reload) {
		log_rotate();
		log_mesg(LOG_INFO, "Reloading server...");
		goto reload_server;
	}
	log_mesg(LOG_INFO, "Gracefully finished");
}
