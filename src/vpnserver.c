#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vpnserver.h"
#include "eventloop.h"
#include "network.h"
#include "tunnel.h"
#include "encryption.h"
#include "configparser.h"
#include "logger.h"
#include "helper.h"
#include "hashmap.h"

#define PEERS_LIMIT 256
#define PEER_ADDR_EXPIRE 600
#define HASH_SIZE_LIMIT 96000

struct vpn_peer {
	uint32_t private_ip;
	unsigned char point_id;
	int inet_on;
	int lan_on;
	void *encrypt_key;
	time_t last_update;
	struct sockaddr_in addr;
};

struct vpnserver {
	struct event_listener loop;

	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];

	char tun_name[MAX_IF_NAME_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];

	unsigned int block_ip_ttl;

	uint32_t private_ip;
	uint32_t private_mask;

	int peers_count;
	unsigned char point_id_map[PEERS_LIMIT];
	struct vpn_peer *peers[PEERS_LIMIT];

	hashmap *ip_hash;
	hashmap *vpn_ip_hash;
	hashmap *blocked_ip_hash;
};

static void clear_hash_if_large(hashmap *hash)
{
	if (hash->used <= HASH_SIZE_LIMIT)
		return;
	clear_map(hash);
	log_mesg(LOG_WARNING, "hash has grown too large and was cleared");
}

static int throttle_packet(struct vpnserver *serv, struct sockaddr_in *addr)
{
	uint32_t ip = addr->sin_addr.s_addr;
	hashmap_key ip_key;
	hashmap_val ip_val, ip_counter;

	clear_hash_if_large(serv->ip_hash);

	HASHMAP_KEY_INT(ip_key, ip);
	ip_counter = hashmap_inc(serv->ip_hash, &ip_key, 1);
	if (ip_counter > 1) {
		if (ip_counter % 100000 == 0)
			log_mesg(LOG_NOTICE, "received %lu packets from %s",
				ip_counter, ipv4tos(ip, 0));
	} else {
		log_mesg(LOG_INFO, "received packet from %s", ipv4tos(ip, 0));
	}

	ip_val = hashmap_get(serv->blocked_ip_hash, &ip_key);
	if (ip_val == HASHMAP_MISS)
		return 0;

	if ((time_t)ip_val > get_unix_time())
		return 1;

	hashmap_delete(serv->blocked_ip_hash, &ip_key);
	log_mesg(LOG_NOTICE, "ip address %s is unblocked", ipv4tos(ip, 0));
	return 0;
}

static void block_ip(struct vpnserver *serv, struct sockaddr_in *addr)
{
	uint32_t ip = addr->sin_addr.s_addr;
	hashmap_key ip_key;
	hashmap_val ip_val;

	if (!serv->block_ip_ttl)
		return;

	clear_hash_if_large(serv->blocked_ip_hash);

	HASHMAP_KEY_INT(ip_key, ip);
	ip_val = (hashmap_val)get_unix_time() + serv->block_ip_ttl;
	hashmap_insert(serv->blocked_ip_hash, &ip_key, ip_val);
	log_mesg(LOG_NOTICE, "ip address %s is blocked", ipv4tos(ip, 0));
}

static struct vpn_peer *
get_peer_by_id(struct vpnserver *serv, unsigned char point_id)
{
	return serv->peers[serv->point_id_map[point_id]];
}

static struct vpn_peer *
get_peer_by_addr(struct vpnserver *serv, uint32_t vpn_ip)
{
	hashmap_val point_id;
	hashmap_key ip_key;

	HASHMAP_KEY_INT(ip_key, vpn_ip);
	point_id = hashmap_get(serv->vpn_ip_hash, &ip_key);
	if (point_id == HASHMAP_MISS)
		return NULL;
	return get_peer_by_id(serv, point_id);
}

static struct vpn_peer *alloc_peer(
	unsigned char point_id,
	const char *ip,
	const char *cipher_key,
	int inet_on,
	int lan_on)
{
	unsigned char bin_cipher_key[64];
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
		log_mesg(LOG_ERR, "peer %u: key too long", point_id);
		return NULL;
	}
	if (!binarize(cipher_key, keylen, bin_cipher_key)) {
		log_mesg(LOG_ERR, "peer %u: key has not hex format", point_id);
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

static int create_peer(struct vpnserver *serv, unsigned char point_id,
	const char *ip, const char *cipher_key, int inet, int lan)
{
	struct vpn_peer *peer;
	hashmap_key ip_key;

	if (serv->peers_count == PEERS_LIMIT - 1) {
		log_mesg(LOG_ERR, "peer %u: too many peers", point_id);
		return -1;
	}
	if (serv->point_id_map[point_id] != 0xff) {
		log_mesg(LOG_ERR, "peer %u: already exists", point_id);
		return -1;
	}

	peer = alloc_peer(point_id, ip, cipher_key, inet, lan);
	if (!peer)
		return -1;

	serv->point_id_map[point_id] = serv->peers_count;
	serv->peers[serv->peers_count++] = peer;

	HASHMAP_KEY_INT(ip_key, peer->private_ip);
	hashmap_insert(serv->vpn_ip_hash, &ip_key, point_id);
	return 0;
}

static int is_private_peer(struct vpnserver *serv, uint32_t ip)
{
	uint32_t private_net = serv->private_ip & serv->private_mask;
	return ip != serv->private_ip && ip != private_net &&
		ip_in_network(ip, private_net, serv->private_mask);
}

static void log_drop(const char *mesg, uint32_t src_ip, uint32_t dst_ip)
{
	char src_addr[MAX_IPV4_ADDR_LEN];
	char dst_addr[MAX_IPV4_ADDR_LEN];

	ipv4tosb(src_ip, 1, src_addr);
	ipv4tosb(dst_ip, 1, dst_addr);

	log_mesg(LOG_NOTICE, "packet from %s to %s dropped: %s",
		src_addr, dst_addr, mesg);
}

static void route_packet(struct vpnserver *serv, struct vpn_peer *src,
	void *buffer, size_t length)
{
	ssize_t res;
	uint32_t src_ip = src->private_ip;
	uint32_t dest_ip = get_destination_ip(buffer);

	if (is_private_peer(serv, dest_ip)) {
		struct vpn_peer *dest = get_peer_by_addr(serv, dest_ip);
		if (!dest || !dest->last_update) {
			log_drop("destination not found", src_ip, dest_ip);
			return;
		}
		if (!src->lan_on) {
			log_drop("source lan disabled", src_ip, dest_ip);
			return;
		}
		if (!dest->lan_on) {
			log_drop("destination lan disabled", src_ip, dest_ip);
			return;
		}
		if (get_unix_time() > dest->last_update + PEER_ADDR_EXPIRE) {
			log_drop("client address expired", src_ip, dest_ip);
			return;
		}
		length += PACKET_SIGNATURE_LEN;
		encrypt_packet(buffer, &length, dest->encrypt_key);
		res = send_udp(serv->loop.sockfd, buffer, length, &dest->addr);
	} else {
		if (!src->inet_on && dest_ip != serv->private_ip) {
			log_drop("source inet disabled", src_ip, dest_ip);
			return;
		}
		res = send_tun(serv->loop.tunfd, buffer, length);
	}
	if (res < 0)
		log_mesg(LOG_ERR, "forwarding packet from client failed");
}

static void socket_handler(void *ctx)
{
	struct vpnserver *serv = ctx;
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct sockaddr_in addr;
	struct vpn_peer *peer;
	unsigned char point_id;
	ssize_t res;
	size_t length;

	res = recv_udp(serv->loop.sockfd, buffer, MAX_UDP_PAYLOAD, &addr);
	if (res < 0) {
		err_panic(&serv->loop, "reading udp socket");
		return;
	}
	if (!res || throttle_packet(serv, &addr))
		return;

	length = res;
	point_id = buffer[--length];
	peer = get_peer_by_id(serv, point_id);
	if (!peer) {
		log_mesg(LOG_NOTICE, "peer %u not found", point_id);
		block_ip(serv, &addr);
		return;
	}
	decrypt_packet(buffer, &length, peer->encrypt_key);
	if (!check_signature(buffer, &length)) {
		log_mesg(LOG_NOTICE, "bad packet signature");
		block_ip(serv, &addr);
		return;
	}
	if (!check_ipv4_packet(buffer, length, 0)) {
		log_mesg(LOG_NOTICE, "invalid ipv4 packet from socket");
		block_ip(serv, &addr);
		return;
	}
	if (peer->private_ip != get_source_ip(buffer)) {
		log_mesg(LOG_NOTICE, "wrong peer private ip address");
		block_ip(serv, &addr);
		return;
	}
	peer->last_update = get_unix_time();
	memcpy(&peer->addr, &addr, sizeof(struct sockaddr_in));
	route_packet(serv, peer, buffer, length);
}

static void tun_if_handler(void *ctx)
{
	struct vpnserver *serv = ctx;
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct vpn_peer *peer;
	ssize_t res;
	size_t length;
	uint32_t src_ip, dest_ip;

	res = recv_tun(serv->loop.tunfd, buffer, TUN_IF_MTU);
	if (res < 0) {
		err_panic(&serv->loop, "reading tun device");
		return;
	}
	if (!res)
		return;

	length = res;
	if (!check_ipv4_packet(buffer, length, 1)) {
		log_mesg(LOG_NOTICE, "bad ipv4 packet from tun");
		return;
	}
	src_ip = get_source_ip(buffer);
	dest_ip = get_destination_ip(buffer);
	peer = get_peer_by_addr(serv, dest_ip);
	if (!peer || !peer->last_update) {
		log_drop("destination not found", src_ip, dest_ip);
		return;
	}
	if (!peer->inet_on && src_ip != serv->private_ip) {
		log_drop("destination inet disabled", src_ip, dest_ip);
		return;
	}
	if (get_unix_time() > peer->last_update + PEER_ADDR_EXPIRE) {
		log_drop("client address expired", src_ip, dest_ip);
		return;
	}
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, peer->encrypt_key);
	res = send_udp(serv->loop.sockfd, buffer, length, &peer->addr);
	if (res < 0)
		log_mesg(LOG_ERR, "forwarding packet from tun failed");
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
	const char *ip, *cipher_key;
	int res, point_id, inet, lan, has_errors = 0;

	serv->peers_count = 0;
	memset(serv->peers, 0, sizeof(serv->peers));
	memset(serv->point_id_map, 0xff, sizeof(serv->point_id_map));

	for (peer = cfg; peer; peer = peer->next) {
		int current_peer_ok = 1;
		point_id = get_int_var(peer, "point_id");
		ip = get_str_var(peer, "private_ip", MAX_IPV4_ADDR_LEN);
		cipher_key = get_var_value(peer, "cipher_key");
		inet = get_bool_var(peer, "inet");
		lan = get_bool_var(peer, "lan");

		if (point_id > 0xff || point_id < 0)
			ADD_PEER_ERROR("invalid point_id", peer);
		if (!ip)
			ADD_PEER_ERROR("private ip not set", peer);
		if (!cipher_key)
			ADD_PEER_ERROR("cipher key not set", peer);
		if (inet < 0)
			ADD_PEER_ERROR("bad inet option value", peer);
		if (lan < 0)
			ADD_PEER_ERROR("bad lan option value", peer);
		if (!current_peer_ok)
			continue;

		res = create_peer(serv, point_id, ip, cipher_key, inet, lan);
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
	int i;

	if (!serv)
		return;

	for (i = 0; i < serv->peers_count; i++) {
		free(serv->peers[i]->encrypt_key);
		free(serv->peers[i]);
	}

	delete_map(serv->ip_hash);
	delete_map(serv->vpn_ip_hash);
	delete_map(serv->blocked_ip_hash);
	free(serv);
}

static struct vpnserver *create_server(const char *file)
{
	struct vpnserver *serv = NULL;
	struct config_section *config;
	int port, block_ip_ttl, res;
	const char *ip, *tun_name, *tun_addr, *tun_netmask;

	config = read_config(file);
	if (!config)
		return NULL;

	port = get_int_var(config, "port");
	block_ip_ttl = get_int_var(config, "block_ip_ttl");
	ip = get_str_var(config, "ip", MAX_IPV4_ADDR_LEN);
	if (!ip)
		CONFIG_ERROR("ip var not set");

	tun_name = get_str_var(config, "tun_name", MAX_IF_NAME_LEN);
	tun_addr = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN);
	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN);

	serv = malloc(sizeof(struct vpnserver));
	memset(serv, 0, sizeof(struct vpnserver));
	init_event_listener(&serv->loop);

	strcpy(serv->ip_addr, ip);
	strcpy(serv->tun_name, tun_name ? tun_name : TUN_IF_NAME);
	strcpy(serv->tun_addr, tun_addr ? tun_addr : TUN_IF_ADDR);
	strcpy(serv->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_MASK);

	serv->private_ip = inet_network(serv->tun_addr);
	serv->private_mask = inet_network(serv->tun_netmask);
	serv->port = port ? port : VPN_PORT;
	serv->block_ip_ttl = block_ip_ttl;

	serv->ip_hash = make_map();
	serv->vpn_ip_hash = make_map();
	serv->blocked_ip_hash = make_map();

	res = add_peers(serv, config->next);
	if (res < 0)
		CONFIG_ERROR("adding peers failed");

	free_config(config);
	return serv;
}

static void set_event_handlers(struct vpnserver *serv)
{
	struct event_listener *loop = &serv->loop;

	loop->tun_if_callback = tun_if_handler;
	loop->socket_callback = socket_handler;
	loop->ctx = serv;
}

static int vpn_server_up(struct vpnserver *serv)
{
	struct event_listener *loop = &serv->loop;
	int res;

	res = create_tun_if(serv->tun_name);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Allocating interface failed");
		return -1;
	}
	loop->tunfd = res;
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
	loop->sockfd = res;
	log_mesg(LOG_INFO, "Listen udp on %s:%u",
		get_local_bind_addr(loop->sockfd),
		get_local_bind_port(loop->sockfd));
	set_max_sndbuf(loop->sockfd);
	set_max_rcvbuf(loop->sockfd);
	set_event_handlers(serv);
	return 0;
}

static void vpn_server_down(struct vpnserver *serv)
{
	close(serv->loop.tunfd);
	close(serv->loop.sockfd);
	free_server(serv);
}

int run_vpnserver(const char *config)
{
	struct vpnserver *serv;
	int res, reload, status;

reload_server:
	serv = create_server(config);
	if (!serv) {
		log_mesg(LOG_EMERG, "Failed to create server configuration");
		return 1;
	}
	res = vpn_server_up(serv);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Failed to bring server up");
		return 1;
	}
	event_loop(&serv->loop);
	reload = serv->loop.reload_flag;
	status = serv->loop.status_flag;
	vpn_server_down(serv);
	if (reload) {
		log_mesg(LOG_INFO, "Reloading configuration...");
		goto reload_server;
	}
	return status;
}
