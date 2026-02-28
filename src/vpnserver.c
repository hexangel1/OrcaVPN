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
#include "bytetrie.h"

#define PEERS_LIMIT 256
#define PEER_ADDR_EXPIRE 600
#define IP_MEMORY_LIMIT 1000000
#define GET_PEER_ID(ip) ((ip) & 0xff)

struct vpn_peer {
	uint32_t private_ip;
	crypto_key *encrypt_key;
	int inet_on;
	int lan_on;
	time_t last_update;
	struct sockaddr_in addr;
};

struct orcavpn_server {
	struct event_selector loop;

	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];

	char tun_name[MAX_IF_NAME_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];

	unsigned int block_ip_ttl;

	uint32_t private_ip;
	uint32_t private_mask;

	int peers_count;
	unsigned char peer_id_map[PEERS_LIMIT];
	struct vpn_peer *peers[PEERS_LIMIT];

	struct byte_trie *ip_trie;
	struct byte_trie *blocked_ip_trie;

	unsigned long ip_counter;
	unsigned long blocked_ip_counter;
};

static int check_ip(struct orcavpn_server *serv,
	const struct sockaddr_in *addr)
{
	uint32_t ip = addr->sin_addr.s_addr;
	unsigned char *ip_bytes = (unsigned char *)&ip;
	trie_leaf_t *leaf;

	if (serv->ip_counter > IP_MEMORY_LIMIT) {
		serv->ip_counter = 0;
		clear_trie(serv->ip_trie);
		log_mesg(log_lvl_warn, "ip trie was cleared");
	}

	leaf = trie_set(serv->ip_trie, ip_bytes, sizeof(ip));
	leaf->ival++;

	if (leaf->ival % 100000 == 0) {
		log_mesg(log_lvl_normal, "received %lu packets from %s",
			leaf->ival, ipv4tos(ip, 0));
	} else if (leaf->ival == 1) {
		serv->ip_counter++;
		log_mesg(log_lvl_info, "Received packet from %s",
			ipv4tos(ip, 0));
	}

	leaf = trie_get(serv->blocked_ip_trie, ip_bytes, sizeof(ip));
	if (!leaf)
		return 0;

	if ((time_t)leaf->ival > get_unix_time())
		return 1;

	serv->blocked_ip_counter--;
	trie_del(serv->blocked_ip_trie, ip_bytes, sizeof(ip));
	log_mesg(log_lvl_normal, "ip address %s is unblocked", ipv4tos(ip, 0));
	return 0;
}

static void block_ip(struct orcavpn_server *serv,
	const struct sockaddr_in *addr)
{
	uint32_t ip = addr->sin_addr.s_addr;
	unsigned char *ip_bytes = (unsigned char *)&ip;
	trie_leaf_t *leaf;

	if (!serv->block_ip_ttl)
		return;

	if (serv->blocked_ip_counter > IP_MEMORY_LIMIT) {
		serv->blocked_ip_counter = 0;
		clear_trie(serv->blocked_ip_trie);
		log_mesg(log_lvl_warn, "blocked ip trie was cleared");
	}

	serv->blocked_ip_counter++;
	leaf = trie_set(serv->blocked_ip_trie, ip_bytes, sizeof(ip));
	leaf->ival = (trie_uint)get_unix_time() + serv->block_ip_ttl;
	log_mesg(log_lvl_normal, "ip address %s is blocked", ipv4tos(ip, 0));
}

static struct vpn_peer *
get_peer_by_id(struct orcavpn_server *serv, unsigned char peer_id)
{
	return serv->peers[serv->peer_id_map[peer_id]];
}

static struct vpn_peer *
get_peer_by_addr(struct orcavpn_server *serv, uint32_t vpn_ip)
{
	struct vpn_peer *peer = get_peer_by_id(serv, GET_PEER_ID(vpn_ip));
	return peer && peer->private_ip == vpn_ip ? peer : NULL;
}

static int is_private_peer(struct orcavpn_server *serv, uint32_t ip)
{
	uint32_t private_net = serv->private_ip & serv->private_mask;
	return ip != serv->private_ip && ip != private_net &&
		ip_in_network(ip, private_net, serv->private_mask);
}

static struct vpn_peer *alloc_peer(
	const char *name,
	uint32_t private_ip,
	const char *hex_key,
	const char *cipher_name,
	int inet_on,
	int lan_on)
{
	unsigned char bin_key[64];
	crypto_key *encrypt_key;
	size_t hex_keylen = strlen(hex_key);
	size_t keylen = hex_keylen / 2;
	crypto_key_type cipher;
	struct vpn_peer *peer;

	if (keylen > sizeof(bin_key)) {
		log_mesg(log_lvl_err, "peer %s: key too long", name);
		return NULL;
	}
	if (!binarize(hex_key, hex_keylen, bin_key)) {
		log_mesg(log_lvl_err, "peer %s: key has not hex format", name);
		return NULL;
	}

	cipher = crypto_key_parse_cipher(cipher_name);
	if (cipher < 0) {
		log_mesg(log_lvl_err, "peer %s: invalid cipher: %s",
			name, cipher_name);
		return NULL;
	}
	encrypt_key = crypto_key_create(bin_key, keylen, cipher);
	if (!encrypt_key) {
		log_mesg(log_lvl_err, "peer %s: cipher %s key create failed",
			name, cipher_name);
		return NULL;
	}

	peer = malloc(sizeof(struct vpn_peer));
	memset(peer, 0, sizeof(struct vpn_peer));
	peer->private_ip = private_ip;
	peer->encrypt_key = encrypt_key;
	peer->inet_on = inet_on;
	peer->lan_on = lan_on;
	return peer;
}

static int create_peer(struct orcavpn_server *serv, const char *name,
	const char *ip, const char *key, const char *cipher,
	int inet, int lan)
{
	struct vpn_peer *peer;
	uint32_t private_ip;

	private_ip = inet_network(ip);
	if (!is_private_peer(serv, private_ip)) {
		log_mesg(log_lvl_err, "peer %s: invalid tun ip: %s", name, ip);
		return -1;
	}
	if (serv->peers_count == PEERS_LIMIT - 1) {
		log_mesg(log_lvl_err, "peer %s: too many peers", name);
		return -1;
	}
	if (serv->peer_id_map[GET_PEER_ID(private_ip)] != 0xff) {
		log_mesg(log_lvl_err, "peer %s: already exists", name);
		return -1;
	}

	peer = alloc_peer(name, private_ip, key, cipher, inet, lan);
	if (!peer)
		return -1;

	serv->peer_id_map[GET_PEER_ID(private_ip)] = serv->peers_count;
	serv->peers[serv->peers_count++] = peer;
	return 0;
}

static void log_drop(const char *mesg, uint32_t src_ip, uint32_t dst_ip)
{
	char src_addr[MAX_IPV4_ADDR_LEN];
	char dst_addr[MAX_IPV4_ADDR_LEN];

	ipv4tosb(src_ip, 1, src_addr);
	ipv4tosb(dst_ip, 1, dst_addr);

	log_mesg(log_lvl_normal, "packet from %s to %s dropped: %s",
		src_addr, dst_addr, mesg);
}

static void update_remote_addr(struct vpn_peer *peer,
	const struct sockaddr_in *addr)
{
	char buf[MAX_IPV4_CONN_LEN];

	if (!peer->last_update || memcmp(&peer->addr, addr, sizeof(*addr))) {
		memcpy(&peer->addr, addr, sizeof(struct sockaddr_in));
		log_mesg(log_lvl_info, "Connection from %s",
			addr_to_str(addr, buf, sizeof(buf)));
	}
	peer->last_update = get_unix_time();
}

static ssize_t route_packet(struct orcavpn_server *serv, struct vpn_peer *src,
	void *buffer, size_t length)
{
	uint32_t src_ip = src->private_ip;
	uint32_t dst_ip = get_destination_ip(buffer);
	ssize_t res;

	if (is_private_peer(serv, dst_ip)) {
		struct vpn_peer *dst = get_peer_by_addr(serv, dst_ip);
		if (!dst || !dst->last_update) {
			log_drop("destination not found", src_ip, dst_ip);
			return 0;
		}
		if (!src->lan_on) {
			log_drop("source lan disabled", src_ip, dst_ip);
			return 0;
		}
		if (!dst->lan_on) {
			log_drop("destination lan disabled", src_ip, dst_ip);
			return 0;
		}
		if (get_unix_time() > dst->last_update + PEER_ADDR_EXPIRE) {
			log_drop("client address expired", src_ip, dst_ip);
			return 0;
		}
		encrypt_message(buffer, &length, dst->encrypt_key);
		res = send_udp(serv->loop.sockfd, buffer, length, &dst->addr);
	} else {
		if (dst_ip == (serv->private_ip & serv->private_mask)) {
			log_drop("destination not found", src_ip, dst_ip);
			return 0;
		}
		if (!src->inet_on && dst_ip != serv->private_ip) {
			log_drop("source inet disabled", src_ip, dst_ip);
			return 0;
		}
		res = send_tun(serv->loop.tunfd, buffer, length);
	}
	return res;
}

static void socket_handler(void *ctx)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct orcavpn_server *serv = ctx;
	struct vpn_peer *peer;
	struct sockaddr_in addr;
	unsigned char peer_id;
	size_t length;
	ssize_t res;

	res = recv_udp(serv->loop.sockfd, buffer, MAX_UDP_PAYLOAD, &addr);
	if (res < 0) {
		err_panic(&serv->loop, "reading udp socket");
		return;
	}
	if (!res || check_ip(serv, &addr))
		return;

	length = res;
	peer_id = buffer[--length];
	peer = get_peer_by_id(serv, peer_id);
	if (!peer) {
		log_mesg(log_lvl_normal, "peer %u not found", peer_id);
		block_ip(serv, &addr);
		return;
	}
	if (decrypt_message(buffer, &length, peer->encrypt_key)) {
		log_mesg(log_lvl_normal, "decrypt packet failed");
		block_ip(serv, &addr);
		return;
	}
	if (check_header_ipv4(buffer, length)) {
		log_mesg(log_lvl_normal, "udp packet with bad ip header");
		block_ip(serv, &addr);
		return;
	}
	if (get_source_ip(buffer) != peer->private_ip) {
		log_mesg(log_lvl_normal, "wrong peer private ip address");
		block_ip(serv, &addr);
		return;
	}
	update_remote_addr(peer, &addr);
	res = route_packet(serv, peer, buffer, length);
	if (res < 0)
		log_mesg(log_lvl_err, "forwarding packet from client failed");
}

static void tundev_handler(void *ctx)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct orcavpn_server *serv = ctx;
	struct vpn_peer *peer;
	uint32_t src_ip, dst_ip;
	size_t length;
	ssize_t res;

	res = recv_tun(serv->loop.tunfd, buffer, TUN_IF_MTU);
	if (res < 0) {
		err_panic(&serv->loop, "reading tun device");
		return;
	}
	if (!res)
		return;

	length = res;
	if (get_ip_version(buffer, length) != 4)
		return;
	if (check_header_ipv4(buffer, length)) {
		log_mesg(log_lvl_normal, "tun packet with bad ip header");
		return;
	}

	src_ip = get_source_ip(buffer);
	dst_ip = get_destination_ip(buffer);
	peer = get_peer_by_addr(serv, dst_ip);
	if (!peer || !peer->last_update) {
		log_drop("destination not found", src_ip, dst_ip);
		return;
	}
	if (!peer->inet_on && src_ip != serv->private_ip) {
		log_drop("destination inet disabled", src_ip, dst_ip);
		return;
	}
	if (get_unix_time() > peer->last_update + PEER_ADDR_EXPIRE) {
		log_drop("client address expired", src_ip, dst_ip);
		return;
	}

	encrypt_message(buffer, &length, peer->encrypt_key);
	res = send_udp(serv->loop.sockfd, buffer, length, &peer->addr);
	if (res < 0)
		log_mesg(log_lvl_err, "forwarding packet from tun failed");
}

#define ADD_PEER_ERROR(message, peer) \
	do { \
		has_errors = 1; \
		current_peer_ok = 0; \
		log_mesg(log_lvl_err, "[%s] " message, (peer)->scope); \
	} while (0)

static int add_peers(struct orcavpn_server *serv, struct config_section *cfg)
{
	struct config_section *peer;
	const char *ip, *key, *cipher;
	int res, inet, lan, has_errors = 0;

	serv->peers_count = 0;
	memset(serv->peers, 0, sizeof(serv->peers));
	memset(serv->peer_id_map, 0xff, sizeof(serv->peer_id_map));

	for (peer = cfg; peer; peer = peer->next) {
		int current_peer_ok = 1;
		ip     = get_str_var(peer, "ip", MAX_IPV4_ADDR_LEN);
		key    = get_var_value(peer, "key");
		cipher = get_var_value(peer, "cipher");
		inet   = get_bool_var(peer, "inet");
		lan    = get_bool_var(peer, "lan");

		if (!ip)
			ADD_PEER_ERROR("ip param not set", peer);
		if (!key)
			ADD_PEER_ERROR("key param not set", peer);
		if (!cipher)
			ADD_PEER_ERROR("cipher param not set", peer);
		if (inet < 0)
			ADD_PEER_ERROR("bad inet option value", peer);
		if (lan < 0)
			ADD_PEER_ERROR("bad lan option value", peer);
		if (!current_peer_ok)
			continue;

		res = create_peer(serv, peer->scope,
			ip, key, cipher, inet, lan);
		if (res < 0)
			ADD_PEER_ERROR("create peer failed", peer);
	}
	return has_errors ? -1 : 0;
}

#define CONFIG_ERROR(message) \
	do { \
		free_server(serv); \
		free_config(config); \
		log_mesg(log_lvl_err, "config error: " message); \
		return NULL; \
	} while (0)

static void free_server(struct orcavpn_server *serv)
{
	int i;

	if (!serv)
		return;

	for (i = 0; i < serv->peers_count; i++) {
		crypto_key_destroy(serv->peers[i]->encrypt_key);
		free(serv->peers[i]);
	}

	delete_trie(serv->ip_trie);
	delete_trie(serv->blocked_ip_trie);
	free(serv);
}

static struct orcavpn_server *create_server(const char *file)
{
	struct orcavpn_server *serv = NULL;
	struct config_section *config;
	int port, block_ip_ttl, res;
	const char *ip, *tun_name, *tun_addr, *tun_netmask;

	config = read_config(file);
	if (!config)
		return NULL;
	if (strcmp(config->scope, "server"))
		CONFIG_ERROR("expected server section");

	ip           = get_str_var(config, "ip", MAX_IPV4_ADDR_LEN);
	port         = get_int_var(config, "port");
	block_ip_ttl = get_int_var(config, "block_ip_ttl");
	tun_name     = get_str_var(config, "tun_name", MAX_IF_NAME_LEN);
	tun_addr     = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN);
	tun_netmask  = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN);

	if (!ip)
		ip = "0.0.0.0";
	if (!port)
		port = ORCAVPN_PORT;
	if (!tun_name)
		tun_name = TUN_IF_NAME;
	if (!tun_addr)
		tun_addr = TUN_IF_ADDR;
	if (!tun_netmask)
		tun_netmask = TUN_IF_MASK;

	serv = malloc(sizeof(struct orcavpn_server));
	memset(serv, 0, sizeof(struct orcavpn_server));
	init_event_selector(&serv->loop);

	strcpy(serv->ip_addr, ip);
	strcpy(serv->tun_name, tun_name);
	strcpy(serv->tun_addr, tun_addr);
	strcpy(serv->tun_netmask, tun_netmask);

	serv->private_ip = inet_network(serv->tun_addr);
	serv->private_mask = inet_network(serv->tun_netmask);
	serv->port = port;
	serv->block_ip_ttl = block_ip_ttl;

	serv->ip_trie = make_trie();
	serv->blocked_ip_trie = make_trie();

	res = add_peers(serv, config->next);
	if (res < 0)
		CONFIG_ERROR("adding peers failed");

	free_config(config);
	return serv;
}

static void set_event_handlers(struct orcavpn_server *serv)
{
	struct event_selector *loop = &serv->loop;

	loop->tundev_callback = tundev_handler;
	loop->socket_callback = socket_handler;
	loop->ctx = serv;
}

static int vpn_server_up(struct orcavpn_server *serv)
{
	struct event_selector *loop = &serv->loop;
	int res;

	res = create_tun_if(serv->tun_name);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Create tun if failed");
		return -1;
	}
	loop->tunfd = res;
	log_mesg(log_lvl_info, "Created tun if %s", serv->tun_name);
	res = setup_tun_if(serv->tun_name, serv->tun_addr, serv->tun_netmask);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Setup tun if failed");
		return -1;
	}
	res = create_udp_sock(serv->ip_addr, serv->port);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Create socket failed");
		return -1;
	}
	loop->sockfd = res;
	log_mesg(log_lvl_info, "Listen udp on %s",
		get_local_addr(loop->sockfd));
	set_max_sndbuf(loop->sockfd);
	set_max_rcvbuf(loop->sockfd);
	set_event_handlers(serv);
	return 0;
}

static void vpn_server_down(struct orcavpn_server *serv)
{
	close(serv->loop.tunfd);
	close(serv->loop.sockfd);
	free_server(serv);
}

int run_vpnserver(const char *config)
{
	struct orcavpn_server *serv;
	int res, reload, status;

reload_server:
	serv = create_server(config);
	if (!serv) {
		log_mesg(log_lvl_fatal, "Failed to create server");
		return 1;
	}
	res = vpn_server_up(serv);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Failed to bring server up");
		return 1;
	}
	event_loop(&serv->loop);
	reload = serv->loop.reload_flag;
	status = serv->loop.status_flag;
	vpn_server_down(serv);
	if (reload) {
		log_mesg(log_lvl_info, "Reloading configuration...");
		goto reload_server;
	}
	return status;
}
