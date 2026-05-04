#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vpnclient.h"
#include "eventloop.h"
#include "network.h"
#include "ipproto.h"
#include "tunnel.h"
#include "encryption.h"
#include "configparser.h"
#include "logger.h"
#include "helper.h"

#define KEEPALIVE_INTVL_DEFAULT 30 /* 30 seconds */
#define KEEPALIVE_PROBES_DEFAULT 0 /* infinite probes */
#define GET_PEER_ID(ip) ((ip) & 0xff)

struct orcavpn_client {
	struct event_selector loop;

	char server_ip[IPV4_ADDR_LEN];
	unsigned short server_port;
	unsigned short port;

	char tun_name[TUN_IF_NAMSIZ];
	char tun_addr[IPV4_ADDR_LEN];
	char tun_mask[IPV4_ADDR_LEN];
	int  tun_persist;

	uint32_t private_ip;
	uint32_t router_ip;

	crypto_key *encrypt_key;

	int junk_count;
	int junk_min;
	int junk_max;

	int keepalive_intvl;
	int keepalive_probes;
	int no_responded_pings;

	unsigned short sequance_id;
	unsigned short sequance_no;
};

static unsigned char get_magic_byte(void)
{
	return get_rand_from(0x80, 0xff);
}

static int fill_junk_data(unsigned char *buf, int junk_min, int junk_max)
{
	int i, junk_len = get_rand_from(junk_min, junk_max);

	for (i = 0; i < junk_len; i++)
		buf[i] = get_rand_from('!', '~');

	return junk_len;
}

static void send_junk_packets(struct orcavpn_client *clnt)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	int i, len, res;

	for (i = 0; i < clnt->junk_count; i++) {
		len = fill_junk_data(buffer, clnt->junk_min, clnt->junk_max);
		res = send_udp(clnt->loop.sockfd, buffer, len, NULL);
		if (res < 0)
			log_mesg(log_lvl_err, "sending junk packet failed");
		proc_delay_us(get_rand_from(500, 1500));
	}
}

static void send_keepalive_ping(struct orcavpn_client *clnt)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct icmp_echo_param icmp_echo;
	size_t length;
	ssize_t res;

	icmp_echo.src_ip = clnt->private_ip;
	icmp_echo.dst_ip = clnt->router_ip;
	icmp_echo.seq_id = clnt->sequance_id;
	icmp_echo.seq_no = clnt->sequance_no++;
	read_random(icmp_echo.data, PING_DATA_LEN);

	length = write_icmp_echo(buffer, &icmp_echo);
	encrypt_message(buffer, &length, clnt->encrypt_key);
	buffer[length++] = GET_PEER_ID(clnt->private_ip);
	buffer[length++] = get_magic_byte();

	res = send_udp(clnt->loop.sockfd, buffer, length, NULL);
	if (res < 0)
		log_mesg(log_lvl_err, "sending ping packet failed");

	clnt->no_responded_pings++;
}

static void alarm_handler(void *ctx)
{
	struct orcavpn_client *clnt = ctx;
	int keepalive_probes = clnt->keepalive_probes;

	if (!keepalive_probes || clnt->no_responded_pings < keepalive_probes) {
		send_keepalive_ping(clnt);
	} else {
		log_mesg(log_lvl_err, "connection to server lost");
		do_reload(&clnt->loop);
	}
}

static void socket_handler(void *ctx)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct orcavpn_client *clnt = ctx;
	size_t length;
	ssize_t res;

	res = recv_udp(clnt->loop.sockfd, buffer, MAX_UDP_PAYLOAD, NULL);
	if (res < 0) {
		err_panic(&clnt->loop, "reading udp socket");
		return;
	}
	if (!res)
		return;

	length = res;
	if (decrypt_message(buffer, &length, clnt->encrypt_key)) {
		log_mesg(log_lvl_normal, "decrypt packet failed");
		return;
	}
	if (check_header_ipv4(buffer, length)) {
		log_mesg(log_lvl_normal, "udp packet with bad ip header");
		return;
	}
	if (get_destination_ip(buffer) != clnt->private_ip) {
		log_mesg(log_lvl_normal, "bad destination ip address");
		return;
	}
	clnt->no_responded_pings = 0;
	res = send_tun(clnt->loop.tunfd, buffer, length);
	if (res < 0)
		log_mesg(log_lvl_err, "sending packet to tun failed");
}

static void tundev_handler(void *ctx)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct orcavpn_client *clnt = ctx;
	size_t length;
	ssize_t res;

	res = recv_tun(clnt->loop.tunfd, buffer, TUN_IF_MTU);
	if (res < 0) {
		err_panic(&clnt->loop, "reading tun device");
		return;
	}
	if (!res)
		return;

	length = res;
	if (get_ip_version(buffer, length) != 4)
		return;
	if (get_source_ip(buffer) != clnt->private_ip)
		return;
	if (check_header_ipv4(buffer, length)) {
		log_mesg(log_lvl_normal, "tun packet with bad ip header");
		return;
	}

	encrypt_message(buffer, &length, clnt->encrypt_key);
	buffer[length++] = GET_PEER_ID(clnt->private_ip);
	buffer[length++] = get_magic_byte();
	res = send_udp(clnt->loop.sockfd, buffer, length, NULL);
	if (res < 0)
		log_mesg(log_lvl_err, "sending packet to server failed");
}

#define CONFIG_ERROR(message) \
	do { \
		free_config(config); \
		log_mesg(log_lvl_err, "config error: " message); \
		return NULL; \
	} while (0)

static struct orcavpn_client *create_client(const char *file)
{
	struct orcavpn_client *clnt;
	struct config_section *config;
	unsigned char bin_key[64];
	size_t keylen, hex_keylen;
	unsigned short server_port, port;
	int junk_count, junk_min, junk_max;
	int keepalive_intvl, keepalive_probes;
	const char *server_ip, *router_ip;
	const char *tun_name, *tun_addr, *tun_mask;
	const char *hex_key, *cipher_name;
	crypto_key_type cipher;
	void *encrypt_key;

	config = read_config(file);
	if (!config)
		return NULL;
	if (strcmp(config->scope, "client"))
		CONFIG_ERROR("expected client section");
	if (config->next)
		CONFIG_ERROR("only client section is needed");

	server_ip   = get_str_var(config, "server_ip", IPV4_ADDR_LEN);
	server_port = get_int_var(config, "server_port");
	port        = get_int_var(config, "port");
	router_ip   = get_str_var(config, "router_ip", IPV4_ADDR_LEN);

	tun_name    = get_str_var(config, "tun_name", TUN_IF_NAMSIZ);
	tun_addr    = get_str_var(config, "tun_addr", IPV4_ADDR_LEN);
	tun_mask    = get_str_var(config, "tun_mask", IPV4_ADDR_LEN);

	hex_key     = get_var_value(config, "key");
	cipher_name = get_var_value(config, "cipher");

	junk_count  = get_int_var(config, "junk_count");
	junk_min    = get_int_var(config, "junk_min");
	junk_max    = get_int_var(config, "junk_max");

	keepalive_intvl  = get_int_var(config, "keepalive_intvl");
	keepalive_probes = get_int_var(config, "keepalive_probes");

	if (!server_ip)
		CONFIG_ERROR("server_ip param not set");
	if (!server_port)
		server_port = ORCAVPN_PORT;
	if (!router_ip)
		router_ip = TUN_IF_ADDR;
	if (!tun_name)
		tun_name = TUN_IF_NAME;
	if (!tun_addr)
		CONFIG_ERROR("tun_addr param not set");
	if (!tun_mask)
		tun_mask = TUN_IF_MASK;

	if (!hex_key)
		CONFIG_ERROR("key param not set");
	if (!cipher_name)
		CONFIG_ERROR("cipher param not set");

	if (junk_count) {
		if (junk_count < 0 || junk_count > 1000)
			CONFIG_ERROR("junk_count not in [0, 1000]");
		if (junk_min < 1 || junk_min > 128)
			CONFIG_ERROR("junk_min not in [1, 128]");
		if (junk_max < junk_min || junk_max > 1280)
			CONFIG_ERROR("junk_max not in [junk_min, 1280]");
	}

	if (keepalive_intvl < 1)
		keepalive_intvl = KEEPALIVE_INTVL_DEFAULT;
	if (keepalive_probes < 1)
		keepalive_probes = KEEPALIVE_PROBES_DEFAULT;

	hex_keylen = strlen(hex_key);
	keylen = hex_keylen / 2;
	if (keylen > sizeof(bin_key))
		CONFIG_ERROR("key too long");
	if (!binarize(hex_key, hex_keylen, bin_key))
		CONFIG_ERROR("key has not hex format");

	cipher = crypto_key_parse_cipher(cipher_name);
	if (cipher < 0)
		CONFIG_ERROR("invalid cipher selected");
	encrypt_key = crypto_key_create(bin_key, keylen, cipher);
	if (!encrypt_key)
		CONFIG_ERROR("encrypt key create failed");

	clnt = malloc(sizeof(struct orcavpn_client));
	memset(clnt, 0, sizeof(struct orcavpn_client));
	init_event_selector(&clnt->loop);

	strcpy(clnt->server_ip, server_ip);
	strcpy(clnt->tun_name, tun_name);
	strcpy(clnt->tun_addr, tun_addr);
	strcpy(clnt->tun_mask, tun_mask);

	clnt->server_port = server_port;
	clnt->port = port;
	clnt->tun_persist = (get_bool_var(config, "tun_persist") == 1);
	clnt->router_ip = inet_network(router_ip);
	clnt->private_ip = inet_network(tun_addr);
	clnt->encrypt_key = encrypt_key;
	clnt->junk_count = junk_count;
	clnt->junk_min = junk_min;
	clnt->junk_max = junk_max;
	clnt->keepalive_intvl = keepalive_intvl;
	clnt->keepalive_probes = keepalive_probes;
	clnt->no_responded_pings = 0;
	clnt->sequance_id = (0xffff & getpid());
	clnt->sequance_no = 0;

	free_config(config);
	return clnt;
}

static void set_event_handlers(struct orcavpn_client *clnt)
{
	struct event_selector *loop = &clnt->loop;

	loop->tundev_callback = tundev_handler;
	loop->socket_callback = socket_handler;
	loop->alarm_callback = alarm_handler;
	loop->alarm_interval = clnt->keepalive_intvl * 1000;
	loop->ctx = clnt;
}

static int vpn_client_up(struct orcavpn_client *clnt)
{
	struct event_selector *loop = &clnt->loop;
	int res;

	res = create_tun_if(clnt->tun_name, clnt->tun_persist);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Create tun if failed");
		return -1;
	}
	loop->tunfd = res;
	log_mesg(log_lvl_info, "Created tun if %s", clnt->tun_name);
	res = setup_tun_if(clnt->tun_name, clnt->tun_addr, clnt->tun_mask);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Setup tun if failed");
		return -1;
	}
	res = create_udp_sock("0.0.0.0", clnt->port);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Create socket failed");
		return -1;
	}
	loop->sockfd = res;
	res = connect_sock(loop->sockfd, clnt->server_ip, clnt->server_port);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Connection to server failed");
		return -1;
	}
	log_mesg(log_lvl_info, "Connected from %s to %s",
		get_local_addr(loop->sockfd), get_remote_addr(loop->sockfd));
	set_max_sndbuf(loop->sockfd);
	set_max_rcvbuf(loop->sockfd);
	set_event_handlers(clnt);
	send_junk_packets(clnt);
	send_keepalive_ping(clnt);
	return 0;
}

static void vpn_client_down(struct orcavpn_client *clnt)
{
	close(clnt->loop.tunfd);
	close(clnt->loop.sockfd);
	crypto_key_destroy(clnt->encrypt_key);
	free(clnt);
}

int run_vpnclient(const char *config)
{
	struct orcavpn_client *clnt;
	int res, reload, status;

reload_client:
	clnt = create_client(config);
	if (!clnt) {
		log_mesg(log_lvl_fatal, "Failed to create client");
		return 1;
	}
	res = vpn_client_up(clnt);
	if (res < 0) {
		log_mesg(log_lvl_fatal, "Failed to bring client up");
		return 1;
	}
	event_loop(&clnt->loop);
	reload = clnt->loop.reload_flag;
	status = clnt->loop.status_flag;
	vpn_client_down(clnt);
	if (reload) {
		log_mesg(log_lvl_info, "Reloading configuration...");
		goto reload_client;
	}
	return status;
}
