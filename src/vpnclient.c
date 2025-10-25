#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vpnclient.h"
#include "eventloop.h"
#include "network.h"
#include "tunnel.h"
#include "encryption.h"
#include "configparser.h"
#include "logger.h"
#include "helper.h"

#define IDLE_TIMEOUT 30
#define GET_PEER_ID(ip) ((ip) & 0xff)

struct vpnclient {
	struct event_listener loop;

	unsigned short port;
	unsigned short server_port;
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char server_ip[MAX_IPV4_ADDR_LEN];

	char tun_name[MAX_IF_NAME_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];

	uint32_t private_ip;
	uint32_t router_ip;

	crypto_key *encrypt_key;

	unsigned short sequance_id;
	unsigned short sequance_no;
};

static void ping_vpn_router(struct vpnclient *clnt)
{
	unsigned char buffer[PACKET_BUFFER_SIZE];
	struct icmp_echo_param icmp_echo;
	ssize_t res;
	size_t length;

	icmp_echo.src_ip = clnt->private_ip;
	icmp_echo.dst_ip = clnt->router_ip;
	icmp_echo.seq_id = clnt->sequance_id;
	icmp_echo.seq_no = clnt->sequance_no++;
	read_random(icmp_echo.data, PING_DATA_LEN);
	length = write_icmp_echo(buffer, &icmp_echo);
	encrypt_message(buffer, &length, clnt->encrypt_key);
	buffer[length++] = GET_PEER_ID(clnt->private_ip);
	res = send_udp(clnt->loop.sockfd, buffer, length, NULL);
	if (res < 0)
		log_mesg(LOG_ERR, "sending ping packet failed");
}

static void timeout_handler(void *ctx)
{
	ping_vpn_router((struct vpnclient *)ctx);
}

static void socket_handler(void *ctx)
{
	struct vpnclient *clnt = ctx;
	unsigned char buffer[PACKET_BUFFER_SIZE];
	ssize_t res;
	size_t length;

	res = recv_udp(clnt->loop.sockfd, buffer, MAX_UDP_PAYLOAD, NULL);
	if (res < 0) {
		err_panic(&clnt->loop, "reading udp socket");
		return;
	}
	if (!res)
		return;

	length = res;
	if (decrypt_message(buffer, &length, clnt->encrypt_key)) {
		log_mesg(LOG_NOTICE, "decrypt packet failed");
		return;
	}
	if (check_header_ipv4(buffer, length, 0)) {
		log_mesg(LOG_NOTICE, "udp packet with bad ip header");
		return;
	}
	if (get_destination_ip(buffer) != clnt->private_ip) {
		log_mesg(LOG_NOTICE, "bad destination ip address");
		return;
	}
	res = send_tun(clnt->loop.tunfd, buffer, length);
	if (res < 0)
		log_mesg(LOG_ERR, "sending packet to tun failed");
}

static void tundev_handler(void *ctx)
{
	struct vpnclient *clnt = ctx;
	unsigned char buffer[PACKET_BUFFER_SIZE];
	ssize_t res;
	size_t length;

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
	if (check_header_ipv4(buffer, length, 1)) {
		log_mesg(LOG_NOTICE, "tun packet with bad ip header");
		return;
	}

	encrypt_message(buffer, &length, clnt->encrypt_key);
	buffer[length++] = GET_PEER_ID(clnt->private_ip);
	res = send_udp(clnt->loop.sockfd, buffer, length, NULL);
	if (res < 0)
		log_mesg(LOG_ERR, "sending packet to server failed");
}

#define CONFIG_ERROR(message) \
	do { \
		free_config(config); \
		log_mesg(LOG_ERR, message); \
		return NULL; \
	} while (0)

static struct vpnclient *create_client(const char *file)
{
	struct vpnclient *clnt;
	struct config_section *config;
	unsigned char bin_key[64];
	size_t keylen, hex_keylen;
	int port, server_port;
	const char *ip, *server_ip, *router_ip;
	const char *tun_addr, *tun_netmask, *tun_name;
	const char *hex_key, *cipher_name;
	crypto_key_type cipher;
	void *encrypt_key;

	config = read_config(file);
	if (!config)
		return NULL;

	ip          = get_str_var(config, "ip", MAX_IPV4_ADDR_LEN);
	port        = get_int_var(config, "port");
	server_ip   = get_str_var(config, "server_ip", MAX_IPV4_ADDR_LEN);
	server_port = get_int_var(config, "server_port");
	router_ip   = get_str_var(config, "router_ip", MAX_IPV4_ADDR_LEN);

	tun_addr    = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN);
	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN);
	tun_name    = get_str_var(config, "tun_name", MAX_IF_NAME_LEN);

	hex_key     = get_var_value(config, "key");
	cipher_name = get_var_value(config, "cipher");

	if (!ip)
		ip = "0.0.0.0";
	if (!server_ip)
		CONFIG_ERROR("server_ip param not set");
	if (!server_port)
		server_port = VPN_PORT;
	if (!router_ip)
		router_ip = TUN_IF_ADDR;
	if (!tun_name)
		tun_netmask = TUN_IF_NAME;
	if (!tun_addr)
		CONFIG_ERROR("tun_addr param not set");
	if (!tun_netmask)
		tun_netmask = TUN_IF_MASK;

	if (!hex_key)
		CONFIG_ERROR("key param not set");
	if (!cipher_name)
		CONFIG_ERROR("cipher param not set");

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

	clnt = malloc(sizeof(struct vpnclient));
	memset(clnt, 0, sizeof(struct vpnclient));
	init_event_listener(&clnt->loop);

	strcpy(clnt->ip_addr, ip);
	strcpy(clnt->server_ip, server_ip);
	strcpy(clnt->tun_name, tun_name);
	strcpy(clnt->tun_addr, tun_addr);
	strcpy(clnt->tun_netmask, tun_netmask);

	clnt->port = port;
	clnt->server_port = server_port;
	clnt->router_ip = inet_network(router_ip);
	clnt->private_ip = inet_network(tun_addr);
	clnt->encrypt_key = encrypt_key;
	clnt->sequance_id = (0xffff & getpid());
	clnt->sequance_no = 0;

	free_config(config);
	return clnt;
}

static void set_event_handlers(struct vpnclient *clnt)
{
	struct event_listener *loop = &clnt->loop;

	loop->tundev_callback = tundev_handler;
	loop->socket_callback = socket_handler;
	loop->timeout_callback = timeout_handler;
	loop->timeout = IDLE_TIMEOUT * 1000;
	loop->ctx = clnt;
}

static int vpn_client_up(struct vpnclient *clnt)
{
	struct event_listener *loop = &clnt->loop;
	int res;

	res = create_tun_if(clnt->tun_name);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Allocating interface failed");
		return -1;
	}
	loop->tunfd = res;
	res = setup_tun_if(clnt->tun_name, clnt->tun_addr, clnt->tun_netmask);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Setting up %s failed", clnt->tun_name);
		return -1;
	}
	res = create_udp_socket(clnt->ip_addr, clnt->port);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Create socket failed");
		return -1;
	}
	loop->sockfd = res;
	res = connect_socket(loop->sockfd, clnt->server_ip, clnt->server_port);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Connection failed");
		return -1;
	}
	log_mesg(LOG_INFO, "Connected from %s:%u to %s:%u",
		get_local_bind_addr(loop->sockfd),
		get_local_bind_port(loop->sockfd),
		clnt->server_ip, clnt->server_port);
	set_max_sndbuf(loop->sockfd);
	set_max_rcvbuf(loop->sockfd);
	set_event_handlers(clnt);
	return 0;
}

static void vpn_client_down(struct vpnclient *clnt)
{
	close(clnt->loop.tunfd);
	close(clnt->loop.sockfd);
	crypto_key_destroy(clnt->encrypt_key);
	free(clnt);
}

int run_vpnclient(const char *config)
{
	struct vpnclient *clnt;
	int res, reload, status;

reload_client:
	clnt = create_client(config);
	if (!clnt) {
		log_mesg(LOG_EMERG, "Failed to create client configuration");
		return 1;
	}
	res = vpn_client_up(clnt);
	if (res < 0) {
		log_mesg(LOG_EMERG, "Failed to bring client up");
		return 1;
	}
	event_loop(&clnt->loop);
	reload = clnt->loop.reload_flag;
	status = clnt->loop.status_flag;
	vpn_client_down(clnt);
	if (reload) {
		log_mesg(LOG_INFO, "Reloading configuration...");
		goto reload_client;
	}
	return status;
}
