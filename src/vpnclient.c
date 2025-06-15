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

	void *encrypt_key;
	uint8_t point_id;

	uint16_t sequance_id;
	uint16_t sequance_no;
};

static void ping_vpn_router(struct vpnclient *clnt)
{
	uint8_t buffer[PACKET_BUFFER_SIZE];
	struct icmp_echo_param icmp_echo;
	ssize_t res;
	size_t length;

	icmp_echo.src_ip = clnt->private_ip;
	icmp_echo.dst_ip = clnt->router_ip;
	icmp_echo.seq_id = clnt->sequance_id;
	icmp_echo.seq_no = clnt->sequance_no++;
	read_random(icmp_echo.data, PING_DATA_LEN);
	length = write_icmp_echo(buffer, &icmp_echo);
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, clnt->encrypt_key);
	buffer[length++] = clnt->point_id;
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
	uint8_t buffer[PACKET_BUFFER_SIZE];
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
	decrypt_packet(buffer, &length, clnt->encrypt_key);
	if (!check_signature(buffer, &length)) {
		log_mesg(LOG_NOTICE, "bad packet signature");
		return;
	}
	if (!check_ipv4_packet(buffer, length, 0)) {
		log_mesg(LOG_NOTICE, "bad ipv4 packet from socket");
		return;
	}
	if (clnt->private_ip != get_destination_ip(buffer)) {
		log_mesg(LOG_NOTICE, "bad destination ip address");
		return;
	}
	res = send_tun(clnt->loop.tunfd, buffer, length);
	if (res < 0)
		log_mesg(LOG_ERR, "sending packet to tun failed");
}

static void tun_if_handler(void *ctx)
{
	struct vpnclient *clnt = ctx;
	uint8_t buffer[PACKET_BUFFER_SIZE];
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
	if (!check_ipv4_packet(buffer, length, 1)) {
		log_mesg(LOG_NOTICE, "bad ipv4 packet from tun");
		return;
	}
	if (clnt->private_ip != get_source_ip(buffer))
		return;
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, clnt->encrypt_key);
	buffer[length++] = clnt->point_id;
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
	uint8_t bin_cipher_key[64];
	size_t keylen;
	int port, server_port, point_id;
	const char *ip_addr, *server_ip, *router_ip, *cipher_key;
	const char *tun_addr, *tun_netmask, *tun_name;
	void *encrypt_key;

	config = read_config(file);
	if (!config)
		return NULL;

	ip_addr = get_str_var(config, "ip", MAX_IPV4_ADDR_LEN);
	if (!ip_addr)
		ip_addr = "0.0.0.0";
	router_ip = get_str_var(config, "router_ip", MAX_IPV4_ADDR_LEN);
	if (!router_ip)
		router_ip = TUN_IF_ADDR;
	server_ip = get_str_var(config, "server_ip", MAX_IPV4_ADDR_LEN);
	if (!server_ip)
		CONFIG_ERROR("server_ip var not set");
	tun_addr = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN);
	if (!tun_addr)
		CONFIG_ERROR("tun_addr var not set");
	cipher_key = get_var_value(config, "cipher_key");
	if (!cipher_key)
		CONFIG_ERROR("cipher key var not set");

	keylen = strlen(cipher_key);
	if (keylen > sizeof(bin_cipher_key) * 2)
		CONFIG_ERROR("cipher key too long");
	if (!binarize(cipher_key, keylen, bin_cipher_key))
		CONFIG_ERROR("cipher key has not hex format");

	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN);
	tun_name = get_str_var(config, "tun_name", MAX_IF_NAME_LEN);
	port = get_int_var(config, "port");
	server_port = get_int_var(config, "server_port");
	point_id = get_int_var(config, "point_id");
	if (point_id > 0xFF || point_id < 0)
		CONFIG_ERROR("invalid point_id");

	encrypt_key = gen_encrypt_key(bin_cipher_key, keylen / 2);
	if (!encrypt_key)
		CONFIG_ERROR("encrypt keygen failed");

	clnt = malloc(sizeof(struct vpnclient));
	memset(clnt, 0, sizeof(struct vpnclient));
	init_event_listener(&clnt->loop);

	strcpy(clnt->ip_addr, ip_addr);
	strcpy(clnt->server_ip, server_ip);
	strcpy(clnt->tun_addr, tun_addr);
	strcpy(clnt->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_NETMASK);
	strcpy(clnt->tun_name, tun_name ? tun_name : TUN_IF_NAME);

	clnt->port = port;
	clnt->server_port = server_port ? server_port : VPN_PORT;
	clnt->point_id = point_id;
	clnt->router_ip = inet_network(router_ip);
	clnt->private_ip = inet_network(clnt->tun_addr);
	clnt->encrypt_key = encrypt_key;
	clnt->sequance_id = (0xffff & getpid());
	clnt->sequance_no = 0;

	free_config(config);
	return clnt;
}

static void set_event_handlers(struct vpnclient *clnt)
{
	struct event_listener *loop = &clnt->loop;

	loop->tun_if_callback = tun_if_handler;
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
	free(clnt->encrypt_key);
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
