#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>

#include "vpnclient.h"
#include "network.h"
#include "encrypt/encryption.h"
#include "sigevent.h"
#include "configparser.h"
#include "logger.h"
#include "helper.h"

#define IDLE_TIMEOUT 60

struct vpnclient {
	int tunfd;
	int sockfd;
	int reload_flag;
	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];
	char tun_name[MAX_IF_NAME_LEN];
	unsigned short server_port;
	char server_ip[MAX_IPV4_ADDR_LEN];
	void *cipher_key;
	uint32_t router_ip;
	uint32_t private_ip;
	uint8_t point_id;
	uint16_t sequance_id;
	uint16_t sequance_no;
};

static int ping_vpn_router(struct vpnclient *clnt)
{
	char buffer[PACKET_BUFFER_SIZE];
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
	encrypt_packet(buffer, &length, clnt->cipher_key);
	buffer[length++] = clnt->point_id;
	res = send_udp(clnt->sockfd, buffer, length, NULL);
	if (res < 0) {
		log_mesg(LOG_ERR, "sending ping packet failed");
		return -1;
	}
	return 0;
}

static int timeout_handler(struct vpnclient *clnt)
{
	return ping_vpn_router(clnt);
}

static int socket_handler(struct vpnclient *clnt)
{
	char buffer[PACKET_BUFFER_SIZE];
	ssize_t res;
	size_t length;

	res = recv_udp(clnt->sockfd, buffer, MAX_UDP_PAYLOAD, NULL);
	if (res < 0) {
		log_mesg(LOG_ERR, "receiving packet failed");
		return -1;
	}
	length = res;
	decrypt_packet(buffer, &length, clnt->cipher_key);
	if (!check_signature(buffer, &length)) {
		log_mesg(LOG_NOTICE, "bad packet signature");
		return -1;
	}
	res = write(clnt->tunfd, buffer, length);
	if (res < 0) {
		log_perror("write to tun failed");
		return -1;
	}
	return 0;
}

static int tun_if_handler(struct vpnclient *clnt)
{
	char buffer[PACKET_BUFFER_SIZE];
	ssize_t res;
	size_t length;

	res = read(clnt->tunfd, buffer, TUN_IF_MTU);
	if (res <= 0) {
		log_perror("read from tun failed");
		return -1;
	}
	length = res;
	if (clnt->private_ip != get_source_ip(buffer, length))
		return -1;
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, clnt->cipher_key);
	buffer[length++] = clnt->point_id;
	res = send_udp(clnt->sockfd, buffer, length, NULL);
	if (res < 0) {
		log_mesg(LOG_ERR, "sending packet failed");
		return -1;
	}
	return 0;
}

static int sigevent_handler(struct vpnclient *clnt, const sigset_t *sigmask)
{
	switch (get_signal_event()) {
	case sigevent_restart:
		clnt->reload_flag = 1;
		restore_signal_mask(sigmask);
		/* fallthrough */
	case sigevent_shutdown:
		return -1;
	case sigevent_absent:
		;
	}
	return 0;
}

static void vpn_client_handle(struct vpnclient *clnt)
{
	fd_set readfds;
	sigset_t sigmask;
	struct timespec timeout = {IDLE_TIMEOUT, 0};
	int res, nfds = MAX(clnt->tunfd, clnt->sockfd) + 1;

	setup_signal_events(&sigmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(clnt->tunfd, &readfds);
		FD_SET(clnt->sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, &timeout, &sigmask);
		if (res < 0) {
			if (errno != EINTR) {
				log_perror("pselect");
				break;
			}
			res = sigevent_handler(clnt, &sigmask);
			if (res < 0)
				break;
			continue;
		}
		if (res == 0) {
			timeout_handler(clnt);
			continue;
		}
		if (FD_ISSET(clnt->tunfd, &readfds))
			tun_if_handler(clnt);
		if (FD_ISSET(clnt->sockfd, &readfds))
			socket_handler(clnt);
	}
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
	uint8_t cipher_key[CIPHER_KEY_LEN];
	int port, server_port, point_id;
	const char *ip_addr, *server_ip, *router_ip, *hex_key;
	const char *tun_addr, *tun_netmask, *tun_name;

	config = read_config(file);
	if (!config)
		return NULL;

	ip_addr = get_str_var(config, "ip_addr", MAX_IPV4_ADDR_LEN - 1);
	if (!ip_addr)
		ip_addr = "";
	router_ip = get_str_var(config, "router_ip", MAX_IPV4_ADDR_LEN - 1);
	if (!router_ip)
		router_ip = TUN_IF_ADDR;
	server_ip = get_str_var(config, "server_ip", MAX_IPV4_ADDR_LEN - 1);
	if (!server_ip)
		CONFIG_ERROR("server_ip var not set");
	tun_addr = get_str_var(config, "tun_addr", MAX_IPV4_ADDR_LEN - 1);
	if (!tun_addr)
		CONFIG_ERROR("tun_addr var not set");
	hex_key = get_str_var(config, "cipher_key", CIPHER_KEY_HEX_LEN);
	if (!hex_key || strlen(hex_key) != CIPHER_KEY_HEX_LEN)
		CONFIG_ERROR("password var not set");

	if (!binarize(hex_key, CIPHER_KEY_HEX_LEN, cipher_key))
		CONFIG_ERROR("invalid cipher key");

	tun_netmask = get_str_var(config, "tun_netmask", MAX_IPV4_ADDR_LEN - 1);
	tun_name = get_str_var(config, "tun_name", MAX_IF_NAME_LEN - 1);
	port = get_int_var(config, "port");
	server_port = get_int_var(config, "server_port");
	point_id = get_int_var(config, "point_id");
	if (point_id > 0xFF || point_id < 0)
		CONFIG_ERROR("invalid point_id");

	clnt = malloc(sizeof(struct vpnclient));
	memset(clnt, 0, sizeof(struct vpnclient));
	clnt->tunfd = -1;
	clnt->sockfd = -1;
	clnt->reload_flag = 0;

	strcpy(clnt->ip_addr, ip_addr);
	strcpy(clnt->server_ip, server_ip);
	strcpy(clnt->tun_addr, tun_addr);
	strcpy(clnt->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_NETMASK);
	strcpy(clnt->tun_name, tun_name ? tun_name : TUN_IF_NAME);

	clnt->port = port ? port : VPN_PORT;
	clnt->server_port = server_port ? server_port : VPN_PORT;
	clnt->point_id = point_id;
	clnt->router_ip = inet_network(router_ip);
	clnt->private_ip = inet_network(clnt->tun_addr);
	clnt->cipher_key = get_expanded_key(cipher_key);
	clnt->sequance_id = (0xffff & getpid());
	clnt->sequance_no = 0;

	free_config(config);
	return clnt;
}

static int vpn_client_up(struct vpnclient *clnt)
{
	int res;
	res = create_udp_socket(clnt->ip_addr, clnt->port);
	if (res < 0) {
		log_mesg(LOG_ERR, "Create socket failed");
		return -1;
	}
	clnt->sockfd = res;
	res = connect_socket(clnt->sockfd, clnt->server_ip, clnt->server_port);
	if (res < 0) {
		log_mesg(LOG_ERR, "Connection failed");
		return -1;
	}
	res = create_tun_if(clnt->tun_name);
	if (res < 0) {
		log_mesg(LOG_ERR, "Allocating interface failed");
		return -1;
	}
	clnt->tunfd = res;
	log_mesg(LOG_INFO, "created dev %s", clnt->tun_name);
	res = setup_tun_if(clnt->tun_name, clnt->tun_addr, clnt->tun_netmask);
	if (res < 0) {
		log_mesg(LOG_ERR, "Setting up %s failed", clnt->tun_name);
		return -1;
	}
	set_nonblock_io(clnt->sockfd);
	set_nonblock_io(clnt->tunfd);
	return 0;
}

static void vpn_client_down(struct vpnclient *clnt)
{
	close(clnt->sockfd);
	close(clnt->tunfd);
	free(clnt->cipher_key);
	free(clnt);
}

void run_vpnclient(const char *config)
{
	struct vpnclient *clnt;
	int res, reload;

reload_client:
	clnt = create_client(config);
	if (!clnt) {
		log_mesg(LOG_ERR, "Failed to create init client");
		exit(EXIT_FAILURE);
	}
	res = vpn_client_up(clnt);
	if (res < 0) {
		log_mesg(LOG_ERR, "Failed to bring client up");
		exit(EXIT_FAILURE);
	}

	log_mesg(LOG_INFO, "Running client...");
	vpn_client_handle(clnt);
	reload = clnt->reload_flag;
	vpn_client_down(clnt);
	if (reload) {
		log_mesg(LOG_INFO, "Reloading client...");
		goto reload_client;
	}
	log_mesg(LOG_INFO, "Gracefully finished");
}
