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
#include "helper.h"

struct vpnclient {
	int tunfd;
	int sockfd;
	unsigned short port;
	char ip_addr[MAX_IPV4_ADDR_LEN];
	char tun_addr[MAX_IPV4_ADDR_LEN];
	char tun_netmask[MAX_IPV4_ADDR_LEN];
	char tun_name[MAX_IF_NAME_LEN];
	int tun_mtu;
	unsigned short server_port;
	char server_ip[MAX_IPV4_ADDR_LEN];
	void *cipher_key;
	uint32_t private_ip;
	uint8_t point_id;
};

static int tun_if_forward(struct vpnclient *clnt)
{
	ssize_t res;
	size_t length;
	char buffer[PACKET_BUFFER_SIZE];
	res = recv_udp(clnt->sockfd, buffer, MAX_UDP_PAYLOAD, NULL);
	if (res == -1) {
		fprintf(stderr, "receiving packet failed\n");
		return -1;
	}
	length = res;
	decrypt_packet(buffer, &length, clnt->cipher_key);
	if (!check_signature(buffer, &length)) {
		fprintf(stderr, "bad packet signature\n");
		return -1;
	}
	res = write(clnt->tunfd, buffer, length);
	if (res == -1) {
		perror("write to tun failed");
		return -1;
	}
	return 0;
}

static int sockfd_forward(struct vpnclient *clnt)
{
	ssize_t res;
	size_t length;
	char buffer[PACKET_BUFFER_SIZE];
	res = read(clnt->tunfd, buffer, clnt->tun_mtu);
	if (res <= 0) {
		perror("read from tun failed");
		return -1;
	}
	length = res;
	if (clnt->private_ip != get_source_ip(buffer, length))
		return -1;
	sign_packet(buffer, &length);
	encrypt_packet(buffer, &length, clnt->cipher_key);
	buffer[length++] = clnt->point_id;
	res = send_udp(clnt->sockfd, buffer, length, NULL);
	if (res == -1) {
		fprintf(stderr, "sending packet failed\n");
		return -1;
	}
	return 0;
}

static void vpn_client_handle(struct vpnclient *clnt)
{
	fd_set readfds;
	sigset_t origmask;
	int res, nfds = MAX(clnt->tunfd, clnt->sockfd) + 1;

	setup_signal_events(&origmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(clnt->tunfd, &readfds);
		FD_SET(clnt->sockfd, &readfds);
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
		if (FD_ISSET(clnt->tunfd, &readfds))
			sockfd_forward(clnt);
		if (FD_ISSET(clnt->sockfd, &readfds))
			tun_if_forward(clnt);
	}
}

#define CONFIG_ERROR(message) \
	do { \
		free_config(config); \
		fputs(message "\n", stderr); \
		return NULL; \
	} while (0)

static struct vpnclient *create_client(const char *file)
{
	struct vpnclient *clnt;
	struct config_section *config;
	uint8_t cipher_key[CIPHER_KEY_LEN];
	int port, server_port;
	const char *ip_addr, *server_ip, *hex_key;
	const char *tun_addr, *tun_netmask, *tun_name;

	config = read_config(file);
	if (!config)
		return NULL;

	ip_addr = get_str_var(config, "ip_addr", MAX_IPV4_ADDR_LEN - 1);
	if (!ip_addr)
		CONFIG_ERROR("ip_addr var not set");
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

	clnt = malloc(sizeof(struct vpnclient));
	memset(clnt, 0, sizeof(struct vpnclient));
	clnt->tunfd = -1;
	clnt->sockfd = -1;

	strcpy(clnt->ip_addr, ip_addr);
	strcpy(clnt->server_ip, server_ip);
	strcpy(clnt->tun_addr, tun_addr);
	strcpy(clnt->tun_netmask, tun_netmask ? tun_netmask : TUN_IF_NETMASK);
	strcpy(clnt->tun_name, tun_name ? tun_name : TUN_IF_NAME);

	clnt->tun_mtu = TUN_MTU_SIZE;
	clnt->port = port ? port : VPN_PORT;
	clnt->server_port = server_port ? server_port : VPN_PORT;
	clnt->point_id = 0;
	clnt->private_ip = inet_network(clnt->tun_addr);
	clnt->cipher_key = get_expanded_key(cipher_key);

	free_config(config);
	return clnt;
}

static int vpn_client_up(struct vpnclient *clnt)
{
	int res;
	res = create_udp_socket(clnt->ip_addr, clnt->port);
	if (res == -1) {
		fprintf(stderr, "Create socket failed\n");
		return -1;
	}
	clnt->sockfd = res;
	res = socket_connect(clnt->sockfd, clnt->server_ip, clnt->server_port);
	if (res == -1) {
		fprintf(stderr, "Connection failed\n");
		return -1;
	}
	res = create_tun_if(clnt->tun_name);
	if (res == -1) {
		fprintf(stderr, "Allocating interface failed\n");
		return -1;
	}
	clnt->tunfd = res;
	fprintf(stderr, "created dev %s\n", clnt->tun_name);
	res = setup_tun_if(clnt->tun_name, clnt->tun_addr, clnt->tun_netmask, clnt->tun_mtu);
	if (res == -1) {
		fprintf(stderr, "Setting up %s failed\n", clnt->tun_name);
		return -1;
	}
	nonblock_io(clnt->sockfd);
	nonblock_io(clnt->tunfd);
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
	int res;
	struct vpnclient *clnt;
	clnt = create_client(config);
	if (!clnt) {
		fprintf(stderr, "Failed to create init client\n");
		exit(EXIT_FAILURE);
	}
	res = vpn_client_up(clnt);
	if (res == -1) {
		fprintf(stderr, "Failed to bring client up\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "Running client...\n");
	vpn_client_handle(clnt);
	vpn_client_down(clnt);
	fprintf(stderr, "Gracefully finished\n");
}
