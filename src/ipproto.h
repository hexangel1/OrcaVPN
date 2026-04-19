#ifndef IPPROTO_H_SENTRY
#define IPPROTO_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_IPV4_ADDR_LEN 16
#define MAX_IPV4_CONN_LEN (MAX_IPV4_ADDR_LEN + sizeof(":65535") - 1)
#define PING_DATA_LEN 24

struct icmp_echo_param {
	uint32_t src_ip;
	uint32_t dst_ip;
	unsigned short seq_id;
	unsigned short seq_no;
	unsigned char data[PING_DATA_LEN];
};

/* Evaluate IP header checksum */
unsigned short ip_checksum(const unsigned short *addr, unsigned int count);
/* Get IP protocol version */
int get_ip_version(const void *buf, size_t len);
/* Validate IPv4 header */
int check_header_ipv4(const void *buf, size_t len);
/* Write IPv4 icmp echo packet data to buffer */
int write_icmp_echo(void *buf, const struct icmp_echo_param *param);

/* Get destination ip address from IPv4 packet */
uint32_t get_destination_ip(const void *buf);
/* Get source ip address from IPv4 packet */
uint32_t get_source_ip(const void *buf);

/* Convert IPv4 address to string, use provided buffer for return value */
const char *ipv4tosb(uint32_t ip, int host_order, char *buf);
/* Convert IPv4 address to string, use static buffer for return value */
const char *ipv4tos(uint32_t ip, int host_order);
/* Write IPv4 address to buf in format <ip>:<port> */
char *addr_to_str(const struct sockaddr_in *addr, char *buf, size_t len);
/* Check IPv4 address belongs to network */
int ip_in_network(uint32_t ip, uint32_t network, uint32_t mask);

#endif /* IPPROTO_H_SENTRY */
