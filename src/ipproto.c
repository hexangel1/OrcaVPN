#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "ipproto.h"

unsigned short ip_checksum(const unsigned short *addr, unsigned int count)
{
	register unsigned long sum = 0;

	while (count > 1)  {
		sum += *addr++;
		count -= 2;
	}
	if (count > 0)
		sum += *(unsigned char *)addr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = ~sum;
	return sum;
}

int get_ip_version(const void *buf, size_t len)
{
	const struct iphdr *ip_header = buf;

	if (len < sizeof(struct iphdr))
		return -1;
	return ip_header->version;
}

int check_header_ipv4(const void *buf, size_t len)
{
	const struct iphdr *ip_header = buf;
	unsigned int ip_header_len;

	if (len < sizeof(struct iphdr))
		return 1;

	if (ip_header->version != 4 || (size_t)ntohs(ip_header->tot_len) != len)
		return 1;

	ip_header_len = ip_header->ihl * 4;
	if (ip_header_len < 20 || ip_header_len > 60 || ip_header_len > len)
		return 1;

	return ip_checksum((unsigned short *)ip_header, ip_header_len) != 0;
}

int write_icmp_echo(void *buf, const struct icmp_echo_param *param)
{
	struct iphdr *ip_header;
	struct icmphdr *icmp_header;
	unsigned char *echo_data;
	unsigned short total_len;

	ip_header = (void *)buf;
	icmp_header = (void *)((char *)ip_header + sizeof(struct iphdr));
	echo_data = (void *)((char *)icmp_header + sizeof(struct icmphdr));
	total_len = sizeof(struct iphdr) + sizeof(struct icmphdr) +
		sizeof(param->data);

	ip_header->ihl = 5;
	ip_header->version = 4;
	ip_header->tos = 0;
	ip_header->tot_len = htons(total_len);
	ip_header->id = htons(0xffff & rand());
	ip_header->frag_off = htons(0x4000);
	ip_header->ttl = 64;
	ip_header->protocol = IPPROTO_ICMP;
	ip_header->check = 0;
	ip_header->saddr = htonl(param->src_ip);
	ip_header->daddr = htonl(param->dst_ip);

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;
	icmp_header->checksum = 0;
	icmp_header->un.echo.id = htons(param->seq_id);
	icmp_header->un.echo.sequence = htons(param->seq_no);

	memcpy(echo_data, param->data, PING_DATA_LEN);

	ip_header->check = ip_checksum((unsigned short *)ip_header,
		sizeof(struct iphdr));
	icmp_header->checksum = ip_checksum((unsigned short *)icmp_header,
		sizeof(struct icmphdr) + PING_DATA_LEN);

	return total_len;
}

uint32_t get_destination_ip(const void *buf)
{
	return ntohl(((struct iphdr *)buf)->daddr);
}

uint32_t get_source_ip(const void *buf)
{
	return ntohl(((struct iphdr *)buf)->saddr);
}

const char *ipv4tosb(uint32_t ip, int host_order, char *buf)
{
	static char ipv4_buffer[MAX_IPV4_ADDR_LEN];

	if (!buf)
		buf = ipv4_buffer;
	if (!host_order)
		ip = ntohl(ip);
	snprintf(buf, sizeof(ipv4_buffer), "%u.%u.%u.%u",
		(ip >> 24) & 0xff, (ip >> 16) & 0xff,
		(ip >> 8)  & 0xff, (ip) & 0xff);
	return buf;
}

const char *ipv4tos(uint32_t ip, int host_order)
{
	return ipv4tosb(ip, host_order, NULL);
}

char *addr_to_str(const struct sockaddr_in *addr, char *buf, size_t len)
{
	char ipv4_buffer[MAX_IPV4_ADDR_LEN];

	ipv4tosb(addr->sin_addr.s_addr, 0, ipv4_buffer);
	snprintf(buf, len, "%s:%u", ipv4_buffer, ntohs(addr->sin_port));
	return buf;
}

int ip_in_network(uint32_t ip, uint32_t network, uint32_t mask)
{
	return (ip & mask) == (network & mask);
}
