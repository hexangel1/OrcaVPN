#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>

#include "network.h"
#include "sigevent.h"
#include "helper.h"

static void event_loop(int tunfd, int sockfd)
{
	fd_set readfds;
	sigset_t origmask;
	int res, nfds = (tunfd > sockfd ? tunfd : sockfd) + 1;

	setup_signal_events(&origmask);
	for (;;) {
		FD_ZERO(&readfds);
		FD_SET(tunfd, &readfds);
		FD_SET(sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, NULL, &origmask);
		if (res == -1) {
			if (errno != EINTR) {
				perror("pselect");
				break;
			}
			res = get_signal_event();
			if (res == sigevent_shutdown)
				break;
			if (res == sigevent_restart)
				fprintf(stderr, "RESTART!!!!!!!\n");
			continue;
		}
		if (FD_ISSET(tunfd, &readfds))
			sockfd_forward(tunfd, sockfd);
		if (FD_ISSET(sockfd, &readfds))
			tun_if_forward(tunfd, sockfd);
	}
}

void service_log(const char *message, int write_syslog)
{
	if (write_syslog)
		syslog(LOG_INFO, "%s", message);
	fprintf(stderr, "%s\n", message);
}

int main()
{
	char tun_name[IFNAMSIZ] = TUN_IF_NAME;
	int sockfd, tunfd, res;
	sockfd = create_udp_socket("192.168.1.10", VPN_PORT);
	if (sockfd == -1) {
		fprintf(stderr, "Create socket failed\ns");
		exit(1);
	}
	res = socket_connect(sockfd, "192.168.1.9", VPN_PORT);
	if (res == -1) {
		fprintf(stderr, "Connection failed\n");
		exit(1);
	}
	tunfd = create_tun_if(tun_name);
	if (tunfd == -1) {
		fprintf(stderr, "Allocating interface\n");
		exit(1);
	}
	fprintf(stderr, "created dev %s\n", tun_name);
	res = setup_tun_if(tun_name, "10.0.0.1", TUN_IF_NETMASK, TUN_MTU_SIZE);
	if (res == -1) {
		fprintf(stderr, "Setting up %s failed\n", tun_name);
		exit(1);
	}
	nonblock_io(sockfd);
	nonblock_io(tunfd);
	fprintf(stderr, "Running\n");
	event_loop(tunfd, sockfd);
	fprintf(stderr, "Gracefully finished\n");
	close(tunfd);
	close(sockfd);
	return 0;
}
