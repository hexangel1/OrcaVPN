#define _POSIX_C_SOURCE 200112L
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>

#include "eventloop.h"
#include "sigevent.h"
#include "network.h"
#include "logger.h"
#include "helper.h"

static void process_signal(struct event_listener *loop)
{
	switch (get_signal_event()) {
	case sigevent_reload:
		log_rotate();
		loop->reload_flag = 1;
		/* fallthrough */
	case sigevent_stop:
		loop->exit_loop = 1;
	case sigevent_absent:
		;
	}
}

static void prepare_loop(struct event_listener *loop, sigset_t *sigmask,
	struct timespec **timeout, struct timespec *timeout_buf)
{
	set_nonblock_io(loop->tunfd);
	set_nonblock_io(loop->sockfd);
	setup_signal_events(sigmask);
	*timeout = ms2timespec(timeout_buf, loop->timeout);
	log_mesg(LOG_INFO, "Running event loop...");
}

static void terminate_loop(struct event_listener *loop, sigset_t *sigmask)
{
	UNUSED(loop);
	restore_signal_mask(sigmask);
	log_mesg(LOG_INFO, "Exiting event loop...");
}

void event_loop(struct event_listener *loop)
{
	fd_set readfds;
	sigset_t sigmask;
	struct timespec timeout_buf, *timeout;
	int res, nfds = MAX(loop->tunfd, loop->sockfd) + 1;

	prepare_loop(loop, &sigmask, &timeout, &timeout_buf);
	FD_ZERO(&readfds);

	while (!loop->exit_loop) {
		FD_SET(loop->tunfd, &readfds);
		FD_SET(loop->sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, timeout, &sigmask);
		if (res < 0) {
			if (errno != EINTR) {
				log_perror("pselect");
				err_panic(loop, "polling fds");
				break;
			}
			process_signal(loop);
			continue;
		}
		if (res == 0 && loop->timeout_callback) {
			loop->timeout_callback(loop->ctx);
			continue;
		}
		if (FD_ISSET(loop->tunfd, &readfds))
			loop->tundev_callback(loop->ctx);
		if (FD_ISSET(loop->sockfd, &readfds))
			loop->socket_callback(loop->ctx);
	}
	terminate_loop(loop, &sigmask);
}

void init_event_listener(struct event_listener *loop)
{
	memset(loop, 0, sizeof(struct event_listener));
	loop->tunfd = -1;
	loop->sockfd = -1;
	loop->timeout = -1;
}

void err_panic(struct event_listener *loop, const char *mesg)
{
	log_mesg(LOG_EMERG, "Fatal error %s, process terminating", mesg);
	loop->status_flag = 1;
	loop->exit_loop = 1;
}
