#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <errno.h>

#include "eventloop.h"
#include "sigevent.h"
#include "network.h"
#include "logger.h"
#include "helper.h"

static void process_signal(struct event_selector *evsel)
{
	switch (get_signal_event()) {
	case sigevent_reload:
		log_rotate();
		evsel->reload_flag = 1;
		/* fallthrough */
	case sigevent_stop:
		evsel->exit_loop = 1;
	case sigevent_absent:
		;
	}
}

static void prepare_loop(struct event_selector *evsel, sigset_t *sigmask,
	struct timespec **timeout, struct timespec *timeout_buf)
{
	set_nonblock_io(evsel->tunfd);
	set_nonblock_io(evsel->sockfd);
	setup_signal_events(sigmask);
	*timeout = ms2timespec(timeout_buf, evsel->timeout);
	log_mesg(LOG_INFO, "Running event loop...");
}

static void terminate_loop(struct event_selector *evsel, sigset_t *sigmask)
{
	UNUSED(evsel);
	restore_signal_mask(sigmask);
	log_mesg(LOG_INFO, "Exiting event loop...");
}

void event_loop(struct event_selector *evsel)
{
	fd_set readfds;
	sigset_t sigmask;
	struct timespec timeout_buf, *timeout;
	int res, nfds = MAX(evsel->tunfd, evsel->sockfd) + 1;

	prepare_loop(evsel, &sigmask, &timeout, &timeout_buf);

	while (!evsel->exit_loop) {
		FD_ZERO(&readfds);
		FD_SET(evsel->tunfd, &readfds);
		FD_SET(evsel->sockfd, &readfds);
		res = pselect(nfds, &readfds, NULL, NULL, timeout, &sigmask);
		if (res < 0) {
			if (errno != EINTR) {
				log_perror("pselect");
				raise_panic(evsel, "polling fds");
				break;
			}
			process_signal(evsel);
			continue;
		}
		if (res == 0 && evsel->timeout_callback) {
			evsel->timeout_callback(evsel->ctx);
			continue;
		}
		if (FD_ISSET(evsel->tunfd, &readfds))
			evsel->tun_if_callback(evsel->ctx);
		if (FD_ISSET(evsel->sockfd, &readfds))
			evsel->socket_callback(evsel->ctx);
	}
	terminate_loop(evsel, &sigmask);
}

void init_event_selector(struct event_selector *evsel)
{
	memset(evsel, 0, sizeof(struct event_selector));
	evsel->tunfd = -1;
	evsel->sockfd = -1;
	evsel->timeout = -1;
}

void raise_panic(struct event_selector *evsel, const char *mesg)
{
	log_mesg(LOG_EMERG, "Fatal error %s, process terminating", mesg);
	evsel->status_flag = EXIT_FAILURE;
	evsel->exit_loop = 1;
}
