#ifndef EVENTLOOP_H_SENTRY
#define EVENTLOOP_H_SENTRY

struct event_selector {
	int tunfd;
	int sockfd;

	int exit_loop;
	int reload_flag;
	int status_flag;
	long timeout;

	void (*tun_if_callback)(void *);
	void (*socket_callback)(void *);
	void (*timeout_callback)(void *);
	void *ctx;
};

void event_loop(struct event_selector *evsel);

void init_event_selector(struct event_selector *evsel);

void raise_panic(struct event_selector *evsel, const char *mesg);

#endif /* EVENTLOOP_H_SENTRY */
