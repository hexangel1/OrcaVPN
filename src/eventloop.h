#ifndef EVENTLOOP_H_SENTRY
#define EVENTLOOP_H_SENTRY

struct event_selector {
	int tunfd;
	int sockfd;

	int exit_loop;
	int reload_flag;
	int status_flag;
	unsigned long alarm_interval;

	void (*tundev_callback)(void *);
	void (*socket_callback)(void *);
	void (*alarm_callback)(void *);
	void *ctx;
};

/* Main loop */
void event_loop(struct event_selector *loop);
/* Init event selector */
void init_event_selector(struct event_selector *loop);
/* Exit event loop with error */
void err_panic(struct event_selector *loop, const char *mesg);

#endif /* EVENTLOOP_H_SENTRY */
