#ifndef EVENTLOOP_H_SENTRY
#define EVENTLOOP_H_SENTRY

struct event_listener {
	int tunfd;
	int sockfd;

	int exit_loop;
	int reload_flag;
	int status_flag;
	long timeout;

	void (*tundev_callback)(void *);
	void (*socket_callback)(void *);
	void (*timeout_callback)(void *);
	void *ctx;
};

/* Main loop */
void event_loop(struct event_listener *loop);
/* Init event listener */
void init_event_listener(struct event_listener *loop);
/* Exit event loop with error */
void err_panic(struct event_listener *loop, const char *mesg);

#endif /* EVENTLOOP_H_SENTRY */
