#ifndef SIGEVENT_H_SENTRY
#define SIGEVENT_H_SENTRY

#include <signal.h>

typedef enum sigevent_status {
	sigevent_absent,
	sigevent_reload,
	sigevent_stop
} sigevent_status_t;

/* Set signal handlers and sigmask */
void setup_signal_events(sigset_t *origmask);
/* Set original signal mask */
void restore_signal_mask(const sigset_t *origmask);
/* Get signal event */
sigevent_status_t get_signal_event(void);

#endif /* SIGEVENT_H_SENTRY */
