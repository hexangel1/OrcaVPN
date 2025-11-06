#ifndef SIGEVENT_H_SENTRY
#define SIGEVENT_H_SENTRY

#include <signal.h>

typedef enum sigevent_status {
	sigevent_absent,
	sigevent_alarm,
	sigevent_reload,
	sigevent_stop
} sigevent_status_t;

/* Set signal handlers and sigmask */
int setup_signal_events(sigset_t *origmask, unsigned long interval);
/* Set original signal mask */
void restore_signal_events(const sigset_t *origmask);
/* Get signal event */
sigevent_status_t get_signal_event(void);

#endif /* SIGEVENT_H_SENTRY */
