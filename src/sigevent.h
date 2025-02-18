#ifndef SIGEVENT_H_SENTRY
#define SIGEVENT_H_SENTRY

#include <signal.h>

typedef enum sigevent_status {
	sigevent_absent,
	sigevent_reload,
	sigevent_stop
} sigevent_status_t;

void setup_signal_events(sigset_t *origmask);

void restore_signal_mask(const sigset_t *origmask);

sigevent_status_t get_signal_event(void);

#endif /* SIGEVENT_H_SENTRY */
