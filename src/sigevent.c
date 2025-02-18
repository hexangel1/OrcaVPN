#define _POSIX_C_SOURCE 200112L
#include <signal.h>
#include <string.h>

#include "sigevent.h"

static volatile sig_atomic_t sigevent_flag = sigevent_absent;

static void signal_handler(int signum)
{
	if (signum == SIGHUP || signum == SIGUSR1)
		sigevent_flag = sigevent_reload;
	else if (signum == SIGTERM || signum == SIGUSR2)
		sigevent_flag = sigevent_stop;
}

static void register_sigactions(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	sa.sa_handler = signal_handler;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

static void set_signal_mask(sigset_t *origmask)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, SIGUSR2);
	sigprocmask(SIG_BLOCK, &mask, origmask);
}

void setup_signal_events(sigset_t *origmask)
{
	register_sigactions();
	set_signal_mask(origmask);
}

void restore_signal_mask(const sigset_t *origmask)
{
	sigprocmask(SIG_SETMASK, origmask, NULL);
}

sigevent_status_t get_signal_event(void)
{
	sigevent_status_t status = sigevent_flag;
	sigevent_flag = sigevent_absent;
	return status;
}
