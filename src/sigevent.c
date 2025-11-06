#define _POSIX_C_SOURCE 200112L
#include <signal.h>
#include <string.h>
#include <sys/time.h>

#include "sigevent.h"
#include "logger.h"

static volatile sig_atomic_t sigevent_flag = sigevent_absent;

static void signal_handler(int signum)
{
	if (signum == SIGALRM)
		sigevent_flag = sigevent_alarm;
	else if (signum == SIGHUP || signum == SIGUSR1)
		sigevent_flag = sigevent_reload;
	else if (signum == SIGTERM || signum == SIGUSR2)
		sigevent_flag = sigevent_stop;
}

static int set_action(int signum, const struct sigaction *sa, sigset_t *mask)
{
	int res = sigaction(signum, sa, NULL);
	if (res < 0) {
		log_perror("sigaction");
		return -1;
	}
	if (mask)
		sigaddset(mask, signum);
	return 0;
}

static int register_sigactions(sigset_t *origmask)
{
	struct sigaction sa;
	sigset_t mask;

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sigemptyset(&mask);

	sa.sa_handler = SIG_IGN;
	if (set_action(SIGPIPE, &sa, NULL) < 0)
		return -1;

	sa.sa_handler = signal_handler;
	if (set_action(SIGHUP,  &sa, &mask) < 0)
		return -1;
	if (set_action(SIGTERM, &sa, &mask) < 0)
		return -1;
	if (set_action(SIGALRM, &sa, &mask) < 0)
		return -1;
	if (set_action(SIGUSR1, &sa, &mask) < 0)
		return -1;
	if (set_action(SIGUSR2, &sa, &mask) < 0)
		return -1;

	if (sigprocmask(SIG_BLOCK, &mask, origmask) < 0) {
		log_perror("sigprocmask");
		return -1;
	}
	return 0;
}

static int set_heartbeat(unsigned long interval)
{
	struct itimerval it;
	int res;

	it.it_interval.tv_sec = interval / 1000;
	it.it_interval.tv_usec = (interval % 1000) * 1000;
	memcpy(&it.it_value, &it.it_interval, sizeof(it.it_interval));
	res = setitimer(ITIMER_REAL, &it, NULL);
	if (res < 0) {
		log_perror("setitimer");
		return -1;
	}
	return 0;
}

int setup_signal_events(sigset_t *origmask, unsigned long interval)
{
	if (register_sigactions(origmask) < 0)
		return -1;
	if (set_heartbeat(interval) < 0)
		return -1;
	return 0;
}

void restore_signal_events(const sigset_t *origmask)
{
	sigprocmask(SIG_SETMASK, origmask, NULL);
	set_heartbeat(0);
}

sigevent_status_t get_signal_event(void)
{
	sigevent_status_t status = sigevent_flag;
	sigevent_flag = sigevent_absent;
	return status;
}
