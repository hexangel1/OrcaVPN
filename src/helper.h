#ifndef HELPER_H_SENTRY
#define HELPER_H_SENTRY

#include <stddef.h>
#include <time.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define XDIGIT(c) (\
	((c) >= '0' && (c) <= '9') ? ((c) - '0') : \
	((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) : \
	((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : (-1))

#define UNUSED(v) ((void)(v))

void daemonize(const char *pidfile);

time_t get_unix_time(void);

struct timespec *ms2timespec(struct timespec *ts, long ms);

char *hexlify(const void *data, size_t len, int upper, char *res);

void *binarize(const char *hex, size_t len, void *res);

#endif /* HELPER_H_SENTRY */
