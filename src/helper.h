#ifndef HELPER_H_SENTRY
#define HELPER_H_SENTRY

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define IS_XDIGIT(c) (\
	((c) >= '0' && (c) <= '9') || \
	((c) >= 'a' && (c) <= 'f') || \
	((c) >= 'A' && (c) <= 'F'))

#define XDIGIT(c) (\
	((c) >= '0' && (c) <= '9') ? ((c) - '0') : \
	((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) : \
	((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) : (-1))

#define UNUSED(v) ((void)(v))

/* Daemonize process, write pid to file */
void daemonize(const char *pidfile);

/* Get current unix time */
time_t get_unix_time(void);
/* Write time in milliseconds to struct timespec */
struct timespec *ms2timespec(struct timespec *ts, long ms);

/* Hexlify binary data */
char *hexlify(const void *data, size_t len, int upper, char *res);
/* Binarize hex string */
void *binarize(const char *hex, size_t len, void *res);

#endif /* HELPER_H_SENTRY */
