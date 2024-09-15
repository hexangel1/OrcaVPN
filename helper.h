#ifndef HELPER_H_SENTRY
#define HELPER_H_SENTRY

#include <stddef.h>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

void daemonize(const char *service);

char *hexlify(const void *data, size_t len, int upper, char *out);

#endif /* HELPER_H_SENTRY */
